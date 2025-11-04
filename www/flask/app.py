from flask import Flask, render_template, request, redirect, url_for, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import select
import json
import psycopg2
from psycopg2.extensions import quote_ident

PG_CONNSTR = "postgresql://xenoeye:password@localhost/xenoeyedb"
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "supersecretkey"

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# User model
class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    displayname = db.Column(db.String(500), nullable=False)
    description = db.Column(db.String(4000), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

class Permissions(db.Model):
    __tablename__ = 'permissions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    mo_name = db.Column(db.String(500), nullable=False)
    mo_display = db.Column(db.String(500), nullable=False)
    tmpl = db.Column(db.String(200), nullable=False)

with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

@app.route("/lk/dashboard", methods=["GET"])
@login_required
def dashboard():
    g.user = {}
    g.user['displayname'] = current_user.displayname
    g.user['description'] = current_user.description

    #get list of allowed MO's
    g.mo = Permissions.query.filter_by(user_id = current_user.id).all()
    if len(g.mo) == 0:
        #no MO's
        g.user['error'] = 'No monitoring objects found for this user'
        return render_template("dashboard-err.html", username=current_user.username)

    mo = request.args.get('mo')
    if not mo:
        g.curr_mo = g.mo[0]
    else:
        for m in g.mo:
            if m.mo_name == mo:
                g.curr_mo = m

    if not hasattr(g, 'curr_mo'):
        g.user['error'] = 'Incorrect monitoring object ' + mo
        return render_template("dashboard-err.html", username=current_user.username)

    #load template
    template_name = g.curr_mo.tmpl
    if template_name == '':
        template_name = 'default'

    with open('xe-tmpl/' + template_name + '.json') as f:
        g.nav = json.load(f)


    g.curr_section = request.args.get('s')
    if not g.curr_section:
        g.curr_section = 0
    g.curr_section = int(g.curr_section)

    g.curr_rep = request.args.get('r')
    if not g.curr_rep:
        g.curr_rep = 0
    g.curr_rep = int(g.curr_rep)

    g.r = g.nav[g.curr_section]["r"][g.curr_rep]

    return render_template("dashboard.html", username=current_user.username)

@app.route("/lk/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = Users.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("dashboard"))
        else:
            return render_template("login.html", error="Invalid username or password")

    return render_template("login.html")


@app.route("/lk/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("dashboard"))

@app.route("/lk/")
@login_required
def root():
    return redirect(url_for("dashboard"))


@app.route('/lk/r.data', methods=["GET"])
@login_required
def r_data():
    mo = request.args.get('mo')
    #allow empty mo
    if not mo:
        mo = ''

    amo = Permissions.query.filter_by(user_id = current_user.id, mo_name = mo).all()
    if len(amo) == 0:
        return "Incorrect request", 400


    section = request.args.get('s')
    if not section:
        return "Incorrect request", 400
    section = int(section)

    rep = request.args.get('r')
    if not rep:
        return "Incorrect request", 400
    rep = int(rep)

    chart = request.args.get('c')
    if not chart:
        return "Incorrect request", 400
    chart = int(chart)

    #time range
    arg_tr = request.args.get('tr')
    if not arg_tr:
        arg_tr = "21600" # 6 hours

    arg_tr = int(arg_tr)
    if arg_tr <= 0:
        arg_tr = 21600

    #load template
    template_name = amo[0].tmpl
    if template_name == '':
        template_name = 'default'

    with open('xe-tmpl/' + template_name + '.json') as f:
        tmpl = json.load(f)

    ch = tmpl[section]["r"][rep]["charts"][chart]

    conn = psycopg2.connect(PG_CONNSTR)
    cur = conn.cursor()

    query = ch["query"]

    query = query.replace("$mo", mo)
    query = query.replace("$tr", str(arg_tr))

    cur.execute(query)

    r = cur.fetchall()

    cur.close() 
    conn.close()

    return jsonify(r)


