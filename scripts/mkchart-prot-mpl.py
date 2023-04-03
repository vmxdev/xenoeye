import numpy as np
import matplotlib
matplotlib.use('agg')
import matplotlib.pyplot as plt
import psycopg2

INTERVAL = '5 minutes'
CONNSTR = 'postgresql://xenoeye:password@localhost/xenoeyedb'
PTHRESHOLD = 4.0

protocols = []
octets = []
explode = []
protolabels = []

# Load dataset
query = """
select iana_protocols.name, sum(octets) as oct
from ingress_proto
join iana_protocols on ingress_proto.proto=iana_protocols.num
where time >= now() - interval '{}'
group by iana_protocols.name
order by oct desc
""".format(INTERVAL)

conn = psycopg2.connect(CONNSTR)
cursor = conn.cursor()
cursor.execute(query)
records = cursor.fetchall()
for record in records:
    protocols.append(record[0])
    octets.append(record[1])
    explode.append(0.05)

cursor.close()
conn.close()

# prepare labels
sm = sum(octets)
for i in range(len(protocols)):
     proc = 100 * octets[i] / sm
     protolabels.append('{} - {:.2f}%'.format(protocols[i], 100 * octets[i] / sm))
     # don't display protocol name when % less than threshold
     if proc < PTHRESHOLD:
         protocols[i] = ''

# plot

# pie chart
plt.pie(octets,
    labels=protocols,
    autopct=lambda p: format(p, '.2f')+'%' if p > 4 else None,
    pctdistance=0.7,
    explode=explode)

# draw circle
centre_circle = plt.Circle((0, 0), 0.50, fc='white')
fig = plt.gcf()

# adding circle in pie chart
fig.gca().add_artist(centre_circle)

# adding title of chart
plt.title('IP protocols for the last {}'.format(INTERVAL))

# add legends
plt.legend(protolabels, loc='center left', bbox_to_anchor=(1, 0.5), title='IP protocols')

plt.tight_layout()

plt.savefig('mpl-day-i.png')
