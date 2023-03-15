import numpy as np
import matplotlib
matplotlib.use('agg')
import matplotlib.pyplot as plt
import psycopg2

INTERVAL = '60 minutes'
CONNSTR = 'postgresql://xenoeye:password@localhost/xenoeyedb'
PTHRESHOLD = 2.0
TOP=15

ases = []
octets = []
explode = []
aslabels = []

# Load dataset
query = """
with top_ases as
  (select src_as::text, sum(octets) as oct
   from ingress_bytes_by_src_as
   where time >= now() - interval '{interval}'
   group by src_as
   order by oct desc
   limit {top})
select *
from top_ases
union all
select 'Others' as src_as,
   sum(octets) as oct
from ingress_bytes_by_src_as
where src_as::text not in
   (select src_as
    from top_ases)
""".format(interval=INTERVAL, top=TOP)

conn = psycopg2.connect(CONNSTR)
cursor = conn.cursor()
cursor.execute(query)
records = cursor.fetchall()
for record in records:
    ases.append(record[0])
    octets.append(record[1])
    explode.append(0.01)

cursor.close()
conn.close()

# prepare labels
sm = sum(octets)
for i in range(len(ases)):
     proc = 100 * octets[i] / sm
     aslabels.append('{} - {:.2f}%'.format(ases[i], 100 * octets[i] / sm))
     # don't display AS when % less than threshold
     if proc < PTHRESHOLD:
         ases[i] = ''

# plot

# Pie Chart
plt.pie(octets,
    labels=ases,
    autopct=lambda p: format(p, '.2f')+'%' if p > 4 else None,
    pctdistance=0.7,
    explode=explode)
  
# draw circle
centre_circle = plt.Circle((0, 0), 0.50, fc='white')
fig = plt.gcf()
  
# Adding Circle in Pie chart
fig.gca().add_artist(centre_circle)
  
# Adding Title of chart
plt.title('Source Autonomous Systems for the last {}'.format(INTERVAL))
  
# Add Legends
plt.legend(aslabels, title='AS numbers', bbox_to_anchor=(1, 1), loc='upper left')

plt.tight_layout()

plt.savefig('mpl-donut-as.png')

