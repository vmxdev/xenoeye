import numpy as np
import matplotlib
matplotlib.use('agg')
import matplotlib.pyplot as plt
from matplotlib import dates
import psycopg2
import pandas as pd

INTERVAL = '24 hours'
N_IPS = 10
AGGR_MINUTES = 30
CONNSTR = 'postgresql://xenoeye:password@localhost/xenoeyedb'

date_time = []
ips = []
octets = []

# Load dataset
query = """
SELECT date_trunc('hour', time) + date_part('minute', time)::int / {aggr} * interval '{aggr} min', sum(octets)/EXTRACT(epoch FROM interval '{aggr} min') * 8 AS ip, ips FROM
(
  WITH topips AS
  (SELECT  sum(octets) AS ip, COALESCE (src_host::text, 'Other') as ips FROM ingress_bytes_by_src WHERE time >= now() - interval '{interval}' GROUP BY ips ORDER BY ip desc limit {n_ips})
  SELECT time, octets,  COALESCE (src_host::text, 'Other') as ips FROM ingress_bytes_by_src WHERE time >= now() - interval '{interval}' AND src_host::text IN (SELECT ips from topips)
  UNION
  SELECT time, octets, 'Other'                             as ips FROM ingress_bytes_by_src WHERE time >= now() - interval '{interval}' AND src_host::text NOT IN (SELECT ips from topips)
  UNION
  SELECT time, octets, 'Other'                             as ips FROM ingress_bytes_by_src WHERE time >= now() - interval '{interval}' AND src_host IS NULL
) AS report
GROUP BY time, ips ORDER BY time;
""".format(interval=INTERVAL, aggr=AGGR_MINUTES, n_ips=N_IPS)

conn = psycopg2.connect(CONNSTR)
cursor = conn.cursor()
cursor.execute(query)
records = cursor.fetchall()
for record in records:
    date_time.append(record[0])
    octets.append(int(record[1]))
    ips.append(record[2])

cursor.close()
conn.close()

df = pd.DataFrame({'time': date_time, 'octets': octets, 'ips': ips})
table = pd.pivot_table(df, index='time', columns='ips', values='octets', aggfunc='sum', fill_value=0)

table.plot.bar(stacked=True, figsize=(12, 8), ylabel='BPS', xlabel='Time', title='')
plt.legend(title='IP', bbox_to_anchor=(1.05, 1), loc='upper left')

mkfunc = lambda x, pos: '%1.1fGb'  % (x * 1e-9) if x >= 1e9 else '%1.1fMb' % (x * 1e-6) if x >= 1e6 else '%1.1fKb' % (x * 1e-3) if x >= 1e3 else '%1.1f' % x
mkformatter = matplotlib.ticker.FuncFormatter(mkfunc)
plt.gca().yaxis.set_major_formatter(mkformatter)

plt.tight_layout()

plt.savefig('mpl-day-ips.png')
