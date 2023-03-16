import numpy as np
import matplotlib
matplotlib.use('agg')
import matplotlib.pyplot as plt
from matplotlib import dates
import psycopg2
import pandas as pd

INTERVAL = '24 hours'
CONNSTR = 'postgresql://xenoeye:password@localhost/xenoeyedb'

date_time = []
octets = []

# Load dataset
query = """
SELECT time, octets/30*8 FROM ingress_all
  WHERE time >= now() - interval '{interval}'
""".format(interval=INTERVAL)

conn = psycopg2.connect(CONNSTR)
cursor = conn.cursor()
cursor.execute(query)
records = cursor.fetchall()
for record in records:
    date_time.append(record[0])
    octets.append(int(record[1]))

cursor.close()
conn.close()

# Build chart
plt.figure(figsize = (12, 8))

# Calculate bars width
wd = np.min(np.diff(dates.date2num(date_time))) * 1.1
plt.bar(date_time, octets, width = wd)

plt.xticks(rotation=90)

mkfunc = lambda x, pos: '%1.1fGb'  % (x * 1e-9) if x >= 1e9 else '%1.1fMb' % (x * 1e-6) if x >= 1e6 else '%1.1fKb' % (x * 1e-3) if x >= 1e3 else '%1.1f' % x
mkformatter = matplotlib.ticker.FuncFormatter(mkfunc)
plt.gca().yaxis.set_major_formatter(mkformatter)

plt.tight_layout()

plt.savefig('mpl-day-ts.png')
