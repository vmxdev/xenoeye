#!/bin/bash

echo "SELECT time, sum(octets)/30*8 AS ip, ips FROM
(
  WITH topips AS
  (SELECT  sum(octets) AS ip, COALESCE (src_host::text, 'Other') as ips FROM ingress_bytes_by_src WHERE time >= now() - interval '1 day' GROUP BY ips ORDER BY ip desc limit 20)
  SELECT time, octets,  COALESCE (src_host::text, 'Other') as ips FROM ingress_bytes_by_src WHERE time >= now() - interval '1 day' AND src_host::text IN (SELECT ips from topips)
  UNION
  SELECT time, octets, 'Other'                             as ips FROM ingress_bytes_by_src WHERE time >= now() - interval '1 day' AND src_host::text NOT IN (SELECT ips from topips)
  UNION
  SELECT time, octets, 'Other'                             as ips FROM ingress_bytes_by_src WHERE time >= now() - interval '1 day' AND src_host IS NULL
) AS report
GROUP BY time, ips ORDER BY time \\crosstabview time ips ip" | psql postgresql://xenoeye:password@localhost/xenoeyedb > day-i-ip.csv

echo "set terminal png size 1000,400
set output 'day-i-ip.png'
set key autotitle columnhead
set xdata time
set timefmt '%Y-%m-%d %H:%M:%S'
set format y '%.02s%cB'
set xtics rotate
set datafile separator '|'
set key outside
plot 'day-i-ip.csv' using 1:3 with lines, for [i=4:21] '' using 1:i with lines" | gnuplot
