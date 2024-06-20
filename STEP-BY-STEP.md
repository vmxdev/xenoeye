# Step-by-step instructions for installing and configuring the collector

  * [Build and install](#build-and-install)
  * [Checking Netflow packets receiving](#checking-netflow-packets-receiving)
  * [Load-balancing across multiple CPUs](#load-balancing-across-multiple-cpus)
  * [Sampling rate](#sampling-rate)
  * [Monitoring objects](#monitoring-objects)
  * [IP lists](#ip-lists)
  * [Configure what data should be exported to the DBMS](#configure-what-data-should-be-exported-to-the-dbms)
  * [Export to DBMS](#export-to-dbms)
  * [Simple Reporting by IP Addresses](#simple-reporting-by-ip-addresses)
  * [Can we use GeoIP?](#can-we-use-geoip)
  * [Detect spam-bots and ssh-scanners](#detect-spam-bots-and-ssh-scanners)
  * [Plotting with gnuplot](#plotting-with-gnuplot)
  * [Plots with Python Matplotlib](#plots-with-python-matplotlib)
  * [Traffic visualization with Grafana](#traffic-visualization-with-grafana)
  * [Moving Averages](#moving-averages)
  * [Configure and set thresholds](#configure-and-set-thresholds)
  * [Scripts and their options](#scripts-and-their-options)
  * [Extended stats](#extended-stats)
  * [Anomaly alerts using Telegram-bot](#anomaly-alerts-using-telegram-bot)


### Build and install

In minimal Debian 12, you need to install the following packages to build:
``` sh
$ sudo apt -y install git autoconf gcc make libpcap-dev libtool
```

For Debian 13:
``` sh
$ sudo apt -y install git autoconf gcc make libpcap-dev
```

Clone the repository and initialize the submodules

```sh
$ git clone --recurse-submodules https://github.com/vmxdev/xenoeye
```

Or

```sh
$ git clone https://github.com/vmxdev/xenoeye
$ cd xenoeye
$ git submodule update --init --recursive
```

Actually build

```sh
$ autoreconf -i
$ ./configure --sysconfdir=/etc/xenoeye --localstatedir=/var/lib
$ make
```

After that, you should get a binary file `xenoeye`


#### Install

``` sh
$ sudo make install
# change the owner of the directory to the user from whom we will run the collector (user)
$ sudo chown -R user:user /var/lib/xenoeye/
```

`make install` copies binary file `xenoeye` to /usr/local/bin, config files `xenoeye.conf` and `devices.conf` to /etc/xenoeye and creates directories /var/lib/xenoeye/mo, /var/lib/xenoeye/exp и /var/lib/xenoeye/expfailed

The directory `/var/lib/xenoeye` must be writable by the xenoeye process

`make install` is an optional step, the collector can be launched from any location

All default paths can be changed, they are set in the configuration file `xenoeye.conf`. The config files in `xenoeye` are JSON which allow comments


### Checking Netflow packets receiving

The collector can receive Netflow in two ways - using traditional socket interface or capture using pcap.

The second way is more suitable for tests. If you have, for example, .pcap files with Netflow traffic, you can play them on the loopback interface using tcpreplay (`tcpreplay -i lo dump.pcap`) and send the data to the collector in this way.
 
The "capture" section of the main configuration file `xenoeye.conf` is responsible for capturing Netflow. It lists the sockets on which the collector will listen and pcap interfaces with BPF filters.
 
To see that the collector is accepting and decoding flows, set the "dump-flows" parameter in the "debug" section. Allowed values

  * "none" - flows are not logged, normal system state
  * "syslog" - decoded flows are sent to syslog and additionally printed to stderr
  * "/path/to/file.txt" - flows in text form are written to a file

Set this parameter to "syslog"
```
	/*...*/
	"debug": {
		/* allowed values: "none", "syslog", "/path/to/file.txt" */
		"dump-flows": "syslog"
	},
	/*...*/
```


and start the collector
``` sh
$ xenoeye
```

or 

``` sh
$ xenoeye -c /path/to/xenoeye.conf
```

If you are capturing with pcap, the collector must be run as root
 
After the collector receives Netflow template packets, it can parse data flows. They will be sent to `syslog` and simultaneously output to `stderr` in approximately the following text form:
```
IPv4 src addr: 1.2.3.4; IPv4 dst addr: 5.6.7.8; Src TOS: 0; Protocol: 6; Src port: 7878; Dst port: 8787; ICMP type: 0; Input SNMP index: 111; Src VLAN: 222; Src mask: 16; Dst mask: 24; Src AS: 12345; Dst AS: 0; IPv4 next hop: 0.0.0.0; TCP flags: 24; Output SNMP index: 333; Bytes: 65522; Packets: 185; Min TTL: 51; Max TTL: 52; Unknown field 152: 0x00 0x00 0x01 0x77 0x0d 0x0c 0x07 0x00 ; Unknown field 153: 0x00 0x00 0x01 0x77 0x0d 0x0c 0xee 0x00 ; Unknown field 136: 0x02 ; Unknown field 61: 0xff ; Unknown field 243: 0x00 0x00 ; Unknown field 245: 0x00 0x00 ; Unknown field 54: 0x00 0x00 0x00 0x00 ; *dev-ip: 9.10.11.12; *dev-id: 555500, *rate: 1 [flow_debug.c, ...]
```

The collector shows all the fields that are in the netflow packet. It may not know some of the fields and shows them as "`Unknown field NNN: <data bytes>`".
 
In addition to Netflow fields, the collector shows "virtual" fields with an asterisk: `*dev-ip: 1.2.3.4; *dev-id: 123456, *rate: 1`.
 
   * `dev-ip` - IP address of the sensor (router)
   * `dev-id` - sensor ID
   * `rate` - sampling rate, default 1
 
If the flows arrive and are successfully decoded, you can return the old value of the `"dump-flows" parameter: "none"`


### Load-balancing across multiple CPUs

The collector uses a simple load balancing model: each entry in the "capture" section is a separate worker thread.

You can run the collector on multiple UDP ports and send Neflow to each port from different routers.

The operating system will distribute worker threads to different CPUs as needed.


### Sampling rate

The collector does not take (at least for now) the sampling rate from the options template.

To set the sampling rate, edit the `/etc/xenoeye/devices.conf` file. This is a JSON array, each element is a record of the Netflow source device (router). As with other configuration files, comments are allowed.

```
[
	{
		"ip": "1.2.3.4",
		"id": 123456,
		"sampling-rate": 10000
	},
	{
		"ip": "2.3.4.5",
		"sampling-rate": 1000
	}
]
```

The sampling rate can be set for the IP address of the device and, if necessary, also for the source ID (it can be seen in the text dump of the flow, the virtual field `*dev-id`). The collector shows sampling rate in each flow, in the virtual field `*rate`.

Inside the collector, the sampling rate is simply a factor by which the number of octets and packets are multiplied.


### Monitoring objects

The monitoring object is the main entity in the collector. Reports and moving averages are attached to monitoring objects.

The monitoring object is specified by a filter with a BPF-like syntax.

For example, the filter `dst net 10.11.12.0/24` selects all traffic that goes to the network `10.11.12.0/24`.

Filters can define not only networks, but also arbitrary objects that can be selected from Netflow

The monitoring object `src net 10.11.12.0/24 or 10.11.13.0/24 and proto tcp and dst port 80 or 443` defines TCP traffic that exits networks 10.11.12.0/24 and 10.11.13.0/24 to ports 80 or 443, i.e. outgoing HTTP/HTTPS traffic.

Brackets, `and`, `or` and `not` operators are allowed in filters.

In addition to the netflow fields, the virtual fields `dev-ip` and `dev-id` can be used in filters. For example, the filter "`dst net 10.11.12.0/24 and dev-ip 1.2.3.4`" will select only flows that come from router 1.2.3.4. For more information about filters, see [CONFIG.md](CONFIG.md)

Physically, the monitoring object is a directory with the `mo.conf` file, located in a special place - the directory of monitoring objects.

The directory of monitoring objects is specified in the main configuration file, the `mo-dir` parameter. The default is `/var/lib/xenoeye/mo`.


#### Monitoring object "ingress"

Let's create a monitoring object called `ingress`. It will describe all the traffic entering our networks.

First, create a directory with this name:

```sh
$ mkdir -p /var/lib/xenoeye/mo/ingress
```

In this directory, create a `mo.conf` file with the content:

```
{
	/* some of our networks */
	"filter": "dst net 10.11.12.0/24",

	"debug": {
		/* For the test, enable debug mode. Flows that belong to this object will be sent to syslog and stderr */
		"dump-flows": "syslog"
	}
}
```

Restart the collector and see what it displays on the screen. It should only show flows that have an `IPv4 dst addr` on your network.

The operating mode for the collector is without printing or saving each flow to a file. But for small monitoring objects, and when you need every flow with all the data, this feature can be used. We use flow-to-file printing to look at traffic that should not appear on the router. For example, traffic from bogon networks or traffic that has both src and dst IPs not from our networks.


#### Monitoring object "egress"

In the same way, we can create an `egress` monitoring object that will describe the traffic coming **from** our networks.

```sh
$ mkdir -p /var/lib/xenoeye/mo/egress
```

```
{
	"filter": "src net 10.11.12.0/24"
	/* ... */
}
```


### IP lists

In the fields with IP addresses, networks can be specified as single numeric value (`1.2.3.0/24`), enumeration of networks (`1.2.3.0/24 or 1.2.4.0/24`) or list name.
When there are many networks, it makes sense to keep them in a separate file and use the name of the IP list in filters.

To create a list of networks, create a file in the `/var/lib/xenoeye/iplists/` directory. The file name will be the name of the list. For example, you can create a file `/var/lib/xenoeye/iplists/bogon` and put bogon networks in it, one network per line:


```
# Comments and blank lines are allowed in the file with IP networks

10.0.0.0/8
100.64.0.0/10
127.0.0.0/8
169.254.0.0/16
172.16.0.0/12
192.0.0.0/24
192.0.2.0/24
192.168.0.0/16
198.18.0.0/15
198.51.100.0/24
203.0.113.0/24
224.0.0.0/4
240.0.0.0/4
255.255.255.255/32

# One file can contain both IPv4 and IPv6 networks
::/128
::1/128
::ffff:0:0/96
::/96
100::/64
2001:10::/28
2001:db8::/32
fc00::/7
fe80::/10
fec0::/10
ff00::/8
```

After that, it will be possible to specify `bogon` as a network in the filter.

The "`net bogon`" filter will select flows where `IPV4_SRC_ADDR` **or** `IPV4_DST_ADDR` belongs to bogon networks.
 
The filter "`src net bogon and dst net bogon`" will select flows in which both `IPV4_SRC_ADDR` **and** `IPV4_DST_ADDR` simultaneously belong to bogon networks.
 
For IPv6, you need to specify fields with a `6` suffix, for example "`src net6 bogon and dst net6 bogon`"
 
If you want to monitor many networks, it makes sense to create a file listing your networks:
``` sh
$ mkdir -p /var/lib/xenoeye/iplists/
$ echo "1.2.3.0/24" > /var/lib/xenoeye/iplists/my-nets
$ echo "1.2.4.0/24" >> /var/lib/xenoeye/iplists/my-nets
...
```


### Configure what data should be exported to the DBMS

If the collector shows the correct flows for the monitored object, you can remove the printing of the flows and add elements for export to the DBMS.

`/var/lib/xenoeye/mo/ingress/mo.conf`:
```
{
	"filter": "dst net my-nets",

	"debug": {
		"dump-flows": "none"
	},

	/* Determining the data to export */
	"fwm": [
		{
			/* the total number of packets and bytes to our networks, throughout the monitored object */
			"name": "all",
			"fields": ["packets", "octets"]
		},
		{
			/* dst IP dst IP and number of packets/bytes per address */
			"name": "octets_by_dst",
			"fields": ["packets", "octets", "dst host"]
		},
		{
			/* protocol numbers and number of packets/bytes for each protocol */
			"name": "octets_by_proto",
			"fields": ["packets", "octets", "proto"]
		},
		{
			/* src IP address and number of bytes from each unique IP */
			"name": "octets_by_src",
			"fields": ["octets desc", "src host"],
			"limit": 5,    /* limit the number of lines of export */
			"time": 10     /* set the window size to 10 seconds (default 30 seconds) */
		}
	]
}
```

Each element in the "fwm" array corresponds to a table in the DBMS. The name of the table is obtained from the name of the monitoring object + `_` + the name of the element.

Each element must have a name (`"name"`) and a list of netflow fields to be used (`"fields"`). In addition, you can change the time for which data is aggregated (`"time"`, 30 seconds by default) and limit the size of exported rows (by default, all data is exported). A detailed description of the `mo.conf` files is in [CONFIG.md](CONFIG.md)

Let's take a look at each item.


```
{
	"name": "all",
	"fields": ["packets", "octets"]
}
```
The item named "all" instructs the system to create the `ingress_all` table. The table will have 3 fields: `time`, `packets` and `octets`. Every 30 seconds, a record will be added to the table with time and traffic volume throughout the monitoring object.


```
{
	"name": "by_dst",
	"fields": ["packets", "octets", "dst host"]
}
```
The table `ingress_by_dst` will be created with the fields `time`, `packets`, `octets`, `dst_host`. Every 30 seconds, to the table will be added time, all IP addresses that received traffic during these 30 seconds, and the number of packets / bytes that came to each IP address.


```
{
	"name": "by_proto",
	"fields": ["packets", "octets", "proto"]
}
```
The protocol number, the number of incoming packets and bytes for each protocol will be added to the `ingress_by_proto` table


```
{
	"name": "octets_by_src",
	"fields": ["octets desc", "src host"],
	"limit": 5,
	"time": 10
}
```
The `ingress_octets_by_src` table will be updated with the IP addresses of the sources and the number of bytes that came from them. Since there can be many source addresses, we limit their number. Every 30 seconds, only the top 5 sources by byte count will be exported. `"limit": 5` tells the system the number of entries. The specifier `desc` in the field name (`"packets desc"`) tells to sort by number of bytes from largest to smallest

The data will be exported in the following format:
```
time                   octets       src_host
2023-01-09 22:14:33    223566128    1.2.3.4
2023-01-09 22:14:33    218947845    2.3.4.5
2023-01-09 22:14:33    204806183    1.2.4.3
2023-01-09 22:14:33    164083132    3.4.1.2
2023-01-09 22:14:33    121142482    4.2.3.1
2023-01-09 22:14:33   7049471049    NULL
```
The last line with NULL instead of IP address is the sum of the traffic (octets) of all other hosts that are not in the top 5.


For egress traffic, you can create a config file with the following set of collected data:

`/var/lib/xenoeye/mo/egress/mo.conf`:
```
{
	"filter": "src net my-nets",

	"debug": {
		"dump-flows": "none"
	},

	/* data to export */
	"fwm": [
		{
			/* the total number of packets and bytes from our networks, throughout the monitored object */
			"name": "all",
			"fields": ["packets", "octets"]
		},
		{
			/* src IP and number of packets/bytes per address */
			"name": "by_src",
			"fields": ["packets", "octets", "src host"]
		},
		{
			/* protocol numbers and number of packets/bytes for each protocol */
			"name": "by_proto",
			"fields": ["packets", "octets", "proto"]
		},
		{
			/* dst IP and number of bytes to each address */
			"name": "octets_by_dst",
			"fields": ["octets desc", "dst host"],
			"limit": 5,
			"time": 10
		}
	]
}
```
Restart the collector and it will start generating data files.


### Export to DBMS

The collector does not send data directly to the DBMS, but generates export files as SQL scripts. These files are created in the export directory (default '/var/lib/xenoeye/exp')

In order for the data to appear in the DBMS, these files must be periodically given to the `psql` utility.

The `scripts/` directory contains the `fill-db.sh` file that does this. Change the connection parameters in it (`user:password@127.0.0.1:5432/database`) and directory paths if necessary. The database must exist and the user must have write access.

  * `EXP_DIR` - directory where the script looks for export files
  * `FAIL_DIR` - the directory where the script puts the files if the export fails (there is no connection to the DBMS or something else went wrong)

The script can be run from the command line (in an infinite loop `while true; do ./fill-db.sh ; sleep 10; done`) or from cron.

We are running this script in an infinite loop in a tmux window. Collector in a separate window, export script in a separate window.


#### Quick tip: how to install PostgreSQL on the same server as the collector

``` sh
$ sudo apt -y install postgresql
#
$ sudo su - postgres -c "createuser -P xenoeye"
Enter password for new role:
Enter it again:
$ sudo su - postgres -c "createdb xenoeyedb"
$ sudo su - postgres -c "psql -d xenoeyedb -c 'GRANT ALL PRIVILEGES ON DATABASE xenoeyedb TO xenoeye;'"
GRANT
```

``` sh
$ vi scripts/fill-db.sh
```

Edit connection settings if needed

  `psql postgresql://user:password@127.0.0.1:5432/database -f "$sqlscript"`


### Simple Reporting by IP Addresses

After all the manipulations described above, your DBMS tables will begin to fill in. You can start making reports. If you know even a minimal level of SQL it's pretty easy:

Egress traffic in bytes for the entire monitoring object for the last hour:
``` sql
=> select sum(octets) from egress_all where time >= now() - interval '1 hour';
    sum
-------------
 14600823461
(1 row)
```

Ingress traffic per individual destination hosts for the last hour:
``` sql
=> select sum(octets), dst_host from ingress_by_dst where time >= now() - interval '1 hour' group by dst_host order by sum desc;
    sum     |    dst_host
------------+----------------
 1335804665 | 1.2.3.4
  312434774 | 4.3.2.1
  166234656 | 2.1.1.4
...
```

Ingress traffic per individual destination hosts for the previous month:
``` sql
=> select sum(octets), dst_host from ingress_by_dst where time >= date_trunc('month', current_date - interval '1' month) and time < date_trunc('month', current_date) group by dst_host order by sum desc;
```

Other information from Netflow (AS number, Interface Idx, VLAN, TCP/UPD ports, etc.) can also be stored in the tables. Reports on this data can be built in the same way.


### Detect spam-bots and ssh-scanners

If there are infected hosts in your data center or network that scan the rest via ssh, they can be identified by the following monitoring object:

`/var/lib/xenoeye/mo/ssh_scanners/mo.conf`:
```
{
	"filter": "src net my-nets and dst port 22",

	"fwm": [
		{
			"name": "hosts",
			"fields": ["packets", "src host", "dst host", "proto"]
		}
	]
}
```


After the data is exported to the DBMS, you can get a list of host IP addresses with the following query:

``` sql
$ select src_host, count(src_host) from (select distinct src_host, dst_host from ssh_scanners where time >= now() - interval '1 day' order by src_host desc) as x group by src_host order by count desc;
```

IP addresses with a lot of outgoing ssh connections are very likely to be infected and try to infect others

For infected hosts that send SMTP spam, you can create the following monitoring object:

`/var/lib/xenoeye/mo/mail_spam/mo.conf`:
```
{
	"filter": "src net my-nets and not src net mail-servers and dst port 25 or 587 or 465 or 2525",

	"fwm": [
		{
			"name": "hosts",
			"fields": ["packets", "src host", "dst host", "proto"]
		}
	]
}
```

In the file `/var/lib/xenoeye/iplists/mail-servers` you need to write the IP addresses of real mail servers so that they do not get into the monitoring object.

You can select spam hosts with the same query as ssh scanners:

``` sql
$ select src_host, count(src_host) from (select distinct src_host, dst_host from mail_spam where time >= now() - interval '1 day' order by src_host desc) as x group by src_host order by count desc;
```

### Plotting with gnuplot

One of the easiest ways to plot time series is with gnuplot.

``` sh
$ sudo apt -y install gnuplot-nox
```

Let’s plot the incoming traffic for the previous day:

To do this, you need to get the data in text form:

``` sh
$ psql postgresql://xenoeye:password@localhost/xenoeyedb -c "\copy (select * from ingress_all where time >= now() - interval '1 day' order by time) to 'day-i.csv' with CSV delimiter ','"
COPY 2880
```

We build a chart in the file `day-i.png`:

```
$ gnuplot

gnuplot> set terminal png size 1000,400
gnuplot> set output 'day-i.png'
gnuplot> set xdata time
gnuplot> set timefmt '%Y-%m-%d %H:%M:%S'
gnuplot> set xtics rotate
gnuplot> set datafile separator ','
gnuplot> set format y '%.02s%cB'
gnuplot> set style fill solid
gnuplot> set boxwidth 0.5
gnuplot> plot 'day-i.csv' using 1:2 notitle with boxes
gnuplot> ^D
$
```

![gnuplot chart 1](docs-img/gnuplot-day-i.png?raw=true "gnuplot chart 1")


Let's build a more complex graph - incoming traffic broken down by IP protocols:

IP protocol numbers are passed in netflow as numbers. In order to display the names of the protocols in text form, we will take the IANA data and create a table from them in the DBMS.
``` sh
$ wget https://www.iana.org/assignments/protocol-numbers/protocol-numbers-1.csv
# cut off the unnecessary in the file
$ grep "^[0-9]*-" protocol-numbers-1.csv -v | tail -n +2 > iana.csv
# create a table
$ psql postgresql://xenoeye:password@localhost/xenoeyedb -c "create table iana_protocols (num int, name text, descr text, ipv6ext text, ref text);"
CREATE TABLE
# fill it with data
$ psql postgresql://xenoeye:password@localhost/xenoeyedb -c "\copy iana_protocols FROM 'iana.csv' DELIMITER ',' CSV"
COPY 149
```

Now we can make a report with protocol names:

``` sh
$ echo "select time, iana_protocols.name, octets from ingress_proto join iana_protocols on ingress_proto.proto=iana_protocols.num where time >= now() - interval '1 day' order by time \crosstabview time name octets" | psql postgresql://xenoeye:password@localhost/xenoeyedb > day-i-prot.csv
```

Build a graph in the `day-i-prot.png` file (we assume that there are no more than 20 protocols in the result):

```
$ gnuplot
gnuplot> set terminal png size 1000,400
gnuplot> set output 'day-i-prot.png'
gnuplot> set key autotitle columnhead
gnuplot> set xdata time
gnuplot> set timefmt '%Y-%m-%d %H:%M:%S'
gnuplot> set format y '%.02s%cB'
gnuplot> set xtics rotate
gnuplot> set datafile separator '|'
gnuplot> set style fill solid
gnuplot> set boxwidth 0.5
gnuplot> plot 'day-i-prot.csv' using 1:2 with boxes, for [i=3:20] '' using 1:i with boxes
```

![gnuplot chart 2](docs-img/gnuplot-day-prot.png?raw=true "gnuplot chart 2")


And one more chart - incoming traffic broken down by destination IP addresses

There can be a lot of IP addresses in the report (especially in IPv6 networks).

So the SQL query becomes more complicated:

``` sql
SELECT time, sum(octets)/30*8 AS ip, ips FROM
(
  WITH topips AS
  (SELECT  sum(octets) AS ip, COALESCE (src_host::text, 'Other') as ips FROM ingress_octets_by_src WHERE time >= now() - interval '1 day' GROUP BY ips ORDER BY ip desc limit 20)
  SELECT time, octets,  COALESCE (src_host::text, 'Other') as ips FROM ingress_octets_by_src WHERE time >= now() - interval '1 day' AND src_host::text IN (SELECT ips from topips)
  UNION
  SELECT time, octets, 'Other'                             as ips FROM ingress_octets_by_src WHERE time >= now() - interval '1 day' AND src_host::text NOT IN (SELECT ips from topips)
  UNION
  SELECT time, octets, 'Other'                             as ips FROM ingress_octets_by_src WHERE time >= now() - interval '1 day' AND src_host IS NULL
) AS report
GROUP BY time, ips ORDER BY time;
```

Brief explanation:

`SELECT  sum(octets) AS ip, COALESCE (src_host::text, 'Other') as ips FROM ingress_octets_by_src WHERE time >= now() - interval '1 day' GROUP BY ips ORDER BY ip desc limit 20` - select the top 20 addresses, in descending order of the number of bytes

The next three `SELECT` select time, number of bytes and IP address. If the address is not in the top 20, it becomes 'Other', bytes at these addresses are summed

Constants in the top-level select (`SELECT time, sum(octets)/30*8 AS ip, ips FROM`):

30 - the number of seconds in the window, 8 - the number of bits in a byte, the result is recalculated in BPS.


![gnuplot chart 3](docs-img/gnuplot-day-ip.png?raw=true "gnuplot chart 3")

The script to generate such a chart is here: [scripts/mkchart-gnuplot.sh](scripts/mkchart-gnuplot.sh)


### Plots with Python Matplotlib

If you are working with Python, then you may find it more convenient to build plots using the Matplotlib library.

Plots are slightly visually different from those generated by gnuplot.

Installing the required libraries:

``` sh
$ pip3 install matplotlib psycopg2-binary pandas
```


Scripts for generating donut charts that take data from the DBMS and build the chart into files:

[scripts/mkchart-matplotlib-donut-prot.py](scripts/mkchart-matplotlib-donut-prot.py)

![matplotlib chart 1](docs-img/mpl-donut-prot.png?raw=true "matplotlib chart 1")


[scripts/mkchart-matplotlib-donut-as.py](scripts/mkchart-matplotlib-donut-as.py)

![matplotlib chart 2](docs-img/mpl-donut-as.png?raw=true "matplotlib chart 2")



Scripts for generating time series plots:


[scripts/mkchart-matplotlib-ts.py](scripts/mkchart-matplotlib-ts.py)

![matplotlib chart 3](docs-img/mpl-ts.png?raw=true "matplotlib chart 3")


Chart with aggregation and breakdown by IP addresses. Notice how the bursts smooth out when aggregating

[scripts/mkchart-matplotlib-ts-ip.py](scripts/mkchart-matplotlib-ts-ip.py)

![matplotlib chart 4](docs-img/mpl-ts-ips.png?raw=true "matplotlib chart 4")


### Traffic visualization with Grafana

Network data can be visualized using [grafana](https://grafana.com/).

To do this, connect a PostgreSQL data source.

![Grafana PostgreSQL data source](docs-img/pg-data-source.png?raw=true "Grafana PostgreSQL data source")

Create a dashboard and add panels with charts to it.


A simple time series with total traffic for the monitoring object:

![Grafana chart 1](docs-img/grafana-1.png?raw=true "Grafana chart 1")

SQL query for such a chart:

``` sql
SELECT
  time AS "time",
  octets/30*8 as octets
FROM ingress_all
WHERE
  $__timeFilter(time)
ORDER BY 1
```

Time series by protocol:

![Grafana chart proto](docs-img/grafana-pr.png?raw=true "Grafana chart proto")


``` sql
SELECT
  time AS "time",
  sum(octets)/30*8 AS protocol,
  iana_protocols.name as proto
FROM ingress_proto
JOIN iana_protocols on ingress_proto.proto=iana_protocols.num
WHERE
  $__timeFilter(time)
GROUP BY time, iana_protocols.name
ORDER BY time
```

In new versions of Grafana, in order to build such graphs, you need to add a transformation:


![Grafana tr](docs-img/grafana-tr.png?raw=true "Grafana tr")

![Grafana tr1](docs-img/grafana-tr1.png?raw=true "Grafana tr1")

![Grafana tr2](docs-img/grafana-tr2.png?raw=true "Grafana tr2")


Chart broken down by destination IP addresses:

![Grafana chart 2](docs-img/grafana-2.png?raw=true "Grafana chart 2")

There can be a lot of IP addresses so that grafana and the browser do not feel bad, the SQL query will select the top 15 addresses (by the number of bytes) for the display period and show only them. The rest will be shown as 'Other'.

Query for this type of charts:

```
SELECT time, sum(octets)/30*8 AS ip, ips FROM
(
  WITH topips AS
  (SELECT  sum(octets) AS ip, COALESCE (dst_host::text, 'Other') as ips FROM ingress_octets_by_dst WHERE $__timeFilter(time) GROUP BY ips ORDER BY ip desc limit 15)
  SELECT time, octets,  COALESCE (dst_host::text, 'Other') as ips FROM ingress_octets_by_dst WHERE $__timeFilter(time) AND dst_host::text IN (SELECT ips from topips)
  UNION
  SELECT time, octets, 'Other'                             as ips FROM ingress_octets_by_dst WHERE $__timeFilter(time) AND dst_host::text NOT IN (SELECT ips from topips)
  UNION
  SELECT time, octets, 'Other'                             as ips FROM ingress_octets_by_dst WHERE $__timeFilter(time) AND dst_host IS NULL
) AS report
GROUP BY time, ips ORDER BY time
```

More chart examples:


![Grafana chart 3](docs-img/grafana-3.png?raw=true "Grafana chart 3")

![Grafana chart 4](docs-img/grafana-4.png?raw=true "Grafana chart 4")

To display pie charts, the same queries are used as for time bar charts. To sum the data in the chart for the whole selected period, set the `Calculation` property to `Total`


![Grafana pie option](docs-img/grafana-pie-calc.png?raw=true "Grafana pie option")


### Moving Averages

The approach to processing netflow data (as time series) using fixed-size time windows was described above. The collector aggregates the data within these windows and exports it to the DBMS.
This is sufficient for many applications.

But if you need to accurately and quickly respond to an increase in traffic speed, then with this approach, difficulties may arise:

  * Fast bursts can "dissolve" in a sufficiently long window, they will not be visible
  * The system will be able to react to speed changes only after the time window has ended and the data has been exported

In order to avoid this, another approach can be used - to calculate the average traffic speed in sliding windows.

The value of the speed in the sliding window is recalculated immediately after the next flow is received. That is, the reaction of the system will be instant.

Immediately after the threshold is exceeded, the system can execute an external script and enable the collection of extended statistics. After the traffic falls below the threshold again, the system waits for a while. If the traffic during this time does not exceed the threshold, then another script is executed and the collection of extended statistics ends.

For one monitoring object, several moving averages with different parameters (threshold values, window size) can be simultaneously calculated. The idea was this: when one threshold is exceeded, the system administrator is notified and the collection of extended statistics is turned on. When the next, higher threshold is exceeded, we will already have more detailed traffic data, we can notify the administrator again and take some action.

The well-known collector [FastNetMon](https://github.com/pavel-odintsov/fastnetmon) uses a different approach: when the threshold is exceeded, the collector collects some more netflow packets and gets a profile of the current traffic from them. Perhaps we will think about such an option.

For moving averages to work, the collector does not need a DBMS, the configuration is taken from files, all calculations are made inside the collector.


An example of a moving average configuration:

`/var/lib/xenoeye/mo/http_flood/mo.conf`
```
	"mavg": [
		{
			"name": "mavg1",
			"time": 20,
			"fields": ["src host", "octets"],
			"overlimit": [
				{
					"name": "level1",
					"back2norm-time": 60,
					"default": [10000000],
					"limits": "/var/lib/xenoeye/mo/http_flood/limits1.csv",
					"action-script": "/var/lib/xenoeye/scripts/on-start.sh",
					"back2norm-script": "/var/lib/xenoeye/scripts/on-stop.sh"
				}
			]
		}
	]
```

In this configuration, a moving average is calculated for each `"src host"`, **bytes** per second are counted in a moving window.

Brief description of parameters:

  * "time" - sliding window size in seconds. The larger this parameter, the slower changes occur in the sliding window.
  * "name" - name
  * "back2norm-time" - time in seconds after which the system considers that the traffic has returned to normal
  * "default" - threshold default value
  * "limits" - file with individual thresholds for some IP addresses
  * "action-script" - script that is executed when the threshold is exceeded
  * "back2norm-script" - script that is executed when traffic returns to normal

When the volume of traffic goes below the trigger threshold, the system does not immediately take action, but waits for a while. Traffic can immediately grow and break through the threshold again. Only after the traffic is below the threshold of `back2norm-time` seconds, the user script is launched and extended statistics are disabled.

The file format with individual thresholds depends on the `"fields"` value. It must list the individual values, separated by commas, in the same order as in this field.

If the config contains `"fields": ["src host", "octets"]`, the file should look like `IP address,threshold`:
```
1.2.3.4,1000000
1.2.3.5,2000000
```

If `"fields": ["src host", "proto", "packets"]`, then the file must also contain the protocol number:
```
1.2.3.4,1,100000
1.2.3.4,17,200000
1.2.3.4,6,300000
1.2.3.5,6,200000
```
In this configuration, the moving average will be calculated for the unique combination of `"src host", "proto"`, PPS will be calculated in the window.


### Configure and set thresholds

You can use two sources to calculate thresholds: export data to a DBMS and set thresholds based on this data, or ask the system to show the current values of moving averages.

In order for the collector to start writing the current values of the moving averages to the file, you need to set the `dump` parameter to the number of seconds for this moving window. This will be the time between dumps. Then create in the directory with `mo.conf` a file with the same name as the name of the moving average + `.d`.

If in the config `"name": "mavg1"`, then:
``` sh
$ touch /var/lib/xenoeye/mo/http_flood/mavg1.d
```
After that, the collector will periodically write the current values of moving averages to the file `/var/lib/xenoeye/mo/http_flood/mavg1.dump`.


```
Wed Jan 25 23:10:25 2023
mem used/avail: 2M/256M (1245505/268435456 bytes)
 '4.13.136.10'  6  :: 0 (10000000 )
 '4.13.136.11'  6  :: 0 (10000000 )
 '4.13.136.11'  17  :: 30659 (10000000 )
 ...
```

If you want to see how moving averages change over time, you can create a file with `.a` at the end:

``` sh
$ touch /var/lib/xenoeye/mo/http_flood/mavg1.a
```

After that, each dump will be added to the file `/var/lib/xenoeye/mo/http_flood/mavg1.adump`

After you set the thresholds, do not forget to delete the `.a` file, even on small networks it can swell to a huge size


In addition to moving average values, the collector shows the date, time, and memory used to store the set. By default, 256M is allocated, you can change it with the `"mem-m"` parameter:
```
	/* ... */
	"name": "mavg1",
	"dump": 10,
	"mem-m": 10, /* 10 mb */
	"fields": ["src host", "octets"],
	/* ... */
```

Using these values, you can estimate the overall threshold for addresses in the object and, if necessary, individual thresholds for each individual IP (or combination of netflow fields)


### Scripts and their options

The collector runs two scripts: the first one when the threshold is exceeded and the second one when the traffic returns to normal.

Scripts are run with the following parameters:

  0. Name of the monitoring object
  1. Moving average name
  2. Name of item with thresholds
  3. Full name of the notification file
  4. Decoded netflow fields, in the same order as in `"fields"`
  5. Value that has exceeded the threshold
  6. Threshold value

If the threshold is exceeded, before running the script, the collector creates a notification file in a special directory (by default `/var/lib/xenoeye/notifications/`). The file name consists of all of these elements, except for the threshold and threshold values. Inside the file are the decoded netflow fields, the value that exceeded the threshold, and the threshold value. The file is updated every 3 seconds.

After the traffic returns to normal, the notification file is deleted.

With this configuration in `/var/lib/xenoeye/mo/http_flood/mo.conf`:
```
{
	"name": "mavg1",
	"fields": ["src host", "proto", "octets"],
	"overlimit": [
		{
			"name": "level1",
			"action-script": "/var/lib/xenoeye/scripts/on-start.sh",
			"back2norm-script": "/var/lib/xenoeye/scripts/on-stop.sh"
		}
	]
}
```

Scripts will be run with parameters:

`/var/lib/xenoeye/scripts/on-start.sh http_flood mavg1 level1 /var/lib/xenoeye/notifications/http_flood-mavg1-level1-15.22.13.99-6 15.22.13.99 6 1234567 1000000`

It looks a bit redundant, but you can safely ignore parameters you don't need. Most likely you will be interested in the IP address ("src host"`), the protocol and the number of bytes that broke the threshold. These are 4, 5 and 6 parameters if counting from 0.

You can see an example of scripts in the telegram bot [./scripts/telegram-bot/](scripts/telegram-bot/)


### Extended stats

Often, when thresholds are exceeded, you want to know in more detail what kind of traffic caused this excess. If exceeded, you can run a script that will collect raw netflow traffic (using tcpdump / tshark), and then analyze this traffic, for example, using wireshark.

In addition to this method, the collector has an "extended statistics" mechanism. These are special elements of the "fwm" section. They are marked with the `"extended" : true` parameter and are inactive at startup. As soon as the threshold is exceeded, these elements become active, extended data is added to the corresponding tables. When traffic returns to normal, they become inactive again.

You can enable extended statistics for the current monitoring object or for some other one. Tables from another monitor object are written as `monitoring_object/table`.

```
{
	"fwm": [
		{
			"extended": true,
			"name": "ext",
			"fields": ["octets", "src host", "dst host", "tcp-flags"]
		}
		/* ... */
	],

	"mavg": [
		{
			"name": "mavg1",
			"time": 20,
			"fields": ["src host", "octets"],
			"overlimit": [
				{
					"name": "level1",
					"default": [10000000],
					"action-script": "/var/lib/xenoeye/scripts/on-start.sh",
					"back2norm-script": "/var/lib/xenoeye/scripts/on-stop.sh",
					"ext": ["ext"]
					//"ext": ["ext" , "egress/ext"]
				}
			]
		}
		/* ... */
	]
}
```

After the thresholds are exceeded, the corresponding table will begin to be filled with data.

Be careful - extended tables include not only the traffic that caused the excesses, but all that belongs to this monitoring object.


### Anomaly alerts using Telegram-bot

With the help of scripts that run when the threshold is exceeded and when the traffic returns to normal, you can notify the user using instant messengers. We use Telegram, the scripts for launching the bot and notifications are in the directory [./scripts/telegram-bot/](scripts/telegram-bot/)

Create a directory through which scripts will exchange information:
``` sh
$ mkdir -p /var/lib/xenoeye/telemsg/
```

Copy the scripts to the location where they will be run from:
``` sh
$ mkdir -p /var/lib/xenoeye/scripts/tgm/
$ cp scripts/telegram-bot/* /var/lib/xenoeye/scripts/tgm/
```

Edit the monitoring object:
`mo.conf`
```
{
	"name": "mavg1",
	"fields": ["src host", "proto", "octets"],
	"overlimit": [
		{
			"name": "level1",
			"action-script": "/var/lib/xenoeye/scripts/tgm/on-start.sh",
			"back2norm-script": "/var/lib/xenoeye/scripts/tgm/on-stop.sh"
		}
	]
}
```

Restart the collector. Now, when thresholds are exceeded, scripts for notifications will be executed.

The next step is to set up the bot.

  1. Create a Telegram bot (there is a lot of documentation on the Internet on how to do this)
  2. Add the bot's `API_TOKEN` to the script code, instead of `...` in the line `API_TOKEN = '...'`
  3. Start the bot
  4. Start a chat with him
  5. Type the `/id` command in the chat with the bot, the bot will answer what the chat ID is
  6. Add a chat ID to the script code `CHATS = [<your-id>]`. There can be several identifiers (should be separated by commas, `CHATS = [id1, id2]`), then the bot will send notifications to several chats
  7. Restart your bot

After that, the bot should start sending notifications


![telegram-bot](docs-img/tele-bot.png?raw=true "telegram bot")

The red ball marks the beginning of exceeding the threshold, the green one (in response to the beginning) marks the end.

The bot checks for anomalies every few seconds (default 10). If during this time the traffic managed to exceed the threshold and return to normal, the message comes with a yellow ball
