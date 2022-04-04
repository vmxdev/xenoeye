# xenoeye
Netflow collector

[![Build Status](https://app.travis-ci.com/vmxdev/xenoeye.svg?branch=master)](https://app.travis-ci.com/vmxdev/xenoeye)

[`README.ru.md`](README.ru.md) - документация на русском


Program is in planning and early development stage, use with caution

The Collector is designed to detect anomalies in network traffic and get the details of these anomalies using [Netflow](https://en.wikipedia.org/wiki/Netflow) metrics

In its current state, the collector can capture Netflow, parse flows, classify traffic by monitoring objects, aggregate data by netflow fields and export it to a DBMS for further analysis and visualization.


### Supported protocols

  * Netflow v9
  * IPFIX

### Monitoring objects

The key entity in the collector is the monitoring objects. Objects are set by filters. For a description of the filters, see below ("Filters"). The flows that belong to the monitoring object are processed according to the rules of this object.

### Supported netflow-fields

can be viewed in the file [`netflow.def`](netflow.def).

If you want to add a new netflow or filter field, see below ("Adding fields")

### The result of the collector work

Collector generates SQL files for exporting data to a DBMS. Currently only PostgreSQL is supported.

You can visualize data from a DBMS using Grafana.


### Building and installation

On a minimal Debian installation, you need to install the following packages:

```sh
$ sudo apt -y install git autoconf gcc make libpcap-dev
```

Clone the repository and initialize the submodules

```sh
$ git clone https://github.com/vmxdev/xenoeye
$ cd xenoeye
$ git submodule update --init --recursive
```

Actual building

```sh
$ autoreconf -i
$ ./configure --sysconfdir=/etc/xenoeye --localstatedir=/var/lib
$ make
```

After that, we should get a binary file `xenoeye`

Optional step:

```sh
$ sudo make install
```

`make install` copies the xenoeye binary to /usr/local/bin, the xenoeye.conf and devices.conf configuration files to /etc/xenoeye and creates the directories /var/lib/xenoeye/mo, /var/lib/xenoeye/exp and /var/lib/xenoeye/expfailed.

The directory `/var/lib/xenoeye` must be writable by the xenoeye process.

All default paths can be changed, they are set in the configuration file `xenoeye.conf`. The config files in `xenoeye` are JSON in which comments are allowed.

### Setting up and getting netflow

The collector can receive netflow in two ways - using sockets or pcap.

The second case is more suitable for tests. If you have .pcap files with netflow traffic, for example, you can play them on the loopback interface with tcpreplay (`tcpreplay -i lo dump.pcap`) and send them to the collector.

The "capture" section of the configuration file is responsible for capturing netflow. It lists the sockets on which the collector will listen and pcap interfaces with BPF filters.

To see that the collector is accepting and decoding flows, set the "dump-flows" parameter in the "debug" section. Allowed values are

  * "none" - flows are not logged, normal system state
  * "syslog" - decoded flows are sent to syslog and additionally printed to stderr
  * "/path/to/file.txt" - flows in text form are written to a file

Start the collector
```sh
$ xenoeye
```

or

```sh
$ xenoeye -c /path/to/xenoeye.conf
```

If you are capturing with pcap, the collector must be run as root

Once the collector receives the template netflow packets, it can process the data flows. When the "dump-flows" option is enabled, you can see the flows in text like this:

```
IPv4 src addr: 1.2.3.4; IPv4 dst addr: 5.6.7.8; Src TOS: 0; Protocol: 6; Src port: 7878; Dst port: 8787; ICMP type: 0; Input SNMP index: 111; Src VLAN: 222; Src mask: 16; Dst mask: 24; Src AS: 12345; Dst AS: 0; IPv4 next hop: 0.0.0.0; TCP flags: 24; Output SNMP index: 333; Bytes: 65522; Packets: 185; Min TTL: 51; Max TTL: 52; Unknown field 152: 0x00 0x00 0x01 0x77 0x0d 0x0c 0x07 0x00 ; Unknown field 153: 0x00 0x00 0x01 0x77 0x0d 0x0c 0xee 0x00 ; Unknown field 136: 0x02 ; Unknown field 61: 0xff ; Unknown field 243: 0x00 0x00 ; Unknown field 245: 0x00 0x00 ; Unknown field 54: 0x00 0x00 0x00 0x00 ; *dev-ip: 9.10.11.12; *dev-id: 555500, *rate: 1 [flow_debug.c, ...]
```

The collector shows all the fields that are in the netflow packet. He knows some of the fields, some he does not know and shows as "`Unknown field NNN: <bytes with data>`". If you want to teach the collector to understand the new netflow field, see "Adding Fields" below.

Besides the netflow fields, the collector shows "virtual" fields with an asterisk: `*dev-ip: 1.2.3.4; *dev-id: 123456, *rate: 1`.

  * `dev-ip` - IP address of the sensor (router)
  * `dev-id` - Source ID
  * `rate` - sampling rate, default 1

### Setting the sampling rate

To set the sample rate, edit the `devices.conf` file. This is a JSON array, each element is a record of the netflow source device (router).

``` json
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

The rate can be set for the IP address of the device and, if necessary, for the source ID (it can be seen in the text dump of the flow, the virtual field `*dev-id`). The collector shows the sample rate in each flow, in the virtual field `*rate`.

Inside the collector, the sample rate is just a factor by which the number of octets and packets are multiplied.

### Configuring Monitoring Objects

After making sure that netflow comes and is parsed, you can create and configure monitoring objects.

The directory of monitoring objects is specified in the main configuration file, the `mo-dir` parameter. The default is `/var/lib/xenoeye/mo`.

Monitoring objects are subdirectories in this directory.

To create a monitoring object named `monit_object1`, create a subdirectory with that name.

```sh
$ mkdir -p /var/lib/xenoeye/mo/monit_object1
```

And create a file there with a description of the monitoring object. The file should be named `mo.conf` and have the following structure:

``` json
{
	/* In this object traffic to the network 10.11.12.0/24 */
	"filter": "dst net 10.11.12.0/24",

	"debug": {
		/* For the test, you can enable debug mode. The flows that belong to this object will be printed to syslog and stderr */
		"dump-flows": "syslog"
	},

	/* define multiple fixed windows */
	"fwm": [
		{
			/* window with only number of bytes */
			"name": "total",
			"fields": ["octets"]
		},
		{
			/* the window collects the protocol numbers and the number of bytes for each protocol */
			"name": "by_proto",
			"fields": ["octets", "proto"]
		},
		{
			/* src IP address and number of packets from each unique IP */
			"name": "packets_by_src",
			"fields": ["packets desc", "src host"],
			"limit": 5      /* limit the number of export lines */
		},
		{
			/* IP address, destination port and number of packets for each unique src IP + dst port  */
			"name": "octets_by_src_and_port",
			"fields": ["octets desc", "src host", "dst port"],
			"limit": 5,
			"time": 10     /* set the window size to 10 seconds (default 30 seconds) */
		}
	]
}
```

### Filters

Objects are set by filters. Filters are BPF-like rules. Various netflow fields can be used as elements for filtering.
The filter selects only those flows that are needed for monitoring for a particular object.

For example, an object with the filter "`src net 1.2.3.4/28 and proto 17`" will select only flows with UDP traffic coming from network `1.2.3.4/28`.
The logical operators `or`, `and`, `not` and brackets are allowed in filters.

The list of fields by which flows can be filtered is in the [`filter.def`](filter.def) file. To add a new field, see below ("Adding fields")

Fields are of two types - addresses or numeric. To select an address, you can use a network in CIDR notation or the name of a list of networks.
Numeric fields are specified as a single number or range separated by `-`.

For fields that can have a direction, `src` or `dst` can be specified.

The virtual fields `dev-ip` and `dev-id` can be used in the filter. For example, the filter "`dst net 10.11.12.0/24 and dev-ip 1.2.3.4`" will select only flows that come from router 1.2.3.4.


### Lists of IP networks

In the fields with IP addresses, networks can be specified with numeric values (`1.2.3.4/24`) or with a list name. To create a list of networks, create a file in the `/var/lib/xenoeye/iplists/` directory. The file name will be the name of the list. For example, you can create a file `/var/lib/xenoeye/iplists/bogon-net` and put bogon nets in it, one subnet per line:
```
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
```

After that, it will be possible to specify bogon-net as a network in the filter.

The "`net bogon-net`" filter will select flows where `IPV4_SRC_ADDR` **or** `IPV4_DST_ADDR` belongs to bogon networks.

The filter "`src net bogon-net and dst net bogon-net`" will select flows where both `IPV4_SRC_ADDR` **and** `IPV4_DST_ADDR` refer to bogon networks.


### Fixed windows

The `fwm` section describes fixed time windows. The collector aggregates information for the time `time` (if time is not specified, 30 seconds is used) and after this time it dumps the data in the form of a text SQL script. The default export directory is `/var/lib/xenoeye/exp`. It can be changed in `xenoeye.conf`, parameter `export-dir`.

The aggregation uses netflow fields specified as the "fields" parameter. The fields "packets", "octets" and "bits" are counted as the sum of packets, bytes or bits, with the other fields being unique. `bits` = `octets` * 8.

For example, `"fields": ["octets"]` will calculate the sum of bytes per window for the entire monitoring object.

`["octets", "proto"]` - counts all protocols and the sum of bytes for each protocol.

By default, the data in the dump file will be sorted in ascending order.

If you don't want to export all records (there may be a lot of them), you can use the "limit" parameter. It specifies the number of lines to be exported. The last line will be the line with the sum of the remaining lines that were not included in the dump. In the fields of the last row that are not aggregated, there will be NULL, in the fields with packets / bytes there will be the sum of all missing data. For example:

```
IP        Proto    Octets
1.2.3.4   6        200
1.2.3.4   17       100
1.2.3.5   1        300
NULL      NULL     1500
...
```

In case you use a limit, the order of the export lines becomes important. If you need to export top-5 src IP by number of packets, then the fields should be specified in this order: `"fields": ["packets desc", "src host"]`. First comes the field with packets (the lines will be sorted by it), then the rest of the fields.

The `desc` qualifier specifies to sort in reverse order, from highest to lowest.

### Export files and loading into the DBMS

The collector generates export files in the form of SQL scripts for PostgreSQL. In the export directory (by default '/var/lib/xenoeye/exp') files of the following type are created:

``` sql
create table if not exists "monit_object1_rep1" (
  time TIMESTAMPTZ,
  proto int,
  dst_net inet,
  octets int);

create index concurrently if not exists "monit_object1_rep1_idx" on "monit_object1_rep1"(time);

insert into "monit_object1_rep1" values ( to_timestamp(1639725910),  6 ,  '1.2.3.4' ,  2719 );
insert into "monit_object1_rep1" values ( to_timestamp(1639725910),  17 ,  '2.3.4.5' ,  10352 );
insert into "monit_object1_rep1" values ( to_timestamp(1639725910),  1 ,  '3.4.5.6' ,  1584 );
insert into "monit_object1_rep1" values ( to_timestamp(1639725910),  6 ,  '4.5.6.7' ,  75165 );
```

The table name consists of the monitoring object's directory name (`monit_object1`), the underscore character (`_`), and the window name (`rep1`).

For export to the DBMS, you can periodically pass these files to the `psql` utility.

The `scripts/` directory contains the `fill-db.sh` file which does this. Change the connection parameters in it (`user:password@127.0.0.1:5432/database`) and optionally the directory paths. The database must exist and the user must have write access.

  * `EXP_DIR` - directory where the script looks for export files
  * `FAIL_DIR` - directory where the script adds files if the export fails (no connection to the DBMS or something else went wrong)

The script can be run from the command line (in an infinite loop `while true; do ./fill-db.sh ; sleep 10; done`) or from cron.


### Installing and configuring PostgreSQL on the same server as the collector

``` sh
$ sudo apt -y install postgresql
#
$ sudo su - postgres -c "createuser -P xenoeye"
Enter password for new role:
Enter it again:
$ sudo su - postgres -c "createdb xenoeyedb"
$ sudo su - postgres -c "psql -d xenoeyedb -c 'GRANT ALL PRIVILEGES ON DATABASE xenoeyedb TO xenoeye;'"
```

``` sh
$ vi scripts/fill-db.sh
```

Edit connection parameters:

  `psql postgresql://user:password@127.0.0.1:5432/database -f "$sqlscript"`

replace with

  `psql postgresql://xenoeye:password@localhost/xenoeyedb -f "$sqlscript"`

### Visualization with Grafana

Traffic data from PostgreSQL tables can be visualized using [grafana](https://grafana.com/).

To do this, connect a PostgreSQL data source.

![Grafana PostgreSQL data source](docs-img/pg-data-source.png?raw=true "Grafana PostgreSQL data source")

Create a dashboard and add panels with charts to it.


A simple chart with total traffic of the monitoring object:

![Grafana chart 1](docs-img/grafana-1.png?raw=true "Grafana chart 1")

SQL query for such a graph:

``` sql
SELECT
  time AS "time",
  octets
FROM ingress_all
WHERE
  $__timeFilter(time)
ORDER BY 1
```

Chart with traffic broken by destination IP address:

![Grafana chart 2](docs-img/grafana-2.png?raw=true "Grafana chart 2")

SQL query for such a graph:

```
SELECT
  time AS "time",
  sum(octets) AS ip,
  COALESCE (src_host::text, 'Other') as ips
FROM ingress_bytes_by_src
WHERE
  $__timeFilter(time)
GROUP BY time, ips
ORDER BY time, ip
```

A few more chart examples:

![Grafana chart 3](docs-img/grafana-3.png?raw=true "Grafana chart 3")

![Grafana chart 4](docs-img/grafana-4.png?raw=true "Grafana chart 4")

![Grafana chart 5](docs-img/grafana-5.png?raw=true "Grafana chart 5")

![Grafana chart 6](docs-img/grafana-6.png?raw=true "Grafana chart 6")

### Adding netflow fields and fields for filters

The netflow fields that the collector knows are in the `netflow.def` file. Line format:

``` c
FIELD(internal_id,            "Description",              FIELD_TYPE,      netflow_id,  min_size,  max_size)
```

  * `internal_id` - internal identifier, expected valid name for C-struct field
  * `Description` - field description string
  * `FIELD_TYPE` - field type (supported fields are `NF_FIELD_INT`(integer) and `NF_FIELD_IP_ADDR`(IP address))
  * `netflow_record_id` - field identifier
  * `min_size`, `max_size` - minimum and maximum field size in bytes

Field data can be taken from [NetFlow Version 9 Flow-Record Format - Cisco Systems](https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html) или из [IP Flow Information Export (IPFIX) Entities](http://www.iana.org/assignments/ipfix/ipfix.xhtml)

Adding a field to `netflow.def` only changes the netflow parser. In order for this field to be used in filters and in fields for export, you need to add it to `filter.def`

``` c
FIELD(ID,      "name",          TYPE,  src_netflow_field,   dst_netflow_field)
```

  * `ID` - internal identifier
  * `name` - a string with a field that will be used in filters
  * `TYPE` - type (supported RANGE(range of integers), `ADDR4` and `ADDR6` - IP addresses)
  * `src_netflow_field`, `dst_netflow_field` - netflow fields that this filter will work on. `internal_id` values from `netflow.def` are allowed. If the filter can be prefixed with `src` and `dst`, the corresponding netflow fields will be used.

After changing the files, the program needs to be rebuilt.

### List of things that are planned to be done before the release

  * Netflow v5
  * Moving averages
