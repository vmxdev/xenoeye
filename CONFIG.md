# Full description of configuration files

  * [Main configuration file `xenoeye.conf`](#main-configuration-file-xenoeyeconf)
  * [Setting the sampling rates `devices.conf`](#setting-the-sampling-rates-devicesconf)
  * [Description of the monitoring object `mo.conf`](#description-of-the-monitoring-object-moconf)
  * [Files with thresholds](#files-with-thresholds)
  * [IP Lists](#ip-lists)

## General remarks

The configuration consists of two general configuration files and several files that describe the monitoring objects.

The config files in `xenoeye` are JSON, which allows comments.

Two types of comments are allowed: single-line comments that start with `//` and continue to the end of the line, and multi-line comments that start with `/*` and end with `*/`.

Unknown keys are ignored when reading configs.

### Main configuration file `xenoeye.conf`

The file consists of the following sections:

```
{
	"capture": [
		{"socket": {"listen-on": "*", "port": "2055"}},
		{"pcap" : {"interface": "eth0", "filter": "udp and port 2055"}}
	],

	"templates": {
		"db": "/var/lib/xenoeye/templates.tkvdb"
	},

	"debug": {
		/* allowed values: "none", "syslog", "/path/to/file.txt" */
		"dump-flows": "none"
	},

	"devices": "/etc/xenoeye/devices.conf",

	"mo-dir": "/var/lib/xenoeye/mo"
}
```

#### Section `capture`

Each element in the array describes a netflow processing thread.

The collector can capture netflow packets in two ways: using the normal socket interface and using pcap

`socket` is the usual socket interface. Parameters - address on which to listen and port

`pcap` - capturing netflow packets using the libpcap library.

The `interface` parameter is the name of the interface on which to capture netflow and `filter` is the BPF filter.

The BPF filter can be empty, in which case the collector will try to parse all UDP packets on this interface.

The worker thread captures only those packets that are matched by the filter.


#### Section `templates`

In this section, you can specify the file in which netflow templates are stored. The templates are stored on disk, after the start the collector reads them and can immediately decode the flows.

In order to distinguish between devices, a combination of the IP address of the netflow source (router) plus the source ID is used.

Sometimes [samplicator](https://github.com/sleinen/samplicator) or equivalents are used to duplicate netflow. If you collect data from several routers, then after the samplicator they may have the address of the samplicator itself as the source IP address.


#### Section `debug`

The collector can print the contents of decoded flows for debugging. Depending on the value of `"dump-flows"`, it may print to syslog + stderr or to a file.

If printing to syslog is selected, messages are additionally printed to stderr (`LOG_PERROR`). Facility = `LOG_USER`, level = `LOG_DEBUG`.

When printing to a file, buffering is used, the data does not appear in the file immediately, but after a while and in blocks.


#### `devices` and `mo-dir` keys

Point to a file with a sampling frequency and a directory with monitoring objects (see below)


#### `geodb` key

Path to GeoIP/AS databases, "`/var/lib/xenoeye/geoip/`" by default


### Setting the sampling rates `devices.conf`

The collector (at least for now) does not read the sample rate data from the option template. To set the frequency, you need to write it to the `devices.conf` file.

File example:
```
[
	{
		"ip": "127.0.0.1",
		"id": 0,
		"sampling-rate": 1
	},
	{
		"ip": "1.2.3.4",
		"sampling-rate": 1000
	}
	/* ... */
]
```

`ip` - device address, `id` - device identifier. If you enable debug flow printing, then the IP, ID, and sample rate of the device will be printed at the end of each flow.

The default sampling rate is 1.


### Description of the monitoring object `mo.conf`

The directory with monitoring objects contains subdirectories with `mo.conf` files. These files describe monitoring objects.

File example:
```{
	"filter": "dst net mynet",

	"debug": {
		"dump-flows": "none"
	},

	"classification": [
		{
			"fields": ["proto", "mfreq(src port,dst port)", "tcp-flags"],
			"top-percents": 90,
			"time": 30,
			"val": "octets desc"
		}
		,
		{
			"id": 3,
			"fields": ["div_r(octets,packets,100)"],
			"top-percents": 90,
			"time": 30,
			"val": "packets desc"
		}
	],

	"mavg": [
		{
			"name": "mavg1",
			"time": "10",
			"dump": "10",
			"fields": ["dst host", "packets"],
			"overlimit": [
					{
						"name": "level1",
						"limits": "limits1.csv",
						"default": [100000],
						"action-script": "/var/lib/xenoeye/scripts/act.sh",
						"back2norm-time": 5,
						"back2norm-script": "/var/lib/xenoeye/scripts/back.sh"
						"ext": ["ext", "other_mo/ext"]
					}
			]
		}
	]

	,

	"fwm": [
		{
			"name": "fw1",
			"fields": ["src host", "packets desc", "octets desc"]
			"time": 15,
			"limit": 5
		},
		{
			"extended": true,
			"name": "ext",
			"fields": ["octets desc", "src host", "dst host", "proto"]
			"time": 5,
			"limit": 100
		}
	]
}
```

#### `filter` key

A rule in a BPF-like language that describes this monitoring object. Any netflow fields and functions that are known to the system can be used in the rule.

An empty filter is allowed, in this case all flows will be included in the monitoring object.

Filter syntax:
```
filter = IP_ADDR_FIELD_NAME <IPv4/IPv6 ADDR>    /* single address */

filter = IP_ADDR_FIELD_NAME <ADDR_LIST_FILE>    /* file with a list of addresses */

filter = INT_FIELD_NAME INT_VAL                 /* single value */

filter = INT_FIELD_NAME INT_VAL_MIN-INT_VAL_MAX /* range of values */

filter = FIELD_NAME V1 or V2 or V3 ...          /* list of multiple possible values */


filter = NOT <expr>  /* expression inversion */

filter = <expr1> AND <expr2> AND <expr3> ...    /* multiple conditions that must be met at the same time */

filter = <expr1> OR <expr2> OR <expr3> ...      /* multiple conditions, at least one must be met */

filter = <expr1> AND (<expr2> OP <expr3>)       /* AND precedence is higher than OR, brackets may change precedence */

```

Some fields may be prefixed with `src` or `dst` (for example, `src as` or `dst host`). If no prefix is specified, both dst and src will be used.

IPv6 fields have a `6` suffix - `host6`/`net6`.

Examples:

`dst net my-net` - traffic from destination IP from `my-net` list

`net bogon-net` - the filter will select flows whose either `IPV4_SRC_ADDR` or `IPV4_DST_ADDR` belong to bogon networks

`src net6 bogon-net and dst net6 bogon-net` - traffic in which both src IPv6 and dst IPv6 belong to bogon networks

`dst as 12345 and not (dst host 1.2.3.4 or 2.3.4.5 or 3.4.5.6)` - flows with dst autonomous system 12345, excluding several addresses

Current list of available netflow fields: [`filter.def`](filter.def)

See also [How to add a new Netflow field to the collector](INTERNALS.md#)"


Current list of available functions:


  * `continent(ip)` - lowercase two-letter continent code (`eu`, `as`, ...)
  * `country_code(ip)` - lowercase two-letter country code (`es`, `ru`, `cn`, ...)
  * `country(ip)` - full country name
  * `state(ip)`
  * `city(ip)`
  * `zip(ip)`
  * `lat(ip)` - latitude
  * `long(ip)` - longitude

  * `asn(ip)` - autonomous system number
  * `asd(ip)` - text description of the autonomous system

  * `min(port1, port2)` - selects the minimum value of port1 and port2
  * `mfreq(port1, port2)` - selects the more frequently used port
  * `div(aggr1, aggr2)` - division, used to determine the average packet size
  * `divr(aggr1, aggr2, N)` - division with rounding
  * `divl(aggr1, aggr2, N)` - division with rounding down to the nearest power of N


#### Section `debug`

The allowed values are the same as in the `debug` section of the main configuration file.

But, unlike general debugging, only flows that belong to this monitoring object will be printed.


#### Section `fwm`

An array describing multiple time windows of a fixed size.

Description of keys:

`name`: window name. From this name, the name of the table in PostgreSQL is formed, into which the data will be exported. Table name = monitoring object directory + `_` + window name.

`fields`: array of netflow fields and functions to be exported. The same fields are used as in the filter. When exporting, the records will be sorted by fields, from lowest value to highest value. To change the order, add `desc` after the field name.

For example, if you write the fields like this:
`fields = ["src host", "octets"]`

Then the collector will sort the result by src IP order (from smallest to largest)

And if you write it like this:
`fields = ["octets desc", "src host"]`

Then the result will be sorted by the number of bytes from the largest values to the smallest.

The sort order makes sense when the `limit` key is used. With the help of the order, it is possible to export not all IPs, but only the top most significant ones. The rest will be summed up and exported as a separate line.


`time`: window size (time in seconds). The collector will generate a DBMS export file for this table at this interval. The default is `time=30`.

`limit`: how many records to export at one time. If there are more records than this value, then only the first and the remainder will be exported as one line. By default, all records are exported.

`extended`: Marks that this window is inactive at startup and will only be activated when the moving average exceeds the threshold. The default is `false`


#### Section `mavg`

An array describing multiple moving averages. Moving averages for one monitoring object may differ from each other by the set of fields and the window size. The larger the window, the smoother the moving average changes.

Description of keys:

`name`: name used when running scripts (passed as one of the parameters)

`time`: size (in seconds) of the moving average window. Default 5 seconds

`dump`: time (in seconds) between dumps of moving average values. Default is 0 (dump disabled). If you want to see the current values of the moving averages, set this option

`fields`: array of netflow fields and functions over which the collector will monitor the moving average. The fields are the same as in the `fwm` section

`mem-m`: memory size (in megabytes) for . Default 256M

`overlimit`: array describing thresholds exceeded


Description of `overlimit` element keys

`name`: name used when running scripts (passed as one of the parameters)

`limits`: file with thresholds (see below), optional parameter

`default`: default threshold (if the address or fieldset is not in the `limits` file)

`action-script`: path to the script that will run when the threshold is exceeded.

`back2norm-time`: The amount of time the system waits after traffic has dropped below the threshold. The moving average can very quickly break through the threshold from above and below, so as not to constantly execute scripts, there is this parameter

`back2norm-script`: path to a script that will run when traffic returns to normal

`ext`: array of extended statistics elements. After breaking through the threshold, these elements are activated, the tables begin to fill with data. It is allowed to activate elements from other monitoring objects, for example, when the ingress traffic threshold is broken, you can enable extended statistics on egress traffic as well.


#### Section `classification`

An array describing the traffic classification for this monitoring object

Description of keys:

`fields`: list of netflow fields or functions by which traffic will be classified

`time`: time in seconds over which statistics for classification are accumulated. Classification occurs continuously, every `time` seconds

`top-percents`: percentage of traffic from the sample that will be classified

`val`: the value by which the sample will be sorted before classification. `"octets desc"` or `"packets desc"` - by bytes or packets

`id`: class number. After classification, a virtual field with the class name will be added to each flow. These fields with names are called `class0`, `class1`, ..., they are different for each section. If you need to change the number in the name, this can be done by changing this key. For example, if you set `"id": 3`, class names will be written in the `class3` field. In total, up to 5 classifiers are allowed per monitoring object

These virtual fields with class names can be used in the `fwm` and `mavg` sections, just like other netflow fields.

The database with classification results is stored in the file system, in the form of files and directories.
To rename a class, you need to edit the file `/var/lib/xenoeye/clsf/<name of monitoring object>/<classifier number>/<class>/name`
You can name several classes with one name.
Files with class names are reread every `time` seconds.


### Files with thresholds

The thresholds are written in CSV format, the fields must be in the same order as in the `fields` key.

If `"fields": ["src host", "octets"]` then the threshold file should look like this:

```
1.2.3.4,1000000
1.2.3.5,2000000
```

Be careful, 1000000 and 2000000 are **octets** (bytes) per second.

You can set thresholds not just by IP addresses, but by a unique combination of netflow fields.

For example, if `"fields": ["src host", "proto", "packets"]` then the strings should be in this format:

```
# ICMP threshold
1.2.3.4.1.100000
# UDP
1.2.3.4.17.200000
# TCP
1.2.3.4.6.300000
# For another address, set the threshold only over TCP
1.2.3.5.6.200000
```

If the address or combination of fields is not in this file, then the value of `default` is considered the threshold.

The file allows empty lines and lines with comments (start with `#`)


### IP Lists

If you need to use many IP networks in filters, it makes sense to store them in separate files.

The file format is simple: network per line, empty lines and lines with comments are also allowed (start with `#`)

In one file, you can record both IPv4 and IPv6 networks in order to use them in different filters later.

`"filter": "dst net my-net"` - IPv4 networks from the list will be used

`"filter": "dst net6 my-net"` - IPv6
