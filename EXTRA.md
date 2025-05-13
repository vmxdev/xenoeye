# Additional features

  * [GeoIP](#geoip)
  * [Autonomous systems](#autonomous-systems)
  * [Updating databases without restarting the collector](#updating-databases-without-restarting-the-collector)
  * [xegeoq utility](#xegeoq-utility)
  * [Visualizing GeoIP data and AS names with Grafana](#visualizing-geoip-data-and-as-names-with-grafana)
  * [Traffic classification](#traffic-classification)
  * [sFlow](#sflow)
  * [Additional data analysis using sFlow: DNS and SNI](#additional-data-analysis-using-sflow-dns-and-sni)
  * [Nested/Hierarchical Monitoring Objects](#nestedhierarchical-monitoring-objects)
  * [Interfaces classification](#interfaces-classification)
  * [Traffic drops below threshold](#traffic-drops-below-threshold)
  * [Changing moving average thresholds without restarting the collector](#changing-moving-average-thresholds-without-restarting-the-collector)


### GeoIP

A quick general note: despite the fact that geo-information is often used for various reports, you should not trust this data too much.
Geo-bases are not always accurate, they do not cover all addresses, and network attacks often use fake IP addresses.
Use GeoIP with reasonable caution.

The collector is designed to use GeoIP databases in the https://ipapi.is/geolocation.html format

For GeoIP to work, you need to download this data, convert it into an internal format and place it in a special directory for the collector.

How to do this, step by step:

Receive and unpack CSV data files:

``` sh
$ mkdir geo && cd geo
$ wget https://ipapi.is/data/geolocationDatabaseIPv4.csv.zip
$ wget https://ipapi.is/data/geolocationDatabaseIPv6.csv.zip
$ unzip geolocationDatabaseIPv4.csv.zip
$ unzip geolocationDatabaseIPv6.csv.zip
$ cd ..
```

Build databases in internal format from CSV files. To do this, use the `xemkgeodb` utility:

``` sh
$ mkdir geodb
$ ./xemkgeodb -o geodb -v -t geo geo/geolocationDatabaseIPv4.csv geo/geolocationDatabaseIPv6.csv
```

After this, the files `geo4.db` and `geo6.db` should appear in the `geodb` directory.

You need to place these files in a special collector directory. It is set in the global config `xenoeye.conf`
``` json
"geodb": "/var/lib/xenoeye/geoip"
```

``` sh
$ mv geodb/geo* /var/lib/xenoeye/geoip/
```

When the collector is restarted (or if a `-HUP` signal is sent to the collector process), it will load these databases and the GeoIP functions will begin to work.


#### Using GeoIP in a Collector

GeoIP data can be used in filters (to create geographic monitoring objects) or in fields that are exported to PostgreSQL

This is done using functions:

  * `continent()` - lowercase two-letter continent code (`eu`, `as`, ...)
  * `country_code()` - lowercase two-letter country code (`es`, `ru`, `cn`, ...)
  * `country()` - full country name
  * `state()`
  * `city()`
  * `zip()`
  * `lat()` - latitude
  * `long()` - longitude

All functions take a netflow field with an IP address as an argument.

For example, in order to create a monitoring object that will contain traffic entering our network and only from Russia, you need to make the following filter:

`ingress_ru/mo.conf`:
``` 
{
	"filter": "dst host our-net and country_code(src host) 'ru'"
	/* ... */
}
```

The collector will convert the `country_code(src host)` of each flow into a two-letter country code and compare it with `ru`

In order to export geo-information to a DBMS, you need to use the function from the list above as a field.

Examples:

Monitoring object `ingress`, all traffic entering our networks gets into it, the src address is converted into the name of the country, octets are summed up for each country and exported to the DBMS:
`ingress/mo.conf`
```
{
	"filter": "dst net our-net",

	/* ... */

	"fwm": [
		/* ... */
		{
			"name": "country",
			"fields": ["octets desc", "country(src host)"]
		}
	]
}
```

Country data will be exported to the DBMS in the following form:
```
=> select * from ingress_country limit 10;
          time          |   octets    | country_src_host_ 
------------------------+-------------+-------------------
 2023-10-12 11:02:45+03 | 17561134000 | Russia
 2023-10-12 11:02:45+03 |  3002667000 | ?
 2023-10-12 11:02:45+03 |  2094074500 | United States
 2023-10-12 11:02:45+03 |  2030411000 | Netherlands
 2023-10-12 11:02:45+03 |   403552000 | Germany
 2023-10-12 11:02:45+03 |   376779000 | Finland
 2023-10-12 11:02:45+03 |   144323000 | France
 2023-10-12 11:02:45+03 |   128383500 | Japan
 2023-10-12 11:02:45+03 |   124174500 | Hungary
 2023-10-12 11:02:45+03 |    61062500 | United Kingdom
```
`?` means that there are no entries in the GeoIP database for these addresses

One more example. Monitoring object `ingress_ru`, traffic to our networks only from Russia. src addresses are converted into the names of regions and cities, the octets are summed up for each element and exported to the DBMS.
`ingress_ru/mo.conf`:
```
{
	"filter": "dst net our-net and country_code(src host) 'ru'",

	/* ... */
	"fwm": [
		{
			"name": "city",
			"fields": ["octets desc", "city(src host)"]
		}
		,
		{
			"name": "state",
			"fields": ["octets desc", "state(src host)"]
		}
		/* ... */
	]
}
```

Data that is exported to the DBMS:

```
=> select * from ingress_ru_state;
          time          |   octets   |    state_src_host_    
------------------------+------------+-----------------------
 2023-10-12 22:06:34+03 | 6571390500 | Москва
 2023-10-12 22:06:34+03 | 2879552500 | Санкт-Петербург
 2023-10-12 22:06:34+03 | 2359202000 | Ленинградская Область
 2023-10-12 22:06:34+03 |  665152000 | Архангельская Область
 2023-10-12 22:06:34+03 |  374177500 | Тюменская Область
 2023-10-12 22:06:34+03 |  354527500 | Владимирская Область
 2023-10-12 22:06:34+03 |  321759000 | Костромская Область
 2023-10-12 22:06:34+03 |  131455000 | Калужская Область
 2023-10-12 22:06:34+03 |   29730000 | Рязанская Область
...


=> select * from ingress_ru_city;
          time          |   octets   |  city_src_host_  
------------------------+------------+------------------
 2023-10-12 22:06:34+03 | 6569109000 | Moscow
 2023-10-12 22:06:34+03 | 2879552500 | Saint Petersburg
...

```


### Autonomous systems

Even if the router cannot export AS numbers, they can be obtained from IP addresses using external databases. In addition to numbers, you can also get AS names.

We're using databases from https://github.com/sapics/ip-location-db project

This works in much the same way as with GeoIP databases.

You need to download csv files with data:

``` sh
$ cd geo
$ wget https://raw.githubusercontent.com/sapics/ip-location-db/main/asn/asn-ipv4.csv
$ wget https://raw.githubusercontent.com/sapics/ip-location-db/main/asn/asn-ipv6.csv
$ cd ..
```

Convert to internal format:

``` sh
$ ./xemkgeodb -o geodb -t as geo/asn-ipv4.csv geo/asn-ipv6.csv
```

If everything went without errors, copy the databases to the collector directory:
``` sh
$ cp geodb/as* /var/lib/xenoeye/geoip/
```

After restarting the collector (or sending the -HUP signal to the collector process), the database can be used.


#### AS functions

  * `asn()` - autonomous system number
  * `asd()` - text description of the autonomous system

Just like GeoIP functions, they take a netflow field with an IP address as an argument.

Example. We break down all incoming traffic by names of autonomous systems:
`ingress/mo.conf`:
```
{
	"filter": "dst net our-net",

	/* ... */

	"fwm": [
		/* ... */
		{
			"name": "as",
			"fields": ["octets desc", "asd(src host)"],
			"limit": 30
		}
	]
}
```

```
=> select * from ingress_as;
          time          |   octets   |      asd_src_host_       
------------------------+------------+--------------------------
 2023-10-13 11:40:46+03 | 7260510500 | PJSC MegaFon
 2023-10-13 11:40:46+03 | 3816886000 | T2 Mobile LLC
 2023-10-13 11:40:46+03 | 2124086000 | PJSC Rostelecom
 2023-10-13 11:40:46+03 | 1551007000 | Google LLC
 2023-10-13 11:40:46+03 | 1361819000 | LLC VK
 2023-10-13 11:40:46+03 |  777337000 | CJSC RASCOM
 2023-10-13 11:40:46+03 |  761207000 | Global DC Oy
 2023-10-13 11:40:46+03 |  753907500 | Hetzner Online GmbH
 2023-10-13 11:40:46+03 |  592446000 | MEGASVYAZ LLC
...
```

### Updating databases without restarting the collector

GeoIP databases and AS databases are updated quite often. Be careful: the owners of these databases can silently change the format of the CSV files and then the collector will not be able to read them.

It is better to update GeoIP databases manually, or somehow control the update process. The update algorithm is approximately the same as for the first use.

1. You need to download CSV files
2. Generate .db files from CVS files
3. See if everything went well and there are no errors
4. Place new .db files in the geoip directory of the collector
5. Send the -HUP signal to the collector process, it will re-read the database


### xegeoq utility

To test GeoIP and AS, we made a utility called `xegeoq`

It can be used to obtain GeoIP and AS information.

The utility takes as input the path to the database (in internal format) and an IP address or a list of IP addresses. Addresses can be either IPv4 or IPv6

``` sh
./xegeoq -i /var/lib/xenoeye/geoip 1.1.1.1 2A03:2880:10FF:0008:0000:0000:FACE:B00C
1.1.1.1 geo: oc, au, Australia, Victoria, Research, 3095, -37.7, 145.18333
1.1.1.1 as: 13335, Cloudflare, Inc.
2A03:2880:10FF:0008:0000:0000:FACE:B00C geo: ?
2A03:2880:10FF:0008:0000:0000:FACE:B00C as: 32934, Facebook, Inc.
```

### Visualizing GeoIP data and AS names with Grafana

To make it easier to create reports in Grafana, we wrote the following PL/PGSQL function:
```
CREATE OR REPLACE FUNCTION xe_rep(
        src TEXT,
        fld TEXT,
        aggr_fld TEXT,
        k TEXT,
        cond TEXT,
        ntop INT DEFAULT 20,
        unk TEXT DEFAULT '?'
    ) RETURNS TABLE (
        tm TIMESTAMPTZ, 
        val BIGINT,
        name TEXT
    ) AS $$
DECLARE
    query TEXT;
    select_top TEXT;
    fld_t TEXT;
BEGIN
    fld_t := fld || '::text';

    select_top := 'SELECT
            sum('|| aggr_fld || ') AS val, COALESCE (' || fld_t || ', ''Other'') AS name
        FROM ' || src || 
        ' WHERE ' || cond || ' GROUP BY name ORDER BY val desc limit ' || ntop;

    query := 'SELECT time, (sum(' || aggr_fld || ')' || k || ')::bigint AS val, COALESCE(NULLIF(name, ''''), ''' || unk || ''')
            FROM (
                WITH topval AS (' || select_top || ')
            SELECT time, ' || aggr_fld || ',  COALESCE (' || fld_t || ', ''Other'') AS name
                FROM ' || src || ' WHERE ' || cond || ' AND ' || fld_t || ' IN (SELECT name from topval)
            UNION ALL
            SELECT time, ' || aggr_fld || ', ''Other'' AS name
                FROM ' || src || '
                WHERE ' || cond || ' AND ' || fld_t || ' NOT IN (SELECT name from topval)
            UNION ALL
            SELECT time, ' || aggr_fld || ', ''Other'' AS name
                FROM ' || src || '
                WHERE ' || cond || ' AND ' || fld_t || ' IS NULL
        ) AS report
    GROUP BY time, name ORDER BY time';

    RETURN QUERY EXECUTE query;
END;
$$ LANGUAGE plpgsql;
```

If you don't have enough permissions when creating a function (`ERROR: permission denied for schema public`), then run:
``` sh
$ sudo su - postgres -c "psql -d xenoeyedb -c 'ALTER DATABASE xenoeyedb OWNER TO xenoeye;'"
```

The function builds the top N entities (countries, cities, IP addresses, etc.) for a period and selects only them. Those who are not included in the top are grouped under the name 'Other'.

When creating a panel in Grafana, you can write a call to this function in the SQL query field:

```
select tm as time, val as city, name from xe_rep('ingress_ru_city', 'city_src_host_', 'octets', '*8/30', $$ $__timeFilter(time) $$, 20);
```

  - `ingress_ru_city` - table with traffic by city
  - `city_src_host_` - name of the field with cities in the table
  - `octets` - report by bytes (not by packets)
  - `*8/30` - factor, data is added to the table every 30 seconds, to get bits per second, multiply the bytes by 8 and divide by 30 seconds.
  - `$$ $__timeFilter(time) $$` - Grafana macro, filters data only for the required period
  - 20 - the top 20 cities are selected by the amount of traffic, the rest will be in the report as 'Other'


Incoming traffic by autonomous system:

![Grafana by as](docs-img/grafana-as.png?raw=true "Grafana netflow by autonomous systems")

Incoming traffic by country:

![Grafana geoip by countries](docs-img/grafana-geoip-country.png?raw=true "Grafana netflow GeoIP by countries")


Incoming traffic only from Russia by region:

![Grafana geoip by state](docs-img/grafana-geoip-state.png?raw=true "Grafana netflow GeoIP by states")


Incoming traffic only from Russia by city:

![Grafana geoip by city](docs-img/grafana-geoip-city.png?raw=true "Grafana netflow GeoIP by cities")


### Traffic classification

Often network engineers need to understand, atleast approximately, what types of traffic dominate the network. This is done using "classification by application".

Data from netflow is quite difficult to classify “by application” and there are several reasons for this:

  - Even ordinary users (not malicious actors) launch services on non-standard and high ports so that they are not noticed by scanning robots and monitoring systems
  - Data about several network packets can be transmitted in one flow; we can only calculate the average packet size
  - The TCP-flags field is actually a combination (logical OR) of the TCP flags of several TCP session packets that the router saw
  - Netflow data is sampled in most cases

That is, the classification “by application” in the case of netflow/IPFIX is rather a classification by some netflow fields.

Typically, ports, protocols, TCP flags, and packet sizes are used for classification.

Classification in xenoeye works like this: the user selects the fields by which he wants to classify traffic.
The collector collects flows for some time, aggregates them, then sorts them in descending order of packets/octets, selects the top X percent (the number is specified by the user) and breaks this traffic into “classes”.
After this, a label is added to each flow - the name of the class.
The collector tries to name classes in a human-readable way, for example converting port numbers into names, combinations of TCP flags into text form ("ACK+PSH+SYN", "ACK+RST", etc.).
Class names are stored in files (`/var/lib/xenoeye/clsf/<object name>/<classifier number>/<class>/name`), you can rename any class.
Say, you can call UDP traffic on port 443 "QUIC/VPN".
Classification occurs continuously during collector operation. Because network traffic can change significantly over time, new classes may be added periodically.

By making this module, it was planned to solve several problems:
  - see what’s happening on the network by service
  - have the ability to unite certain types of traffic under a common name
  - be able to see separately some types of traffic (for example, traffic on the same ports/protocols, but with different packet sizes)
  - since classes are created automatically from top traffic, after a certain period of “training” the appearance of a new class can be considered as a network anomaly

For classification, the collector has the following auxiliary functions:
  * `min(port1, port2)` - selects the minimum value of port1 and port2
  * `mfreq(port1, port2)` - selects the more frequently used port
  * `div(aggr1, aggr2)` - division, used to determine the average packet size
  * `divr(aggr1, aggr2, N)` - division with rounding
  * `divl(aggr1, aggr2, N)` - division with rounding down to the nearest power of N

`min(src port, dst port)` - the minimum value of the two ports. If services run on small port numbers, this function will return the "server" port, which can be used to guess the type of traffic

`mfreq(src port, dst port)` - returns the port that is used most often (statistics are collected only for the current monitoring object). If the service is on a very high port, but it is often caught in flows, then the function will return this more frequently used high port


The `div*` functions are designed to classify by average packet sizes

`divr(octets,packets,N)` - division with rounding. Divides the number of bytes in the flow by the number of packets and rounds

`divr(octets,packets,100)` for packet sizes from the range 0-99 it will return 0, from the range 100-199 -> 100, 200-299 -> 200, etc.


`divl(octets,packets,N)` - division with rounding down to the nearest power of N. If you need to roughly classify packets by size, for example as "small", "medium", "large" - you can use this function.

`divl(octets,packets,10)` for packet sizes from the range 10-99 it will return 10, from the range 100-999 -> 100, 1000-9999 -> 1000


One monitoring object can be classified with different sets of fields. Class names are added to the set of flow fields as "class0", "class1", etc.
Below is an example for classifying all incoming traffic, but you can classify arbitrary monitoring objects. For example, DNS traffic by protocols (UDP/TCP) and packet size, or separately HTTPS by protocols and TCP flags.
`ingress/mo.conf`:
```
{
	"filter": "dst net our-net",                             // all incoming traffic

	"classification": [{
		// class0
		"fields": ["proto", "mfreq(src port,dst port)"], // we are interested in protocols and ports
		"top-percents": 90,                              // classify the top 90% of traffic
		"val": "octets desc"                             // 90% selected by number of octets
	}
	,
	{
		// class1
		"fields": ["proto", "div_r(octets,packets,100)"], // protocol + packet size
		"top-percents": 90,
		"val": "packets desc"                             // 90% selected by number of packets
	}
	,
	{
		"fields": ["proto", "tcp-flags"],                 // protocol + tcp flags (for non-tcp flags field == 0)
		"top-percents": 90,
		"val": "octets desc"
	}
	],

	/* ... */
	"fwm": [
		/* ... */
		/* export traffic classified by different fields to PostgreSQL */
		{
			"name": "clsf_port",
			"fields": ["octets desc", "class0"],
			"limit": 30
		}
		,
		{
			"name": "clsf_size",
			"fields": ["packets desc", "class1"]
		}
		,
		{
			"name": "clsf_flags",
			"fields": ["octets desc", "class2"]
		}
	}
}

```

#### Classification results on Grafana plots

To build time series with classification, you can use the `xe_rep` function shown above.

The call parameters are the same - table name, field, etc.

By default, unclassified traffic will be shown with the name `?`. To change this, you need to add an optional parameter:
```
select tm as time, val as class, name from xe_rep('ingress_clsf_port', 'class0', 'octets', '*8/30', $$ $__timeFilter(time) $$, 20, 'Unclassified');
```

Classification by ports:

![Grafana classification by ports](docs-img/grafana-class-port.png?raw=true "Grafana netflow classification by ports")

By packets size:

![Grafana classification by size](docs-img/grafana-class-size.png?raw=true "Grafana netflow classification by packet size")

Classification of HTTP/HTTPS traffic by protocols and TCP flags

![Grafana classification by size](docs-img/grafana-class-http.png?raw=true "Grafana netflow classification by packet size")


### sFlow

The collector collects and processes sFlow if there is a section `"sflow-capture"` in the main configuration file:
```
	"sflow-capture": [
		//{"pcap": {"interface": "eth0", "filter": "udp and port 6343"}},
		{"socket": {"listen-on": "*", "port": "6343"}}
	]
```

Just like for Netflow, you can use regular sockets or collect from the network interface using libpcap.

Once the collector starts collecting sFlow, it can be processed in the same way as Netflow. You can create monitoring objects, describe a filter, tables for data export, and moving averages.

If the collector does not recognize the sFlow packet, it silently discards it. To understand how the collector sees sFlow traffic, the `xesflow` utility is included. It captures traffic using pcap and shows the sFlow fields it knows.

```
# ./xesflow -i eth1 -f "udp and port 6343"
version: 5 [sflow-impl.h, line 198, function sflow_process()]
agent address type: 1 [sflow-impl.h, line 205, function sflow_process()]
agent address (IPv4): 172.16.2.2 [sflow-impl.h, line 214, function sflow_process()]
agent id: 16 [sflow-impl.h, line 232, function sflow_process()]
sequence: 15690 [sflow-impl.h, line 235, function sflow_process()]
uptime: 2858088699 [sflow-impl.h, line 238, function sflow_process()]
samples: 7 [sflow-impl.h, line 241, function sflow_process()]
        sample #0 [sflow-impl.h, line 245, function sflow_process()] 
        sample type: 1 (SF5_SAMPLE_FLOW) [sflow-impl.h, line 249, function sflow_process()]
        length:  144 [sflow-impl.h, line 61, function sf5_flow()]
        sequence: 53379644 [sflow-impl.h, line 64, function sf5_flow()]
        src id: 518 [sflow-impl.h, line 67, function sf5_flow()]
        sampling rate: 400 [sflow-impl.h, line 70, function sf5_flow()]
        sample pool: 1956205512 [sflow-impl.h, line 74, function sf5_flow()]
        drop events: 0 [sflow-impl.h, line 76, function sf5_flow()]
        input interface: 0 [sflow-impl.h, line 80, function sf5_flow()]
        output interface: 518 [sflow-impl.h, line 88, function sf5_flow()]
        number of elements: 2 [sflow-impl.h, line 95, function sf5_flow()]
                element #0 [sflow-impl.h, line 100, function sf5_flow()]
                tag: 1 [sflow-impl.h, line 102, function sf5_flow()]
                element length: 80 bytes [sflow-impl.h, line 105, function sf5_flow()]
                header protocol: 1 [sflow-impl.h, line 126, function sf5_flow()]
                header len: 64 [sflow-impl.h, line 127, function sf5_flow()]
                sampled size: 68 [sflow-impl.h, line 129, function sf5_flow()]
                        Ethernet src: 54:4b:8c:ef:23:c0 [rawparse.h, line 116, function rawpacket_parse()]
                        Ethernet dst: 00:25:90:7c:41:8f [rawparse.h, line 116, function rawpacket_parse()]
                        Ethernet proto: 0x8100 [rawparse.h, line 116, function rawpacket_parse()]
                        VLAN 607 [rawparse.h, line 129, function rawpacket_parse()] 
                        IPv4 src: 91.32.91.80 [rawparse.h, line 179, function rawpacket_parse()]
                        IPv4 dst: 121.101.245.97 [rawparse.h, line 179, function rawpacket_parse()]
                        TOS: 0x0 [rawparse.h, line 179, function rawpacket_parse()]
                        ID: 16183 [rawparse.h, line 179, function rawpacket_parse()]
                        TTL: 118 [rawparse.h, line 179, function rawpacket_parse()]
                        IP protocol: 6 [rawparse.h, line 179, function rawpacket_parse()]
                        TCP src port: 2872 [rawparse.h, line 253, function rawpacket_parse()]
                        TCP dst port: 443 [rawparse.h, line 253, function rawpacket_parse()]
                        TCP flags: 0x10 [rawparse.h, line 253, function rawpacket_parse()]
...
```


### Additional data analysis using sFlow: DNS and SNI

Since the sFlow agent sends chunks of packets to the collector, they can be parsed to get some additional information.

The collector has DNS and TLS (HTTPS) SNI protocol parsers.

For example, if you are a hoster, then these parsers can help you create a “hosting map” to understand which domains are hosted in your data center.

```
	"fwm": [
		// ...
		{
			"name": "dns",
			"fields": ["dns-name", "dns-ips"]
		}
		,
		{
			"name": "sni",
			"fields": ["src host", "dst host", "sni"]
		}
	]
```

The collector parses A(IPv4) and AAAA(IPv6) DNS records.

`dns-ips` are stored in the form `{ip1, ip2, ...}` - there can be several IP addresses in a packet with a DNS response.

A query to the DBMS to obtain domain names and their addresses may look something like this:

```
=> select distinct dns_name, unnest(dns_ips::inet[]) as ip from all_dns_sni_d order by ip;
 ns4-34.azure-dns.info.                      | 13.107.206.34
 ns3-34.azure-dns.org.                       | 13.107.222.34
 144.240.101.34.bc.googleusercontent.com.    | 34.101.240.144
 connectivity-check.ubuntu.com.              | 91.189.91.49
 connectivity-check.ubuntu.com.              | 185.125.190.18
 connectivity-check.ubuntu.com.              | 2001:67c:1562::24
 ns3-39.azure-dns.org.                       | 2a01:111:4000:10::27
 mirror.docker.ru.                           | 2a04:8580:ffff:fffe::2
...
```

To obtain domain names from SNI, the size of the captured packets must be large enough.


### Nested/Hierarchical Monitoring Objects

Monitoring objects can be hierarchical/nested. The file system hierarchy is used for this. In the directory where `mo.conf` is located, create a subdirectory and in it the file `mo.conf`, this will be a nested object. Nested monitoring objects are processed starting from the "top" one.

For example, you can create an object of some network, and inside it create a sub-object "udp" with the filter `"proto 17"` - this will be an object with udp-traffic of only this network.

Nested monitoring objects can be useful when there are many objects: they simplify configuration and can be processed more efficiently than a flat list.



### Interfaces classification

Sometimes network engineers want to account for traffic from only some interfaces and ignore or treat the rest in a special way.

This can be done using filters in the MO, or you can use the "interface classification" mechanism in the collector.

In the `devices.conf` configuration file, in the router section, there are two parameters - "mark" and "skip-unmarked":
``` json
	{
		"ip": "1.2.3.4",

		"mark": [
			"src ifidx 1000063 or 1000070 or 1000071",
			"dst ifidx 1000063 or 1000070 or 1000071"
		],
		"skip-unmarked": true
	}
```

Traffic on ports 1000063, 1000070, 1000071 will be marked as follows: if flow goes through one of the ports (`src ifidx`/`dst ifidx`), virtual field `dev-mark` is set to `1`. If two ports are in the list, `dev-mark` is set to `2`. If it does not go through any of the ports, `dev-mark == 0`.

When `skip-unmarked == true` and `dev-mark == 0`, the flow is discarded and not taken into account.

If you think that traffic with `dev-mark == 2` is abnormal and want to analyze it separately, you can create a separate monitoring object with the filter `"dev-mark 2"`.


### Traffic drops below threshold

The collector can use moving averages to track not only traffic spikes, but also drops below a threshold. This can be used to indirectly monitor individual hosts or services (DNS/HTTP, etc.). If a service's traffic has dropped, it's likely that it's in trouble, and it makes sense to notify the user.

In the description of the monitoring object `mo.conf`:
``` json
	"mavg": [
		{
			"name": "pps",
			"time": "30",
			"dump": "5",
			"fields": ["packets"],
			"underlimit": [
					{
						"name": "level1",
						"default": [1000],
						"back2norm-time": 120,
						"action-script": "/var/lib/xenoeye/scripts/underlimit.sh",
						"back2norm-script": "/var/lib/xenoeye/scripts/underlimit-over.sh"
					}
			]
		}
	]
```

### Changing moving average thresholds without restarting the collector

When the collector receives a -HUP signal, it looks at the modification time of the `mo.conf` files. If the date is different from the initial one, the config is reread. But only the threshold data is applied.

The mechanism can be used both manually and automatically. For example, thresholds can be changed by a script that periodically recalculates and sets new thresholds for anomalies and DoS/DDoS attacks.

Some analyzers use the time of day and day of the week to calculate autothresholds. If your threshold recalculation script also uses this information, thresholds can be changed several times a day.
