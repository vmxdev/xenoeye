# Internals

  * [General remarks](#general-remarks)
  * [Worker and auxiliary threads](#worker-and-auxiliary-threads)
  * [Monitoring objects and filters](#monitoring-objects-and-filters)
  * [How to add a new Netflow field to the collector](#how-to-add-a-new-netflow-field-to-the-collector)
  * [Time source](#time-source)
  * [Fixed time windows](#fixed-time-windows)
  * [Moving averages](#moving-averages)
  * [IP lists](#ip-lists)


### General remarks

Netflow data can be viewed as multivariate/multidimentional time series.

There are quite a few approaches and tools for analyzing and processing time series, but the main difficulty in relation to Netflow is its quantity. Even in small networks, there can be a lot of network events that are exported by routers.

Note that many collectors use the words "fast", "high-performance", etc. in the name or description.

To reduce the load on both routers and collectors, traffic sampling is used. The router takes into account only every N-th packet (more precisely, packets are selected randomly from the stream, but on average the sample gives 1: N). The sampling rate can be increased, thereby reducing the number of exported flows per second and the load. You need to take into account that for example with a sampling rate of 1:1000 you will not see literally 99.9% of the traffic. The higher the rate, the less accurate the reports and the worse anomalies in traffic are visible.

Netflow processing is usually data aggregation over large periods of time, data dimensionality reduction (selection of only the required fields), visualization, detection of unwanted traffic, triggering alerts and other actions when anomalies are detected. Sometimes netflow data is used for forecasting.

There is an interesting source of practical approaches for analyzing network traffic - the old stock trading strategies. In traffic, you can quickly detect exceeding thresholds using moving averages, see cycles (daily, weekly), patterns, deviations from them, etc.

Modern open source netflow collectors usually receive flows, decode them, export them to Kafka, ClickHouse, Elastic stack, and then process and visualize with other utilities. For example:

https://github.com/robcowart/elastiflow

https://github.com/akvorado/akvorado

https://github.com/netsampler/goflow2


Not many of the old school collectors survived. Some of the most famous:

https://github.com/phaag/nfdump

https://github.com/pavel-odintsov/fastnetmon - detects thresholds exceeded using exponential moving averages


`xenoeye` is closer to the old-school collectors both in terms of its internal structure and the way it is set up.

The collector stores all configuration in text files. Text files are also generated for export to the database. The idea was not to be tied to any particular DBMS, but to generate export files for different databases, not necessarily relational ones. During the shutdown of the DBMS (in the event of an error or when the database needs maintenance), the collector does not delete the data. After restoring the DBMS functionality, you can export the accumulated data, they will not be lost.

At first, we wanted to store all the raw netflow that the collector receives. But after talking with people from large telecoms, we realized that this was pointless. It is assumed that only data that will actually be used should be exported to persistent storage. At the moment an anomaly occurs (breaking through the thresholds), more extended statistics can be taken.

In addition, it became clear that network engineers are very busy people, it is often easier to adjust the sampling rate on the collector side than to ask them to configure the options template.

We looked at several modern time-series databases, but for various reasons, we settled on vanilla PostgreSQL for now. It works quite acceptable even with mechanical hard drives, is not demanding on memory, is widely distributed and supported.

When thresholds for moving averages are exceeded, custom scripts are launched. It is assumed that the main anomaly processing logic is implemented in these scripts. Almost all networks have their own characteristics. There is no point in hardcoding these features into the collector.


### Worker and auxiliary threads

At startup, the collector reads common configs and `mo.conf` files. Worker threads and several auxiliary threads are launched:
  * A thread that exports aggregated data to files for the DBMS
  * A thread that runs scripts when moving average limits are exceeded and when traffic returns to normal
  * Thread that dumps moving averages

Worker threads received netflow and process it.


### Monitoring objects and filters

After the collector has read the `mo.conf` configuration file, it tries to compile the monitor object filter into bytecode. If it succeeds, the bytecode is stored in memory.

Each incoming flow is decoded using templates. For the flow, the filter bytecode is executed, it is checked whether this flow belongs to the monitored object.

If it does, then the necessary fields are selected from the flow and processed further - in windows of a fixed size and moving averages.


### How to add a new Netflow field to the collector

In Netflow v9 and IPFIX, few hundred fields exist and are described. Out of the box, the collector supports only the most common ones. Some types of fields can be easily added.

The collector operates with netflow fields of two types. The first type is the `IN_BYTES`, `IN_PKTS` and similar fields. These fields are considered aggregated. If they are found in the config in the array of fields for export, then the data from these fields will be summed up.

The remaining fields are considered non-aggregable.

Now this approach is used to describe netflow fields: they are specified in the code, in the files [netflow.def](netflow.def) and [filter.def](filter.def).

When compiling, the [X-Macro](https://en.wikipedia.org/wiki/X_Macro) technique is used, the list of fields turns into a list of `if () else if ()...` conditions. From a performance point of view, it is better not to add many fields to these files, but to leave only the necessary minimum.

Perhaps later we will remake the architecture and it will be possible to add an arbitrary number of fields without losing performance.

The file format is:

`netflow.def`

``` c
FIELD(internal_id,            "Description",              FIELD_TYPE,      netflow_id,  min_size,  max_size)
```

  * `internal_id` is an internal identifier, a valid name for a C struct field is expected
  * `Description` text description of the field
  * `FIELD_TYPE` field type (now `NF_FIELD_INT`(integer) and `NF_FIELD_IP_ADDR`(IP address) are supported))
  * `netflow_record_id` field identifier
  * `min_size`, `max_size` minimum and maximum field size in bytes

Field data (ID, size, etc.) can be taken from [NetFlow Version 9 Flow-Record Format - Cisco Systems](https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html) or from [IP Flow Information Export (IPFIX) Entities](http://www.iana.org/assignments/ipfix/ipfix.xhtml)

Adding a field to `netflow.def` will only change the netflow parser. To use this field in filters and for export to the DBMS, you need to add it to `filter.def`

``` c
FIELD(ID,      "name",          TYPE,  src_netflow_field,   dst_netflow_field)
```

  * `ID` internal identifier
  * `name` is a string that will be used in filters
  * `TYPE` type (now supported `RANGE`(range of integers), `ADDR4` or `ADDR6` - IP addresses)
  * `src_netflow_field`, `dst_netflow_field` netflow fields to work with. What is written in `internal_id` from `netflow.def`. If there can be "source" (`src`) and "destination" `dst` prefixes, the corresponding fields must be specified.


For aggregable fields, the `filter-ag.def` file is used:

``` c
FIELD(ID,   "name",       netflow_field,   SCALE)
```

`SCALE` is the factor by which the field value is multiplied. It is used only for one case - you can specify `bits` in the field list and the collector will export the value `in_bytes` * 8.


After changing the files, the program needs to be recompiled.


### Time source

In each flow, there may be a time when the router started and when it finished monitoring it. The collector **does not look** at this time. The flow time is considered to be the current time on the server. This slightly reduces the accuracy, but greatly simplifies the processing, especially the processing of moving averages.


### Fixed time windows

For export to the DBMS, a classic scheme with two data banks is used.

At the beginning, the first bank is active, the worker thread writes data to it.

After the export time has come, the helper thread switches banks atomically. The one that was inactive becomes active and new data begins to be written to it.

After switching, the inactive bank is re-sorted. If the parameters indicate that only the first N records are needed for export, then the first records are selected, the rest are summed up. The result is a text file that is written to disk.

The helper thread waits for the right amount of time and the process repeats.


### Moving averages

Collector uses [cumulative moving averages](https://en.wikipedia.org/wiki/Moving_average#Cumulative_average)

The value of bytes or packets in the sliding window is recalculated upon receipt of each new flow according to the formula:


$$N = N - \frac{\Delta t}{T}\cdot N + V$$


where N is the current number of bytes/packets in the sliding window

$\Delta t$ - difference between the current time and the time of the last moving average update

T - sliding window size

V - the value (number of bytes / packets) in the new incoming flow

For such moving averages, time windows of almost arbitrary length can be used. It is not necessary to store all flows for a period of time. Only two values need to be stored - the number of bytes or packets in the window and the time of the last update

But if you use very large windows and high traffic, then you can lose precision. In the collector there is a possibility to increase the precision head-on - you can use `__float128` instead of the machine `double`. To do this, you need to change the value of `MAVG_TYPE` in the file [monit-objects.h](monit-objects.h)


### IP lists

Network lists are stored as a bitwise trie. It may not be the fastest storage method, but it is quite simple and efficient. The lists can store many networks, both IPv4 and IPv6. For example, hundreds of thousands of networks of large network operators or GeoIP networks of different regions
