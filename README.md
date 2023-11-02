# xenoeye
Lightweight Netflow collector

[![Build Status](https://app.travis-ci.com/vmxdev/xenoeye.svg?branch=master)](https://app.travis-ci.com/vmxdev/xenoeye)

[`README.ru.md`](README.ru.md) - документация на русском

The documentation is mostly translated automatically using Google translator, so if you see something weird - feel free to let us know.

With this collector and [Netflow](https://en.wikipedia.org/wiki/NetFlow) you can

  * See the traffic of IP networks, individual IP addresses or services
  * Monitor network traffic and quickly respond to bursts
  * Monitor traffic patterns, packet distribution using different Netflow fields


## Key Features

Please read carefully: some items may not be suitable for you

  * The project is in beta state. The collector works for us, but we cannot give any guarantee that it will work for you.
  * This is not a turnkey business solution, but a collector program and several auxiliary scripts. However, with the collector you can generate almost arbitrary reports, build charts, dashboards in Grafana and run scripts when the traffic exceeds the limits.
  * We use the collector to monitor our networks. We are using Netflow v9 and IPFIX, so the collector supports them. Netflow v5 is also supported.
  * Unlike many modern collectors, we **don't use** Apache Kafka, Elastic stack or anything like that. The main processing take place inside the collector itself
  * The documentation contains examples of building simple reports. To build more complex ones, you need at least basic knowledge of SQL
  * Collector processes data in two ways: aggregates it over periods (for reports and charts), and uses moving averages to quickly respond to bursts
  * Both methods can be used individually or together. For example, if a moving average detects a threshold being exceeded, you can run a custom script and immediately enable extended statistics collection
  * Collector is not very demanding on resources. It can process data and build reports even on Orange Pi (analogous to Raspberry Pi) with 4 GB of memory
  * Collector kernel is written in C
  * The collector has only been tested under 64-bit Linux (x64 and AArch64)
  * We are using PostgreSQL as a storage for time series. The data aggregated by the selected Netflow fields is exported there. Aggregation occurs within the collector
  * Not a very large set of Netflow fields is supported out of the box, but you can add almost any field. Fields with types "integer" (various sizes) and "address" (IPv4 and IPv6) are currently supported
  * The project has a very liberal ISC license. We have no plans to make commercial or semi-commercial versions. This means that we cannot make any predictions about the future of the project. But on the other hand:
  * There are no hidden or artificial restrictions


## Performance

Users are usually interested in at least a rough performance estimate, so we made several tests: we recorded real Netflow traffic from different routers in pcap files and played them on the loopback interface using tcpreplay at different speeds.

Tests were run on i3-2120 CPU @ 3.30GHz.

Very roughly, you can rely on following numbers:

In debug mode, when the contents of each flow are printed to a file, it turned out about 100K flow per second per one CPU.

In a slightly closer to production mode, with two monitoring objects, two sliding windows - about 700K fps per single CPU.

These numbers are best read in a pessimistic mood:
  1. if you load the collector with many monitoring objects with a bunch of reports and debug printing, it can choke on 100K fps/CPU or less
  2. most likely 700K fps and more cannot be processed on one CPU

Scaling to multiple cores is described below in the documentation


## Documentation

  * [Step-by-step instructions for installing and configuring the collector](STEP-BY-STEP.md)
    * [Build and install](STEP-BY-STEP.md#build-and-install)
    * [Checking Netflow packets receiving](STEP-BY-STEP.md#checking-netflow-packets-receiving)
    * [Load-balancing across multiple CPUs](STEP-BY-STEP.md#load-balancing-across-multiple-cpus)
    * [Sampling rate](STEP-BY-STEP.md#sampling-rate)
    * [Monitoring objects](STEP-BY-STEP.md#monitoring-objects)
    * [IP lists](STEP-BY-STEP.md#ip-lists)
    * [Configure what data should be exported to the DBMS](STEP-BY-STEP.md#configure-what-data-should-be-exported-to-the-dbms)
    * [Export to DBMS](STEP-BY-STEP.md#export-to-dbms)
    * [Simple Reporting by IP Addresses](STEP-BY-STEP.md#simple-reporting-by-ip-addresses)
    * [Detect spam-bots and ssh-scanners](STEP-BY-STEP.md#detect-spam-bots-and-ssh-scanners)
    * [Plotting with gnuplot](STEP-BY-STEP.md#plotting-with-gnuplot)
    * [Plots with Python Matplotlib](STEP-BY-STEP.md#plots-with-python-matplotlib)
    * [Traffic visualization with Grafana](STEP-BY-STEP.md#traffic-visualization-with-grafana)
    * [Moving Averages](STEP-BY-STEP.md#moving-averages)
    * [Configure and set thresholds](STEP-BY-STEP.md#configure-and-set-thresholds)
    * [Scripts and their options](STEP-BY-STEP.md#scripts-and-their-options)
    * [Extended stats](STEP-BY-STEP.md#extended-stats)
    * [Anomaly alerts using Telegram-bot](STEP-BY-STEP.md#anomaly-alerts-using-telegram-bot)

  * [Additional features](EXTRA.md)
    * [GeoIP](EXTRA.md#geoip)
    * [Autonomous systems](EXTRA.md#autonomous-systems)
    * [Updating databases without restarting the collector](EXTRA.md#updating-databases-without-restarting-the-collector)
    * [xegeoq utility](EXTRA.md#xegeoq-utility)
    * [Visualizing GeoIP data and AS names with Grafana](EXTRA.md#visualizing-geoip-data-and-as-names-with-grafana)
    * [Traffic classification](EXTRA.md#traffic-classification)

  * [Full description of configuration files](CONFIG.md)
    * [Main configuration file `xenoeye.conf`](CONFIG.md#main-configuration-file-xenoeyeconf)
    * [Setting the sampling rates `devices.conf`](CONFIG.md#setting-the-sampling-rates-devicesconf)
    * [Description of the monitoring object `mo.conf`](CONFIG.md#description-of-the-monitoring-object-moconf)
    * [Files with thresholds](CONFIG.md#files-with-thresholds)
    * [IP Lists](CONFIG.md#ip-lists)

  * [Internals](INTERNALS.md)
    * [General remarks](INTERNALS.md#general-remarks)
    * [Worker and auxiliary threads](INTERNALS.md#worker-and-auxiliary-threads)
    * [Monitoring objects and filters](INTERNALS.md#monitoring-objects-and-filters)
    * [How to add a new Netflow field to the collector](INTERNALS.md#how-to-add-a-new-netflow-field-to-the-collector)
    * [Time source](INTERNALS.md#time-source)
    * [Fixed time windows](INTERNALS.md#fixed-time-windows)
    * [Moving averages](INTERNALS.md#moving-averages)
    * [IP lists](INTERNALS.md#ip-lists)
    * [GeoIP and AS databases](#geoip-and-as-databases)


## Plans for the future

Right now we don't plan to add new features. We look at stability, work results, try to fix bugs and make the code simpler and more understandable.
