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
$ /configure --sysconfdir=/etc/xenoeye --localstatedir=/var/lib
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

[...]
