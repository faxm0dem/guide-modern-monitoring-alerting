## Configuration

Here you find the configuration snippets used in the article [syslog-ng, riemann, collectd-notifications, elasticsearch: putting it all together](https://devops.com/2014/09/02/guide-modern-monitoring-alerting/).

### collectd

The following part ensures that `/tmp` is being polled, and that the disk utilization is reported as a percentage:

```xml
<LoadPlugin df>
  Interval 10
</LoadPlugin>
<Plugin df>
  MountPoint "/tmp"
  IgnoreSelected false
  ValuesPercentage true
</Plugin>
```

The next section triggers notifications when the free space of all monitored filesystems goes below 5 and 2 percent, for *warning* and *critical* severities, respectively:

```xml
LoadPlugin threshold
<Plugin threshold>
  <Type "percent_bytes">
    Instance free
    WarningMin 5
    FailureMin 2
  </Type>
</Plugin>
```

Last but not least, this snippet makes sure the `syslog` plugin receives all *notifications* and sends them over to the local syslog implementation:

```xml
LoadPlugin syslog
<Plugin syslog>
  LogLevel info
  NotifyLevel OKAY
</Plugin>
```

### local (any)syslog

This step can be skipped in case you run the log analyzer on the local system.
If you want to forward the local syslog messages to a remote analyzer, this is how to do it. Most systems will ship with some kind of syslog daemon, most likely the original *syslog* or *rsyslog*. As your mileage may vary, we'll present two examples: using the legacy syslog configuration file format (*for example*, using *rsyslog*), or *syslog-ng*.

#### rsyslog/syslog

    *.* @loghost.mydomain.gtld

#### syslog-ng

``` C
source s_local { ... }
destination d_remote {
  network("syslog-ng.mydomain.gtld"
    transport(udp)
    port(514)
    flags(syslog-protocol)
  );
};
log { source(s_local) destination(d_remote) }
```

### remote syslog-ng

Here we present the configuration snippets on the remote *syslog-ng* server, that will make sure our *collectd notifications* are parsed and structured correctly.
We'll give some more details here, as it's both the most important part of our setup, and also the most complex.

#### Network source

This `syslog-ng.conf` section will make sure the remote events are being collected (assuming that your clients send the logs via UDP):

``` C
source s_remote {
	network( transport(udp) port(514) flags(syslog-protocol));
};
```
#### Patterndb

This defines a *patterndb* parser in `syslog-ng.conf`:

``` C
parser p_patterndb {
	db_parser( file("/var/lib/syslog-ng/patterndb.xml") )
};
```

The parser itself is controlled by `patterndb.xml` which contains the *rules* that match the *collectd notification* events:

```xml
<patterndb version='4' pub_date='2013-08-19'>
  <ruleset name='collectd_ruleset' id='ee3bf7e1-4889-4bb0-ae73-8c2ceea629ff'>
    <patterns>
      <pattern>collectd</pattern>
    </patterns>
    <rules>
      <rule provider="syslog-ng-superfan" id='16c80b55-5401-45c7-88ff-06c0dec034ef'
            class='application'
            context-id="collectd-$(sha1 --length 12 ${collectd.hostname} ${collectd.plugin} ${collectd.plugin_instance} ${collectd.type} ${collectd.type_instance})"
            context-scope="global">
        <patterns>
          <pattern>Notification: severity = @ESTRING:collectd.severity:,@ host = @HOSTNAME:collectd.hostname@, plugin = @ESTRING:collectd.plugin:,@ plugin_instance = @ESTRING:collectd.plugin_instance:,@ type = @ESTRING:collectd.type:,@ type_instance = @ESTRING:collectd.type_instance:,@ message = @ESTRING:::@ Data source @QSTRING:collectd.ds:"@ is currently @FLOAT:collectd.metric@. That is @ESTRING:collectd.thresh_type: @the @ESTRING:: @threshold of @FLOAT:collectd.thresh_value@.</pattern>
          <pattern>Notification: severity = @ESTRING:collectd.severity:,@ host = @HOSTNAME:collectd.hostname@, plugin = @ESTRING:collectd.plugin:,@ type = @ESTRING:collectd.type:,@ type_instance = @ESTRING:collectd.type_instance:,@ message = @ESTRING:::@ Data source @QSTRING:collectd.ds:"@ is currently @FLOAT:collectd.metric@. That is @ESTRING:collectd.thresh_type: @the @ESTRING:: @threshold of @FLOAT:collectd.thresh_value@.</pattern>
          <pattern>Notification: severity = @ESTRING:collectd.severity:,@ host = @HOSTNAME:collectd.hostname@, plugin = @ESTRING:collectd.plugin:,@ plugin_instance = @ESTRING:collectd.plugin_instance:,@ type = @ESTRING:collectd.type:,@ message = @ESTRING:::@ Data source @QSTRING:collectd.ds:"@ is currently @FLOAT:collectd.metric@. That is @ESTRING:collectd.thresh_type: @the @ESTRING:: @threshold of @FLOAT:collectd.thresh_value@.</pattern>
          <pattern>Notification: severity = @ESTRING:collectd.severity:,@ host = @HOSTNAME:collectd.hostname@, plugin = @ESTRING:collectd.plugin:,@ type = @ESTRING:collectd.type:,@ message = @ESTRING:::@ Data source @QSTRING:collectd.ds:"@ is currently @FLOAT:collectd.metric@. That is @ESTRING:collectd.thresh_type: @the @ESTRING:: @threshold of @FLOAT:collectd.thresh_value@.</pattern>
        </patterns>
        <tags>
            <tag>syslog</tag>
            <tag>collectd</tag>
        </tags>
      </rule>
    </rules>
  </ruleset>
</patterndb>
```

While this may seem a bit complex, it's mainly due to the *XML* overhead. If you are using *puppet* to manage your configuration, you could use the [ccin2p3-patterndb](https://github.com/ccin2p3/puppet-patterndb) module which will generate it for you. Some notes on this *ruleset*:

 * The `context-id` makes sure all events related to the same *collectd* metric will end up in the same *correlation context*, *for example*, for comprehensive lookup later in *Elasticsearch*.
 * The `context-scope` is set to `global`, which means all events will be in the same *correlation context* regardless of the host sending the *notification*. This is useful as many different hosts might send identical events: the *collectd* client itself, the remote *collectd* aggregator, *etc.*
 * There are four very similar patterns, because *collectd* emits slightly different messages depending on the *plugin*, as *plugin-instance* and *type-instance* are optional.
 * All messages matching the *rule* will get enriched with the tags `syslog` and `collectd`, which will be used later for *routing*.
 * This *ruleset* covers the *WARNING* and *FAILURE* *collectd notifications*. There is the equivalent for *OKAY* *notifications* in the config tarball at the end of this post.

#### Riemann destination

The following `syslog-ng.conf` section reformats the data for the *riemann* server.

``` C
destination d_riemann {
    riemann(
        server("riemann.mydomain.gtld")
        port(5555)
        type("udp")
        ttl("300")
        metric("${collectd.metric}")
        description("$MESSAGE")
        host("${collectd.hostname}")
        state("$(if (\"${collectd.severity}\" == \"FAILURE\") \"critical\" $(if (\"${collectd.severity}\" == \"WARNING\") \"warning\" \"ok\"))")
        tags("syslog", "collectd" )
        service("${collectd.plugin}$(if (\"${collectd.plugin_instance}\" == \"\") \"\" \"-${collectd.plugin_instance}\")/${collectd.type}$(if (\"${collectd.type_instance}\" == \"\") \"\" \"-${collectd.type_instance}\")")
        attributes(
          pair("type", "${collectd.type}")
          pair("type_instance", "${collectd.type_instance}")
          pair("plugin", "${collectd.plugin}")
          pair("plugin_instance", "${collectd.plugin_instance}")
        )
    );
};
```
A few notes:

 * `metric("${collectd.metric}")` makes sure the current measurement of the *collectd value* in the *notification* is the *metric* of the *riemann* event. The actual name of the variable comes from the *patterndb* parser's *rule* definition: `@FLOAT:collectd.metric@`
 * The *riemann* event's *state* is generated according to the *collectd notification severity* field.
 * The *collectd* fully qualified plugin name is reconstructed and set as the *riemann service* (*for example*, `df-tmp/percent_bytes-free`). This is useful if used together with the `collectd-write_riemann` plugin, which uses the same *service* name.
 * The *collectd* *plugin*'s details are added as *riemann attributes*
 * The full unstructured message is copied to the *riemann* event's *description* field.

#### Elasticsearch destination

The following `syslog-ng.conf` snippet configures the *Elasticsearch* destination. This destination is available in the *syslog-ng-incubator* package in the form of a *lua* script. Your mileage may vary: ours does, as we are using a *perl* implementation instead (home grown module using *Search::Elasticsearch* from *cpan*).

``` C
destination d_elasticsearch {
  elasticsearch(
    host("es_cluster.mydomain.gtld")
    port("9200")
    index("collectd-$YEAR.$MONTH.$DAY")
    type("collectd_notification")
  );
};
```
Note that this will create daily indices in *Elasticsearch*.

#### Routing

Now that we have all the pieces of the puzzle, let's connect them using *syslog-ng* *log statements*:

``` C
filter f_collectd_notifications {
	tags("collectd", "syslog")
};
log {
  source(s_remote);
  parser(p_patterndb);
  log {
    filter(f_collectd_notifications);
    destination(d_riemann);
    destination(d_elasticsearch);
  };
  log {
    destination(d_messages);
  };
};
```
The latter will send all messages tagged with `syslog` and `collectd` to *riemann* and *elasticsearch*. Moreover, it will send all messages regardless of their tags to the destination `d_messages`. These tags have been added using the *patterndb*. You can add as many *log statements* you want e.g. to route only *notifications* with *critical* severities to *Nagios* using for instance a *pipe* destination which would be consumed by a *nsca* script.

## Configuration files

[tarball](https://www.balabit.com/support/documentation/pdf/syslog-ng-riemann-elasticsearch.tgz)

Here's a transcript from a shell session working on these configuration files:

```shell
#
# installation
#

$ yum install collectd riemann elasticsearch syslog-ng syslog-ng-incubator lua-socket
[...]
Installed:
  elasticsearch.noarch 0:1.1.1-1            riemann.noarch 0:0.2.5-1            syslog-ng.x86_64 0:3.5.4.1-1.el6            syslog-ng-incubator.x86_64 0:0.3.1-0
  lua-socket.x86_64 0:2.0.2-4.el6

Dependency Installed:
  GeoIP.x86_64 0:1.4.8-1.el6      daemonize.x86_64 0:1.7.3-1.el6        eventlog.x86_64 0:0.2.13-1.el6     ivykis.x86_64 0:0.36.2-1.el6     json-c.x86_64 0:0.10-2.el6
  libnet.x86_64 0:1.1.6-7.el6     riemann-c-client.x86_64 0:1.1.1-0

#
# configuration
#

# after copying the config to /tmp
$ cp /tmp/config/etc/elasticsearch/elasticsearch.yml /etc/elasticsearch/
$ cp /tmp/config/etc/riemann/riemann.config /etc/riemann/
$ cp -r /tmp/config/etc/syslog-ng /etc/
$ update-patterndb
$ cp -r /tmp/config/usr/share/syslog-ng/include/scl/elasticsearch /usr/share/syslog-ng/include/scl/
$ cp /tmp/config/etc/collectd.conf /etc/

#
# starting services
#

$ service rsyslog stop
$ service syslog-ng start
$ service elasticsearch start
$ service riemann start
$ service collectd restart

#
# demo
#

$ dd if=/dev/zero of=/tmp/full bs=1M
dd: writing `/tmp/full': No space left on device
473+0 records in
472+0 records out
495230976 bytes (495 MB) copied, 98.726 s, 5.0 MB/s

$ grep Notification /var/log/messages
Jun 20 15:08:23 localhost.local collectd[2395]: Notification: severity = FAILURE, host = localhost.local, plugin = df, plugin_instance = tmp, type = percent_bytes, type_instance = free, message = Host localhost.local, plugin df (instance tmp) type percent_bytes (instance free): Data source "value" is currently 0.000000. That is below the failure threshold of 2.000000.

$ riemann-client query 'tagged "collectd"'
Event #0:
  time  = 1403269707 - Fri Jun 20 15:08:27 2014
  state = critical
  service = df-tmp/percent_bytes-free
  host = localhost.local
  description = Notification: severity = FAILURE, host = localhost.local, plugin = df, plugin_instance = tmp, type = percent_bytes, type_instance = free, message = Host localhost.local, plugin df (instance tmp) type percent_bytes (instance free): Data source "value" is currently 0.000000. That is below the failure threshold of 2.000000.
  ttl = 300.000000
  metric_sint64 = 0
  metric_d = 0.000000
  metric_f = 0.000000
  tags = [ syslog collectd ]
  attributes = {
    type = percent_bytes
    plugin_instance = tmp
    type_instance = free
    plugin = df
  }

$ curl 0:9200/collectd-2014.06.20/_search\?pretty
{
  "took" : 41,
  "timed_out" : false,
  "_shards" : {
    "total" : 4,
    "successful" : 4,
    "failed" : 0
  },
  "hits" : {
    "total" : 1,
    "max_score" : 1.0,
    "hits" : [ {
      "_index" : "collectd-2014.06.20",
      "_type" : "message",
      "_id" : "Cq6Yg81cQii_1tSRXw4rEQ",
      "_score" : 1.0, "_source" : {"collectd":{"type_instance":"free","type":"percent_bytes","thresh_value":"2.000000","thresh_type":"below","severity":"FAILURE","plugin_instance":"tmp","plugin":"df","metric":"0.000000","hostname":"localhost.local","ds":"value"},"PROGRAM":"collectd","PID":"2395","MESSAGE":"Notification: severity = FAILURE, host = localhost.local, plugin = df, plugin_instance = tmp, type = percent_bytes, type_instance = free, message = Host localhost.local, plugin df (instance tmp) type percent_bytes (instance free): Data source \"value\" is currently 0.000000. That is below the failure threshold of 2.000000.","LEGACY_MSGHDR":"collectd[2395]: ","HOST_FROM":"localhost","HOST":"localhost","@timestamp":"2014-06-20T15:08:23+02:00","@message":"Notification: severity = FAILURE, host = localhost.local, plugin = df, plugin_instance = tmp, type = percent_bytes, type_instance = free, message = Host localhost.local, plugin df (instance tmp) type percent_bytes (instance free): Data source \"value\" is currently 0.000000. That is below the failure threshold of 2.000000."}
    } ]
  }
}

$ rm /tmp/full
$ grep Notification /var/log/messages
Jun 20 15:08:23 localhost collectd[2395]: Notification: severity = FAILURE, host = localhost.local, plugin = df, plugin_instance = tmp, type = percent_bytes, type_instance = free, message = Host localhost.local, plugin df (instance tmp) type percent_bytes (instance free): Data source "value" is currently 0.000000. That is below the failure threshold of 2.000000.
Jun 20 15:14:33 localhost collectd[2395]: Notification: severity = OKAY, host = localhost.local, plugin = df, plugin_instance = tmp, type = percent_bytes, type_instance = free, message = Host localhost.local, plugin df (instance tmp) type percent_bytes (instance free): All data sources are within range again.

$ riemann-client query 'tagged "collectd"'
Event #0:
  time  = 1403270073 - Fri Jun 20 15:14:33 2014
  state = ok
  service = df-tmp/percent_bytes-free
  host = localhost.local
  description = Notification: severity = OKAY, host = localhost.local, plugin = df, plugin_instance = tmp, type = percent_bytes, type_instance = free, message = Host localhost.local, plugin df (instance tmp) type percent_bytes (instance free): All data sources are within range again.
  ttl = 300.000000
  metric_sint64 = 0
  metric_d = 0.000000
  metric_f = 0.000000
  tags = [ syslog collectd ]
  attributes = {
    type = percent_bytes
    plugin_instance = tmp
    type_instance = free
    plugin = df
  }

$ curl 0:9200/collectd-2014.06.20/_search\?pretty
{
  "took" : 1,
  "timed_out" : false,
  "_shards" : {
    "total" : 4,
    "successful" : 4,
    "failed" : 0
  },
  "hits" : {
    "total" : 2,
    "max_score" : 1.0,
    "hits" : [ {
      "_index" : "collectd-2014.06.20",
      "_type" : "message",
      "_id" : "Cq6Yg81cQii_1tSRXw4rEQ",
      "_score" : 1.0, "_source" : {"collectd":{"type_instance":"free","type":"percent_bytes","thresh_value":"2.000000","thresh_type":"below","severity":"FAILURE","plugin_instance":"tmp","plugin":"df","metric":"0.000000","hostname":"localhost.local","ds":"value"},"PROGRAM":"collectd","PID":"2395","MESSAGE":"Notification: severity = FAILURE, host = localhost.local, plugin = df, plugin_instance = tmp, type = percent_bytes, type_instance = free, message = Host localhost.local, plugin df (instance tmp) type percent_bytes (instance free): Data source \"value\" is currently 0.000000. That is below the failure threshold of 2.000000.","LEGACY_MSGHDR":"collectd[2395]: ","HOST_FROM":"localhost","HOST":"localhost","@timestamp":"2014-06-20T15:08:23+02:00","@message":"Notification: severity = FAILURE, host = localhost.local, plugin = df, plugin_instance = tmp, type = percent_bytes, type_instance = free, message = Host localhost.local, plugin df (instance tmp) type percent_bytes (instance free): Data source \"value\" is currently 0.000000. That is below the failure threshold of 2.000000."}
    }, {
      "_index" : "collectd-2014.06.20",
      "_type" : "message",
      "_id" : "73mKTbvnTdGLleXlbg1FBw",
      "_score" : 1.0, "_source" : {"collectd":{"type_instance":"free","type":"percent_bytes","plugin_instance":"tmp","plugin":"df","hostname":"localhost.local"},"PROGRAM":"collectd","PID":"2395","MESSAGE":"Notification: severity = OKAY, host = localhost.local, plugin = df, plugin_instance = tmp, type = percent_bytes, type_instance = free, message = Host localhost.local, plugin df (instance tmp) type percent_bytes (instance free): All data sources are within range again.","LEGACY_MSGHDR":"collectd[2395]: ","HOST_FROM":"localhost","HOST":"localhost","@timestamp":"2014-06-20T15:14:33+02:00","@message":"Notification: severity = OKAY, host = localhost.local, plugin = df, plugin_instance = tmp, type = percent_bytes, type_instance = free, message = Host localhost.local, plugin df (instance tmp) type percent_bytes (instance free): All data sources are within range again."}
    } ]
  }
}
```
