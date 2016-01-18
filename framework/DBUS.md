# DBUS API

# org.fedoraproject.Setroubleshootd

## /org/fedoraproject/Setroubleshootd

### org.fedoraproject.SetroubleshootdIface

#### Methods

##### check_for_new(s: last_seen_id) -> (ii)

Return number of all and red alerts which occurred after last_seen_id.

###### arguments

* `last_seen_id(s)`: a local_id which was last seen by a client

###### return values

* `count(i)`: number of all alerts since *last_seen_id* occurred
* `red(i)`: number of red alerts since *last_seen_id* occurred

***

##### get_all_alerts() → a(ssi)

Return array of *local_id*'s, *summary*'s, and *report_count*'s of all current alerts in a
setroubleshoot database

###### return values

* array of
 * `local_id(s)`: an alert id in a setroubleshoot database
 * `summary(s)`: a brief description of an alert. E.g. `"SELinux is preventing /usr/bin/bash from
  ioctl access on the unix_stream_socket unix_stream_socket."`
 * `report_count(i)`: count of reports of this alert

***

##### get_all_alerts_since(s: since) → a(ssi)

Return array of alerts as in get_all_alerts() but only since *since* timedate

###### arguments

* `since(s)`: timedate since alerts should be returned

###### return values

see get_all_alerts()

***

##### get_alert(s: local_id) -> ssiasa(ssssbb)

Return an alert with summary, audit events, fix suggestions

###### arguments

* `local_id(s)`: an alert id

###### return values

* `local_id(s)`: an alert id
* `summary(s)`: a brief description of an alert. E.g. `"SELinux is preventing /usr/bin/bash from
  ioctl access on the unix_stream_socket unix_stream_socket."`
* `report_count(i)`: count of reports of this alert
* `audit_event(as)`: an array of audit events (AVC, SYSCALL) connected to the alert
* `plugin_analysis(a(ssssbb)`: an array of plugin analysis structure
 * `if_text(s)`:
 * `then_text(s)`
 * `do_text(s)`
 * `analysis_id(s)`: plugin id. It can be used in `org.fedoraproject.SetroubleshootFixit.run_fix()`
 * `fixable(b)`: True when an alert is fixable by a plugin
 * `report_bug(b)`: True when an alert should be reported to bugzilla

#### Signals

##### alert(s: level, s: local_id)

Emitted when a new alert is stored.

###### arguments

* `level`: either *red* or *"yellow"*. *red* means a serious problem.
* `local_id(s)`: an alert id

