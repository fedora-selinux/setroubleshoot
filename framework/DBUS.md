# DBUS API

# org.fedoraproject.Setroubleshootd

## /org/fedoraproject/Setroubleshootd

### org.fedoraproject.SetroubleshootdIface

***

#### Methods

##### check_for_new(s: last_seen_id) -> (ii)

Returns number of all and red alerts which occurred after last_seen_id.

###### arguments

* `last_seen_id(s)`: a local_id which was last seen by a client

###### return values

* `count(i)`: number of all alerts since *last_seen_id* occurred
* `red(i)`: number of red alerts since *last_seen_id* occurred

***

##### delete_alert(s: local_id) -> b

Deletes an alert from the database.

###### arguments

* `local_id(s)`: an alert id

###### return value

* `success(b)`: True if the method was successful

***

##### get_alert(s: local_id) -> ssiasa(ssssbbi)tts

Returns an alert with summary, audit events, fix suggestions

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
 * `priority(i)`: An analysis priority. Typically the value is between 1 - 100. Higher value means that the analysis should have higher priority then other
 with lower values.
* `first_seen_date(t)`: when the alert was seen for the first time, number of microseconds since the Epoch
* `last_seen_date(t)`: when the alert was seen for the last time, number of microseconds since the Epoch
* `level(s)`: "green", "yellow" or "red"

***

##### get_all_alerts() -> a(ssi)

Returns an array of *local_id*'s, *summary*'s, and *report_count*'s of all current alerts in a
setroubleshoot database

###### return values

* array of
 * `local_id(s)`: an alert id in a setroubleshoot database
 * `summary(s)`: a brief description of an alert. E.g. `"SELinux is preventing /usr/bin/bash from
  ioctl access on the unix_stream_socket unix_stream_socket."`
 * `report_count(i)`: count of reports of this alert

***

##### get_all_alerts_ignored() -> a(ssi)

Returns an array of *local_id*'s, *summary*'s, and *report_count*'s of all alerts which a user set to be ignored by a user


###### return values

* array of
 * `local_id(s)`: an alert id in a setroubleshoot database
 * `summary(s)`: a brief description of an alert. E.g. `"SELinux is preventing /usr/bin/bash from
  ioctl access on the unix_stream_socket unix_stream_socket."`
 * `report_count(i)`: count of reports of this alert

***

##### get_all_alerts_since(t: since) -> a(ssi)

Returns array of alerts as in get_all_alerts() but only since *since* timedate

###### arguments

* `since(t)`: number of microseconds since the Epoch

###### return values

see get_all_alerts()

***

##### set_filter(s: local_id, s: filter_type) -> b

Sets a filter on an alert. The alert can be "always" filtered, "never" filtered or "after_first" filtered.

###### arguments

* `local_id(s)`: an alert id
* `filter_type(s)`: "always", "never", "after_first", see 
  https://docs.pagure.org/setroubleshoot/SETroubleShootUserFAQ.html#email-alerts

###### return value

* `success(b)`: True if the method was successful

***

#### Signals

##### alert(s: level, s: local_id)

Emitted when a new alert is stored.

###### arguments

* `level`: either *red* or *"yellow"*. *red* means a serious problem.
* `local_id(s)`: an alert id

