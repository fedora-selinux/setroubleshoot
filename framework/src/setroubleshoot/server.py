from __future__ import absolute_import
# Authors: John Dennis <jdennis@redhat.com>
#          Thomas Liu  <tliu@redhat.com>
#          Dan Walsh <dwalsh@redhat.com>
#
# Copyright (C) 2006-2010 Red Hat, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#

__all__ = ['RunFaultServer',
           'ClientConnectionHandler',
           'get_host_database',
           'send_alert_notification',
           'ConnectionPool',
          ]


from gi.repository import GObject, GLib
import dbus
import dbus.service
import dbus.glib
import gettext
#import errno as Errno
import os
#import pwd
import signal
import atexit
#from stat import *
import sys
import syslog
import systemd.journal
#import threading
#from types import *

from setroubleshoot.config import parse_config_setting, get_config

domain = get_config('general', 'i18n_text_domain')
kwargs = {}
if sys.version_info < (3,):
    kwargs['unicode'] = True
gettext.install(domain    = domain,
                localedir = get_config('general', 'i18n_locale_dir'),
                **kwargs)

translation=gettext.translation(domain, fallback=True)

try:
    _ = translation.ugettext # This raises exception in Python3, succ. in Py2
except AttributeError:
    _ = translation.gettext # Python3


from setroubleshoot.access_control import ServerAccess
from setroubleshoot.analyze import (PluginReportReceiver,
                                    SETroubleshootDatabase,
                                    TestPluginReportReceiver,
                                    AnalyzeThread,
                                    )
from setroubleshoot.avc_audit import *
from setroubleshoot.config import get_config
if get_config('general', 'use_auparse', bool):
    from setroubleshoot.avc_auparse import *
else:
    from setroubleshoot.avc_audit import AuditRecordReceiver

from setroubleshoot.errcode import (ProgramError,
                                    ERR_NOT_AUTHENTICATED,
                                    ERR_USER_LOOKUP,
                                    ERR_USER_PROHIBITED,
                                    ERR_USER_PERMISSION,
                                    ERR_FILE_OPEN,
                                    ERR_DATABASE_NOT_FOUND,
                                    )

from setroubleshoot.rpc import (RpcChannel,
                                ConnectionState,
                                get_socket_list_from_config,
                                ListeningServer,
                                )

from setroubleshoot.rpc_interfaces import (SETroubleshootServerInterface,
                                           SETroubleshootDatabaseNotifyInterface,
                                           SEAlertInterface,
                                           )
from setroubleshoot.util import (get_hostname,
                                 make_database_filepath,
                                 assure_file_ownership_permissions,
                                 get_identity, log_debug, syslog_trace
                                 )

#------------------------------ Utility Functions -----------------------------


def sighandler(signum, frame):
    log_debug("received signal=%s" % signum)
    import setroubleshoot.config as config
    if signum == signal.SIGHUP:
        log_debug("reloading configuration file")
        config.config_init()
        return
    import sys
    sys.exit()

def make_instance_id():
    import time
    hostname = get_hostname()
    pid = os.getpid()
    stamp = str(time.time())
    return '%s:%s:%s' % (hostname, pid, stamp)

def get_host_database():
    return host_database

dbus_system_bus_name = get_config('system_dbus','bus_name')
dbus_system_object_path = get_config('system_dbus','object_path')
dbus_system_interface = get_config('system_dbus','interface')

system_bus = dbus.SystemBus()
system_bus.request_name(dbus_system_bus_name)

# FIXME: this should be part of ClientNotifier
def send_alert_notification(siginfo):
    alert=dbus.lowlevel.SignalMessage(dbus_system_object_path, dbus_system_interface, "alert");
    alert.append(siginfo.level)
    alert.append(siginfo.local_id)
    system_bus.send_message(alert)

    for client in connection_pool.clients('sealert'):
        client.alert(siginfo)

#------------------------------ Variables -------------------------------

host_database = None
analysis_queue = None
email_recipients = None
email_recipients_filepath = get_config('email', 'recipients_filepath')
pkg_version = get_config('general','pkg_version')
rpc_version = get_config('general','rpc_version')
instance_id = make_instance_id()


#-----------------------------------------------------------------------------

class ConnectionPool(object):
    def __init__(self):
        self.client_pool = {}

    def add_client(self, handler):
        if handler in self.client_pool:
            log_debug("add_client: client (%s) already in client pool" % handler)
            return
        self.client_pool[handler] = None

    def remove_client(self, handler):
        if handler not in self.client_pool:
            log_debug("remove_client: client (%s) not in client pool" % handler)
            return
        del(self.client_pool[handler])

    def clients(self, channel_type=None):
        for client in self.client_pool:
            if channel_type is None:
                yield client
            elif client.channel_type == channel_type:
                yield client

    def close_all(self, channel_type=None):
        for client in self.client_pool:
            if client.channel_type == channel_type:
                client.close_connection()

connection_pool = ConnectionPool()

#------------------------------------------------------------------------------

class AlertPluginReportReceiver(PluginReportReceiver):
    def __init__(self, database):
        super(AlertPluginReportReceiver, self).__init__(database)

    def report_problem(self, siginfo):
        siginfo = super(AlertPluginReportReceiver, self).report_problem(siginfo)

        if email_recipients is not None:
            to_addrs = []
            for recipient in email_recipients.recipient_list:
                username = "email:%s" % recipient.address
                action = siginfo.evaluate_filter_for_user(username, recipient.filter_type)
                if action != "ignore":
                    log_debug("Email: siginfo.sig=%s" % siginfo.sig)
                    to_addrs.append(recipient.address)

            if len(to_addrs):
                from setroubleshoot.email_alert import email_alert
                email_alert(siginfo, to_addrs)

        log_debug("sending alert to all clients")

        from setroubleshoot.html_util import html_to_text
        syslog.syslog(syslog.LOG_ERR, siginfo.summary() + _(" For complete SELinux messages. run sealert -l %s") % siginfo.local_id )
        for audit_record in siginfo.audit_event.records:
            if audit_record.record_type == 'AVC':
                pid = audit_record.fields["pid"]
                break;
        systemd.journal.send(siginfo.format_text(), OBJECT_PID=pid)

        for u in siginfo.users:
                action = siginfo.evaluate_filter_for_user(u.username)
                if action == "ignore":
                    return siginfo

        send_alert_notification(siginfo)
        return siginfo

#-----------------------------------------------------------------------------

class ClientConnectionHandler(RpcChannel):
    def __init__(self, socket_address):
        RpcChannel.__init__(self, 'sealert')
        self.socket_address = socket_address.copy()
        self.connection_state.connect('changed', self.on_connection_state_change)

    def on_connection_state_change(self, connection_state, flags, flags_added, flags_removed):
        log_debug("%s.on_connection_state_change: connection_state=%s flags_added=%s flags_removed=%s address=%s" % (self.__class__.__name__, connection_state, connection_state.flags_to_string(flags_added), connection_state.flags_to_string(flags_removed), self.socket_address))

        if flags_removed & ConnectionState.OPEN:
            connection_pool.remove_client(self)

        if flags_added & ConnectionState.OPEN:
            connection_pool.add_client(self)

    def open(self, socket, socket_address):
        if self.connection_state.flags & ConnectionState.OPEN:
            return True
        self.socket_address.socket = socket
        self.connection_state.update(ConnectionState.OPEN)
        self.io_watch_add(self.handle_client_io)


#-----------------------------------------------------------------------------

class SetroubleshootdClientConnectionHandler(ClientConnectionHandler,
                                             SETroubleshootServerInterface,
                                             SETroubleshootDatabaseNotifyInterface,
                                             SEAlertInterface,
                                             ):
    def __init__(self, socket_address):
        ClientConnectionHandler.__init__(self, socket_address)

        self.database = get_host_database()

        self.connect_rpc_interface('SETroubleshootServer', self)
        self.connect_rpc_interface('SETroubleshootDatabase', self)

        self.access = ServerAccess()
        self.username = None
        self.uid = None
        self.gid = None

    def on_connection_state_change(self, connection_state, flags, flags_added, flags_removed):
        log_debug("%s.on_connection_state_change: connection_state=%s flags_added=%s flags_removed=%s address=%s" % (self.__class__.__name__, connection_state, connection_state.flags_to_string(flags_added), connection_state.flags_to_string(flags_removed),self.socket_address))

        if flags_removed & ConnectionState.OPEN:
            connection_pool.remove_client(self)

        if flags_added & ConnectionState.OPEN:
            self.uid, self.gid = self.access.get_credentials(self.socket_address.socket)
            log_debug("%s.on_connection_state_change: open, socket credentials: uid=%s gid=%s" % (self.__class__.__name__, self.uid, self.gid))
            connection_pool.add_client(self)

    def open(self, socket, socket_address):
        if self.connection_state.flags & ConnectionState.OPEN:
            return True
        self.socket_address.socket = socket
        self.connection_state.update(ConnectionState.OPEN)
        self.io_watch_add(self.handle_client_io)


    # ---- SETroubleshootServerInterface Methods ----

    def database_bind(self, database_name):
        if not (self.connection_state.flags & ConnectionState.AUTHENTICATED):
            raise ProgramError(ERR_NOT_AUTHENTICATED)

        host_database = get_host_database()
        if host_database.properties.name == database_name:
            return [host_database.properties]
        raise ProgramError(ERR_DATABASE_NOT_FOUND, "database (%s) not found" % database_name)


    def logon(self, type, username, password):
        log_debug("logon(%s) type=%s username=%s" % (self, type, username))

        if username != get_identity(self.uid):
            raise ProgramError(ERR_USER_LOOKUP, detail="uid=%s does not match logon username (%s)" % (self.uid, username))

        if type == 'sealert':
            privilege = 'client'
        else:
            privilege = None

        if not self.access.user_allowed(privilege, username):
            raise ProgramError(ERR_USER_PROHIBITED)

        self.channel_type = type
        self.channel_name = username
        self.username = username
        self.user = self.database.get_user(username)
        if self.user is None:
            self.database.add_user(username)

        self.connection_state.update(ConnectionState.AUTHENTICATED)
        return [pkg_version, rpc_version]

    def query_email_recipients(self):
        if not (self.connection_state.flags & ConnectionState.AUTHENTICATED):
            raise ProgramError(ERR_NOT_AUTHENTICATED)

        return [email_recipients]

    def set_email_recipients(self, recipients):
        global email_recipients

        log_debug("set_email_recipients: %s" % recipients)

        if not (self.connection_state.flags & ConnectionState.AUTHENTICATED):
            raise ProgramError(ERR_NOT_AUTHENTICATED)

        email_recipients = recipients
        email_recipients.write_recipient_file(email_recipients_filepath)

    # ----  SETroubleshootDatabaseInterface Methods ----

    def delete_signature(self, sig):
        log_debug("delete_signature: sig=%s" % sig)

        if not (self.connection_state.flags & ConnectionState.AUTHENTICATED):
            raise ProgramError(ERR_NOT_AUTHENTICATED)

        siginfo = self.database.delete_signature(sig)
        return None

    def get_properties(self):
        log_debug("get_properties")

        if not (self.connection_state.flags & ConnectionState.AUTHENTICATED):
            raise ProgramError(ERR_NOT_AUTHENTICATED)

        properties = self.database.get_properties()
        return [properties]

    def evaluate_alert_filter(self, sig, username):
        log_debug("evaluate_alert_filter: username=%s sig=%s" % (username, sig))

        if not (self.connection_state.flags & ConnectionState.AUTHENTICATED):
            raise ProgramError(ERR_NOT_AUTHENTICATED)

        action = self.database.evaluate_alert_filter(sig, username)
        return [action]

    def lookup_local_id(self, local_id):
        log_debug("lookup_local_id: %s" % local_id)

        if not (self.connection_state.flags & ConnectionState.AUTHENTICATED):
            raise ProgramError(ERR_NOT_AUTHENTICATED)

        siginfo = self.database.lookup_local_id(local_id)
        return [siginfo]

    def query_alerts(self, criteria):
        log_debug("query_alerts: criteria=%s" % criteria)

        if not (self.connection_state.flags & ConnectionState.AUTHENTICATED):
            raise ProgramError(ERR_NOT_AUTHENTICATED)

        sigs = self.database.query_alerts(criteria)
        return [sigs]

    def set_filter(self, sig, username, filter_type, data = "" ):
        log_debug("set_filter: username=%s filter_type=%s sig=\n%s" % (username, filter_type, sig))

        if not (self.connection_state.flags & ConnectionState.AUTHENTICATED):
            raise ProgramError(ERR_NOT_AUTHENTICATED)

        if username != self.username:
            raise ProgramError(ERR_USER_PERMISSION, detail=_("The user (%s) cannot modify data for (%s)") % (self.username, username))

        self.database.set_filter(sig, username, filter_type, data)
        return None


    def set_user_data(self, sig, username, item, data):
        log_debug("set_user_data: username=%s item=%s data=%s sig=\n%s" % (username, item, data, sig))

        if not (self.connection_state.flags & ConnectionState.AUTHENTICATED):
            raise ProgramError(ERR_NOT_AUTHENTICATED)

        self.database.set_user_data(sig, username, item, data)
        return None

#------------------------------------------------------------------------------

class ClientNotifier(object):
    def __init__(self, connection_pool):
        self.connection_pool = connection_pool

    # ----  SETroubleshootDatabaseNotifyInterface Methods ----

    def signatures_updated(self, type, item):
        for client in self.connection_pool.clients('sealert'):
            client.signatures_updated(type, item)



#------------------------------------------------------------------------------
from setroubleshoot.audit_data import *
import setroubleshoot.util

class SetroubleshootdDBusObject(dbus.service.Object):
    def __init__(self, object_path, analysis_queue, alert_receiver, timeout = 10):
        dbus.service.Object.__init__(self, dbus.SystemBus(), object_path)
        self.conn_ctr=0
        self.timeout = timeout
        self.alarm(self.timeout)
        log_debug('dbus __init__ %s called' % object_path)
        self.queue = analysis_queue
        self.receiver = alert_receiver
        self.record_reader = AuditRecordReader(AuditRecordReader.TEXT_FORMAT)
        self.record_receiver = AuditRecordReceiver()

    def add(self, avc):
        try:
            # FIXME: do not hardcode /var/lib/selinux/ store_path
            policy_type = selinux.selinux_getpolicytype()[1]
            for store_path in [
                "%s%s/modules/active/disable_dontaudit" % (selinux.selinux_path(),policy_type),
                "/var/lib/selinux/%s/active/disable_dontaudit" % policy_type
            ]:
                if os.path.exists(store_path):
                    raise ValueError("Setroubleshoot can not analyze AVCs while dontaudit rules are disabled, 'semodule -B' will turn on dontaudit rules.")
            if verify_avc(avc):
                self.queue.put((avc, self.receiver))

        except ValueError as e:
            syslog.syslog(syslog.LOG_ERR, str(e))

    @dbus.service.signal(dbus_system_interface)
    def restart(self, reason):
        pass

    @dbus.service.method(dbus_system_interface)
    def start(self):
        self.alarm(0)
        self.conn_ctr += 1
        log_debug('dbus iface start() called: %d Connections' % self.conn_ctr)
        return _("Started")

    @dbus.service.method(dbus_system_interface, sender_keyword="sender", in_signature='s', out_signature='ii')
    def check_for_new(self, last_seen_id, sender):
        username = get_identity(self.connection.get_unix_user(sender))
        database = get_host_database()
        s = ""
        signatures = []
        for sig in  database.query_alerts("*").siginfos():
            action = sig.evaluate_filter_for_user(username)
            if action != "ignore":
                signatures.append(sig)

        signatures.sort(key=compare_sig)

        count = 0
        red = 0
        for sig in signatures:
            count += 1
            if sig.level == "red":
                red += 1
            if sig.local_id == last_seen_id:
                red = 0
                count = 0

        return count, red

    def _get_all_alerts_since(self, since, sender):
        username = get_identity(self.connection.get_unix_user(sender))
        database = get_host_database()
        since_alerts = setroubleshoot.util.TimeStamp(since)
        database_alerts = database.query_alerts("*").signature_list
        alerts = []
        for alert in database_alerts:
            if alert.last_seen_date < since_alerts:
                continue
            if alert.evaluate_filter_for_user(username) != "ignore":
                alerts.append((alert.local_id, alert.summary(), alert.report_count))
        return alerts

    @dbus.service.method(dbus_system_interface, sender_keyword="sender", in_signature='s', out_signature='a(ssi)')
    def get_all_alerts_since(self, since, sender):
        return self._get_all_alerts_since(since, sender)

    @dbus.service.method(dbus_system_interface, sender_keyword="sender", in_signature='', out_signature='a(ssi)')
    def get_all_alerts(self, sender):
        """
        Return array of *local_id*'s, *summary*'s, and *report_count*'s of all current alerts in a setroubleshoot database

        returns list of:
        * `local_id(s)`: a report id in a setroubleshoot database
        * `summary(s)`: a brief description of an alert. E.g. `"SELinux is preventing /usr/bin/bash from ioctl access on the unix_stream_socket unix_stream_socket."`
        * `report_count(i)`: count of reports of this alert
"""
        return self._get_all_alerts_since('1970-01-01T00:00:00Z', sender)

    @dbus.service.method(dbus_system_interface, sender_keyword="sender", in_signature='s', out_signature='ssiasa(ssssbbi)sss')
    def get_alert(self, local_id, sender):
        """
Return an alert with summary, audit events, fix suggestions

##### arguments

* `local_id(s)`: an alert id

##### return values

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
 * `priority(i)`:  An analysis priority. Typically the value is between 1 - 100.
* `first_seen_date(s)`: when the alert was seen for the first time, iso8601 format is used - '%Y-%m-%dT%H:%M:%SZ'
* `last_seen_date(s)`: when the alert was seen for the last time, iso8601 format is used - '%Y-%m-%dT%H:%M:%SZ'
* `level(s)`: "green", "yellow" or "red"
"""
        username = get_identity(self.connection.get_unix_user(sender))
        database = get_host_database()
        try:
            database_alerts = database.query_alerts(local_id)
        except ProgramError as e:
            if e.errno == ERR_SIGNATURE_ID_NOT_FOUND:
                return None
            raise e
        alert = database_alerts.siginfos().__next__()
        alert.update_derived_template_substitutions()

        avc = alert.audit_event.records
        audit_events = [event.to_text() for event in avc]

        total_priority, alert_plugins = alert.get_plugins()
        plugins = []
        for plugin, args in alert_plugins:
            plugins.append((
                _("If ") + alert.substitute(plugin.get_if_text(avc, args)),
                alert.substitute(plugin.get_then_text(avc, args)),
                alert.substitute(plugin.get_do_text(avc, args)),
                plugin.analysis_id,
                plugin.fixable,
                plugin.report_bug,
                plugin.priority)
            )


        return (alert.local_id, alert.summary(), alert.report_count,
                audit_events, plugins,
                str(alert.first_seen_date), str(alert.last_seen_date), alert.level
        )



    @dbus.service.method(dbus_system_interface, in_signature='s',  out_signature='s')
    def avc(self, data):
        data = str(data)
        self.alarm(0)
        self.conn_ctr += 1
        log_debug('dbus avc(%s) called: %d Connections' % (data, self.conn_ctr))
        for (record_type, event_id, body_text, fields, line_number) in self.record_reader.feed(str(data)):
            audit_record = AuditRecord(record_type, event_id, body_text, fields, line_number)
            audit_record.audispd_rectify()

            for audit_event in self.record_receiver.feed(audit_record):
                self.add(AVC(audit_event))

        for audit_event in self.record_receiver.flush(0):
            try:
                self.add(AVC(audit_event))
            except ValueError as e:
                syslog.syslog(syslog.LOG_ERR, "Unable to add audit event: %s" % e)

        self.conn_ctr -= 1
        self.alarm(self.timeout)
        return _("AVC")

    @dbus.service.method(dbus_system_interface)
    def finish(self):
        self.conn_ctr -= 1
        log_debug('dbus iface finish() called: %d Connections' % self.conn_ctr)
        self.alarm(self.timeout)
        return ""

    def alarm(self, timeout = 10):
        if self.conn_ctr == 0:
            signal.alarm(timeout)

def compare_sig(a):
    return a.last_seen_date

class SetroubleshootdDBus:
    def __init__(self, analysis_queue, alert_receiver, timeout):
        try:
            log_debug("creating system dbus: bus_name=%s object_path=%s interface=%s" % (dbus_system_bus_name, dbus_system_object_path, dbus_system_interface))
            self.dbus_obj = SetroubleshootdDBusObject(dbus_system_object_path, analysis_queue, alert_receiver, timeout)
        except Exception as e:
            syslog.syslog(syslog.LOG_ERR, "cannot start system DBus service: %s" % e)
            raise e

    def do_restart(self):
        self.dbus_obj.restart("daemon request")
        return True

#------------------------------------------------------------------------------
import selinux
import selinux.audit2why as audit2why

def goodbye(database):
    database.save()
    audit2why.finish()

def RunFaultServer(timeout=10):
    # FIXME
    audit2why.init()
    global host_database, analysis_queue, email_recipients

    signal.signal(signal.SIGHUP, sighandler)
    signal.signal(signal.SIGQUIT, sighandler)
    signal.signal(signal.SIGTERM, sighandler)
    signal.signal(signal.SIGALRM, sighandler)

    #interface_registry.dump_interfaces()

    try:
        # FIXME: should this be using our logging objects in log.py?
        # currently syslog is only used for putting an alert into
        # the syslog with it's id

        pkg_name = get_config('general','pkg_name')
        syslog.openlog(pkg_name)

        # Create an object responsible for sending notifications to clients
        client_notifier = ClientNotifier(connection_pool)

        # Create a database local to this host

        database_filename = get_config('database','filename')
        database_filepath = make_database_filepath(database_filename)
        assure_file_ownership_permissions(database_filepath, 0o600, 'setroubleshoot')
        host_database = SETroubleshootDatabase(database_filepath, database_filename,
                                               friendly_name=_("Audit Listener"))
        host_database.set_notify(client_notifier)

        atexit.register(goodbye, host_database)

        deleted = False
        for i in host_database.sigs.signature_list:
            why, bools = audit2why.analyze(str(i.sig.scontext), str(i.sig.tcontext), str(i.sig.tclass), i.sig.access)
            if why == audit2why.ALLOW or why == audit2why.DONTAUDIT:
                if why == audit2why.ALLOW:
                    reason = "allowed"
                else:
                    reason = "dontaudit'd"
                syslog.syslog(syslog.LOG_ERR, "Deleting alert %s, it is %s in current policy" % (i.local_id, reason) )
                deleted = True
                host_database.delete_signature(i.sig)
        if deleted:
            host_database.save(prune=True)
        # Attach the local database to an object which will send alerts
        # specific to this host

        if not get_config('test', 'analyze', bool):
            alert_receiver = AlertPluginReportReceiver(host_database)
        else:
            alert_receiver = TestPluginReportReceiver(host_database)

        # Create a synchronized queue for analysis requests
        import six.moves.queue
        analysis_queue = six.moves.queue.Queue(0)

        # Create a thread to peform analysis, it takes AVC objects off
        # the analysis queue and runs the plugins against the
        # AVC. Analysis requests in the queue may arrive from a
        # variety of places; from the audit system, from a log file
        # scan, etc. The disposition of the analysis (e.g. where the
        # results of the analysis are to go) are included in the queued
        # object along with the data to analyze.

        analyze_thread = AnalyzeThread(analysis_queue)
        analyze_thread.setDaemon(True)
        analyze_thread.start()

        # Create a thread to receive messages from the audit system.
        # This is a time sensitive operation, the primary job of this
        # thread is to receive the audit message as quickly as
        # possible and return to listening on the audit socket. When
        # it receives a complete audit event it places it in the
        # analysis queue where another thread will process it
        # independently.

#        audit_socket_thread = AuditSocketReceiverThread(analysis_queue, alert_receiver)
#        audit_socket_thread.setDaemon(True)
#        audit_socket_thread.start()

        # Initialize the email recipient list
        from setroubleshoot.signature import SEEmailRecipientSet
        email_recipients = SEEmailRecipientSet()
        assure_file_ownership_permissions(email_recipients_filepath, 0o600, 'setroubleshoot')
        try:
            email_recipients.parse_recipient_file(email_recipients_filepath)
        except ProgramError as e:
            if e.errno == ERR_FILE_OPEN:
                log_debug(e.strerror)
            else:
                raise e

        # Create a server to listen for alert clients and then run.
        listen_addresses = get_socket_list_from_config('listen_for_client')
        for listen_address in listen_addresses:
            listening_server = ListeningServer(listen_address, SetroubleshootdClientConnectionHandler)
            listening_server.open()

        dbus.glib.init_threads()
        setroubleshootd_dbus = SetroubleshootdDBus(analysis_queue, alert_receiver, timeout)
        main_loop = GLib.MainLoop()
        main_loop.run()

    except KeyboardInterrupt as e:
        log_debug("KeyboardInterrupt in RunFaultServer")

    except SystemExit as e:
        log_debug("raising SystemExit in RunFaultServer")

    except Exception as e:
        import traceback
        syslog_trace(traceback.format_exc())
        syslog.syslog(syslog.LOG_ERR, "exception %s: %s" % (e.__class__.__name__, str(e)))

if __name__=='__main__':
    RunFaultServer()
