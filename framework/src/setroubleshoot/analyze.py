# Authors: John Dennis <jdennis@redhat.com>
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

from __future__ import print_function

__all__ = ['AnalyzeThread',
           'Analyze',
           'PluginReportReceiver',
           'TestPluginReportReceiver',
           'SETroubleshootDatabase',
           'SETroubleshootDatabaseLocal',
           'LogfileAnalyzer',
          ]

import syslog
from gi.repository import GObject
import os
import time
import threading
from stat import *
import sys

from setroubleshoot.config import get_config
from setroubleshoot.avc_audit import *
from setroubleshoot.errcode import *
from setroubleshoot.rpc import *
from setroubleshoot.rpc_interfaces import *
from setroubleshoot.signature import *
from setroubleshoot.util import *
from setroubleshoot.audit_data import *
from setroubleshoot.xml_serialize import validate_database_doc

cmp = lambda x, y: (x > y) - (x < y)

#------------------------------------------------------------------------------

#------------------------------------------------------------------------------

class PluginStatistics(object):
    def __init__(self, plugin):
        self.name = plugin.analysis_id
        self.analyze_start_time = None
        self.analyze_end_time = None
        self.analyze_elapsed_time = None
        self.report_start_time = None
        self.report_end_time = None
        self.report_elapsed_time = None

    def __str__(self):
        analyze_elapsed_time = format_elapsed_time(self.analyze_elapsed_time)

        if self.report_elapsed_time is None:
            return "%s: %s elapsed" % (self.name, analyze_elapsed_time)
        else:
            total_elapsed_time = format_elapsed_time(self.report_end_time-self.analyze_start_time)
            report_elapsed_time = format_elapsed_time(self.report_elapsed_time)

            return "%s: %s elapsed, %s analyze elapsed, %s report elapsed" % \
                   (self.name, total_elapsed_time, analyze_elapsed_time, report_elapsed_time)

    def analyze_start(self):
        self.analyze_start_time = time.time()

    def analyze_end(self):
        self.analyze_end_time = time.time()
        self.analyze_elapsed_time = self.analyze_end_time - self.analyze_start_time

    def report_start(self):
        self.report_start_time = time.time()

    def report_end(self):
        self.report_end_time = time.time()
        self.report_elapsed_time = self.report_end_time - self.report_start_time

#------------------------------------------------------------------------------

class AnalyzeStatistics(object):
    def __init__(self, num_plugins):
        self.num_plugins = num_plugins
        self.cur_plugin = None
        self.called_plugins = []
        self.start_time = None
        self.end_time = None
        self.elapsed_time = None

    def __str__(self):
        elapsed_time = None
        avg_plugin_time = None
        n_called = len(self.called_plugins)
        if self.elapsed_time is not None:
            elapsed_time = format_elapsed_time(self.elapsed_time)
            if n_called:
                avg_plugin_time = format_elapsed_time(self.elapsed_time / n_called)

        return "%d/%d plugins in %s elapsed, avg plugin %s elapsed, plugins=[\n%s\n]" % \
               (n_called, self.num_plugins, elapsed_time, avg_plugin_time,
                self.called_plugins_to_string())

    def called_plugins_to_string(self):
        return '\n'.join([str(x) for x in self.called_plugins])

    def start(self):
        self.start_time = time.time()

    def end(self):
        self.end_time = time.time()
        self.elapsed_time = self.end_time - self.start_time

    def new_plugin(self, plugin):
        self.cur_plugin = PluginStatistics(plugin)
        self.called_plugins.append(self.cur_plugin)
        self.cur_plugin.analyze_start()

#------------------------------------------------------------------------------

class Analyze(object):
    def __init__(self):
        self.plugins = load_plugins()
        log_debug("Number of Plugins = %d" % len(self.plugins))

    def get_environment(self, query_environment):
        environment = SEEnvironment()
        if query_environment:
            environment.update()
        return environment

    def get_signature(self, avc, environment):
        sig = SEFaultSignature(
            host        = avc.host,
            access      = avc.access,
            scontext    = avc.scontext,
            tcontext    = avc.tcontext,
            tclass      = avc.tclass,
            tpath       = avc.tpath)
        return sig

    def analyze_avc(self, avc, report_receiver, query_environment=True):
        log_debug("analyze_avc() avc=%s" % avc)

        avc.update()

        environment = self.get_environment(avc.query_environment)

        from string import Template

        if avc.audit_event.line_numbers is not None:
            avc.audit_event.line_numbers.sort()

        siginfo = SEFaultSignatureInfo(
            audit_event    = avc.audit_event,
            source         = avc.source,
            spath          = avc.spath,
            tpath          = avc.tpath,
            src_rpm_list   = avc.src_rpms,
            tgt_rpm_list   = avc.tgt_rpms,
            scontext       = avc.scontext,
            tcontext       = avc.tcontext,
            tclass         = avc.tclass,
            port           = avc.port,
            host           = avc.host,
            sig            = self.get_signature(avc, environment),
            environment    = environment,
            line_numbers   = avc.audit_event.line_numbers,
            last_seen_date = TimeStamp(avc.audit_event.timestamp),
            local_id = report_receiver.generate_id()
            )

        for plugin in self.plugins:
            try:
                report = plugin.analyze(avc)
                if report is not None:
                    if plugin.level == "white":
                        log_debug("plugin level white, not reporting")
                        return;

                    if isinstance(report, list):
                        for r in report:
                            siginfo.plugin_list.append(r)
                    else:
                        siginfo.plugin_list.append(report)

            except Exception as e:
                print(e, file=sys.stderr)
                syslog.syslog(syslog.LOG_ERR, "Plugin Exception %s " % plugin.analysis_id)
                self.plugins.remove(plugin)

        report_receiver.report_problem(siginfo)

#------------------------------------------------------------------------------

class AnalyzeThread(Analyze, threading.Thread):
    def __init__(self,queue):
        # parent class constructors
        threading.Thread.__init__(self)
        Analyze.__init__(self)

        self.queue=queue

    def run(self):
        while True:
            try:
                avc, report_receiver = self.queue.get()
                self.analyze_avc(avc, report_receiver)
            except Exception as e:
                syslog.syslog(syslog.LOG_ERR, "Exception during AVC analysis: %s" % e)
            except ValueError as e:
                syslog.syslog(syslog.LOG_ERR, "Exception during AVC analysis: %s" % e)

#------------------------------------------------------------------------------

class PluginReportReceiver(object):
    def __init__(self, database):
        self.database = database

    def report_problem(self, siginfo):
        try:
            database_siginfo = self.database.lookup_signature(siginfo.sig)
            database_siginfo.update_merge(siginfo)
            self.database.modify_siginfo(database_siginfo)
            log_debug("signature found in database")
        except ProgramError as e:
            if e.errno == ERR_NO_SIGNATURE_MATCH:
                log_debug("not in database yet")
                siginfo.first_seen_date = siginfo.last_seen_date
                database_siginfo = self.database.add_siginfo(siginfo)
            else:
                raise

        return database_siginfo

    def generate_id(self):
        return self.database.sigs.generate_local_id()


class TestPluginReportReceiver(object):
    def __init__(self, database):
        super(TestPluginReportReceiver, self).__init__(database)

    def report_problem(self, siginfo):
        print("Analysis Result: %s" % (siginfo.sig.analysis_id))


#------------------------------------------------------------------------------

class SETroubleshootDatabase(object):
    def __init__(self, filepath, name, friendly_name=None):
        self.filepath = filepath
        self.notify = None
        self.properties = SEDatabaseProperties(name, friendly_name, self.filepath)
        self.lock = threading.Lock()
        self.file_exists = False
        self.modified_count = 0
        self.auto_save_interval = 30   # auto save after this many seconds
        self.auto_save_threshold = 200 # auto save after this many changes
        self.auto_save_timer = None
        self.max_alerts = get_config('database','max_alerts', int)
        self.max_alert_age = None
        max_alert_age = get_config('database','max_alert_age')
        if max_alert_age is not None:
            max_alert_age = max_alert_age.strip()
            if max_alert_age:
                self.max_alert_age = parse_datetime_offset(max_alert_age)

        log_debug("created new database: name=%s, friendly_name=%s, filepath=%s" % (self.properties.name, self.properties.friendly_name, self.properties.filepath))

        self.load()

    def prune(self):
        if not (self.max_alerts or self.max_alert_age): return False

        # Sort oldest to youngest by last_seen_date
        self.sigs.signature_list.sort(lambda a,b: cmp(a.last_seen_date, b.last_seen_date))

        if self.max_alert_age:
            # Find the first alert younger than the age threshold, prune everything before that
            min_time_to_survive = TimeStamp()			# current time
            min_time_to_survive -= self.max_alert_age
            keep = 0
            for siginfo in self.sigs.signature_list:
                if siginfo.last_seen_date > min_time_to_survive:
                    break
                keep += 1

            if keep > 0:
                log_debug("prune by age: max_alert_age=%s min_time_to_survive=%s" % (self.max_alert_age, min_time_to_survive.format()))
                log_debug("prune by age: pruning [%s - %s]" % (self.sigs.signature_list[0].last_seen_date.format(), self.sigs.signature_list[keep-1].last_seen_date.format()))
                log_debug("prune by age: keeping [%s - %s]" % (self.sigs.signature_list[keep].last_seen_date.format(), self.sigs.signature_list[-1].last_seen_date.format()))
                sigs = [siginfo.sig for siginfo in self.sigs.signature_list[:keep]]
                for sig in sigs:
                    self.delete_signature(sig, prune=True)

        if self.max_alerts:
            keep = len(self.sigs.signature_list) - self.max_alerts
            if keep > 0:
                sigs = [siginfo.sig for siginfo in self.sigs.signature_list[:keep]]
                log_debug("prune first %d alerts, len(sigs=%d sigs=%s" % (keep, len(sigs), sigs))
                for sig in sigs:
                    self.delete_signature(sig, prune=True)

    def set_notify(self, notify):
        self.notify = notify

    def validate(self):
        for siginfo in self.sigs.signature_list:
            # Assure first_seen_date is before last_seen_data, if not swap
            if siginfo.last_seen_date < siginfo.first_seen_date:
                tmp = siginfo.last_seen_date
                siginfo.last_seen_date = siginfo.first_seen_date
                siginfo.first_seen_date = tmp

    def load(self):
        self.sigs = SEFaultSignatureSet()

        if self.filepath is None:
            return

        if os.path.exists(self.filepath):
           stat_info = os.stat(self.filepath)
           if stat_info[ST_SIZE] > 0:
               if self.sigs.read_xml_file(self.filepath, 'sigs', validate_database_doc):
                   self.file_exists = True

        self.validate()
        self.prune()

    def save(self, prune=False):
        if self.filepath is None:
            return

        log_debug("writing database (%s) modified_count=%s" % (self.filepath, self.modified_count))

        if not prune:
            self.prune()
        self.sigs.write_xml('sigs', self.filepath)
        self.file_exists = True
        self.modified_count = 0
        if self.auto_save_timer is not None:
            GObject.source_remove(self.auto_save_timer)
            self.auto_save_timer = None

    def mark_modified(self, prune=False):
        self.modified_count += 1
        if self.filepath is None:
            return

        if self.modified_count > self.auto_save_threshold or not self.file_exists:
            self.save(prune)
        elif self.auto_save_timer is None:
            self.auto_save_timer = \
                GObject.timeout_add(self.auto_save_interval*1000,
                                    self.auto_save_callback)

    def auto_save_callback(self):
        log_debug("auto_save database (%s) modified_count=%s" % (self.filepath, self.modified_count))
        self.save()
        return False

    def remove(self):
        if self.filepath is None:
            return
        if os.path.exists(self.filepath):
            log_debug("deleting database (%s)" % self.filepath)
            os.remove(self.filepath)

    def acquire(self):
        self.lock.acquire()

    def release(self):
        self.lock.release()

    def lookup_signature(self, sig):
        siginfo = None

        matches = self.sigs.match_signatures(sig)
        log_debug("lookup_signature: found %d matches with scores %s" % (len(matches), ",".join(["%.2f" % x.score for x in matches])))
        if len(matches) == 0:
            raise ProgramError(ERR_NO_SIGNATURE_MATCH)
        if len(matches) > 1:
            log_debug("lookup_signature: found %d matches with scores %s" % (len(matches), ",".join(["%.2f" % x.score for x in matches])))
        siginfo = matches[0].siginfo
        return siginfo

    def lookup_local_id(self, local_id):
        siginfo = self.sigs.lookup_local_id(local_id)
        if siginfo is None:
            log_debug("lookup_local_id: %s not found" % local_id)
            raise ProgramError(ERR_SIGNATURE_ID_NOT_FOUND, "id (%s) not found" % local_id)
        return siginfo

    def add_siginfo(self, siginfo):
        siginfo = self.sigs.add_siginfo(siginfo)
        if self.notify:
            self.notify.signatures_updated('add', siginfo.local_id)
        self.mark_modified()
        return siginfo

    def get_properties(self):
        return self.properties

    def query_alerts(self, criteria):
        log_debug("query_alerts: criteria=%s" % criteria)

        if criteria == '*':
            return self.sigs

        # FIXME: we assume if criteria is not wildcard its a local_id, need a more general/robust mechanism
        sigs = SEFaultSignatureSet()
        siginfo = self.lookup_local_id(criteria)
        sigs.add_siginfo(siginfo)
        return sigs

    def delete_signature(self, sig, prune=False):
        log_debug("delete_signature: sig=%s" % sig)

        siginfo = self.lookup_signature(sig)
        self.sigs.remove_siginfo(siginfo)
        if self.notify:
            self.notify.signatures_updated('delete', siginfo.local_id)
        self.mark_modified(prune)

    def modify_siginfo(self, siginfo):
        if self.notify:
            self.notify.signatures_updated('modify', siginfo.local_id)
        self.mark_modified()

    def evaluate_alert_filter(self, sig, username):
        log_debug("evaluate_alert_filter: username=%s sig=%s" % (username, sig))

        siginfo = self.lookup_signature(sig)
        action = siginfo.evaluate_filter_for_user(username)
        return action

    def set_user_data(self, sig, username, item, data):
        log_debug("set_user_data: username=%s item=%s data=%s sig=\n%s" % (username, item, data, sig))

        siginfo = self.lookup_signature(sig)
        user_data = siginfo.get_user_data(username)
        user_data.update_item(item, data)
        self.modify_siginfo(siginfo)

    def set_filter(self, sig, username, filter_type, data = "" ):
        log_debug("set_filter: username=%s filter_type=%s sig=\n%s" % (username, filter_type, sig))

        siginfo = self.lookup_signature(sig)
        siginfo.update_user_filter(username, filter_type, data)
        self.modify_siginfo(siginfo)

    def add_user(self, username):
        self.user = self.sigs.users.add_user(username)
        self.mark_modified()

    def get_user(self, username):
        return self.sigs.users.get_user(username)

#------------------------------------------------------------------------------

class SETroubleshootDatabaseLocal(RpcManage,
                                  SETroubleshootDatabaseInterface,
                                  SETroubleshootDatabaseNotifyInterface,
                                  GObject.GObject):

    __gsignals__ = {
        'signatures_updated':
        (GObject.SIGNAL_RUN_LAST, GObject.TYPE_NONE, (GObject.TYPE_PYOBJECT, GObject.TYPE_PYOBJECT)),
        'async-error': # callback(method, errno, strerror)
        (GObject.SIGNAL_RUN_LAST, GObject.TYPE_NONE, (GObject.TYPE_STRING, GObject.TYPE_INT, GObject.TYPE_STRING)),
        }


    def __init__(self, database):
        GObject.GObject.__init__(self)
        RpcManage.__init__(self)
        self.database = database
        self.database.set_notify(self)

    def set_notify(self, notify):
        self.database.set_notify(notify)

    def emit_rpc(self, rpc_id, type, rpc_def, *args):
        log_debug("%s emit %s(%s) id=%s" % (self.__class__.__name__, rpc_def.method, ','.join([str(arg) for arg in args]), rpc_id))
        async_rpc = self.async_rpc_cache[rpc_id]
        func = getattr(self.database, rpc_def.method, None)
        if func is None:
            raise ProgramError(ERR_METHOD_NOT_FOUND,
                               "method %s not found in base class of %s" % (rpc_def.method, self.__class__.__name__))
        try:
            async_rpc.return_args = func(*args)
            async_rpc.return_type = 'method_return'
            if async_rpc.return_args is not None:
                async_rpc.return_args = [async_rpc.return_args]
        except ProgramError as e:
            async_rpc.return_args = [e.errno, e.strerror]
            async_rpc.return_type = 'error_return'

        if async_rpc.return_args is not None:
            GObject.idle_add(self.process_async_return, async_rpc)


    def signatures_updated(self, type, item):
        log_debug('signatures_updated() database local: type=%s item=%s' % (type, item))
        self.emit('signatures_updated', type, item)

GObject.type_register(SETroubleshootDatabaseLocal)

#------------------------------------------------------------------------------

class LogfileAnalyzer(GObject.GObject):
    __gsignals__ = {
        'progress':
        (GObject.SIGNAL_RUN_LAST, GObject.TYPE_NONE, (GObject.TYPE_FLOAT,)),
        'state-changed':
        (GObject.SIGNAL_RUN_LAST, GObject.TYPE_NONE, (GObject.TYPE_PYOBJECT,)),
        }

    def __init__(self, logfile_path=None):
        GObject.GObject.__init__(self)
        log_debug("%s.__init__(%s)" % (self.__class__.__name__, logfile_path))

        self.logfile_path = logfile_path

        self.file = None
        self.fileno = None
        self.read_size = 128

        self.record_reader = None
        self.record_receiver = None
        self.analyzer = None
        self.report_receiver = None

        self.idle_proc_id = None

        self.errno = None
        self.strerror = None

    def open(self, logfile_path=None):
        if logfile_path is not None:
            self.logfile_path = logfile_path
        log_debug('%s.open(%s)' % (self.__class__.__name__, self.logfile_path))
        try:
            stat_info = os.stat(self.logfile_path)
            self.file_size = stat_info[ST_SIZE]
            self.file = open(self.logfile_path)
            self.fileno = self.file.fileno()
        except EnvironmentError as e:
            syslog.syslog(syslog.LOG_ERR, '%s.open(): %s' % (self.__class__.__name__, e.strerror))
            self.errno = e.errno
            self.strerror = e.strerror
            raise e

        self.n_bytes_read = 0
        self.line_count = 0
        self.record_count = 0
        self.progress = 0.0
        self.cancelled = False
        self.emit('progress', self.progress)

        logfile_basename = os.path.basename(self.logfile_path)
        self.friendly_name = "file: %s" % (os.path.splitext(logfile_basename)[0])
        self.database = SETroubleshootDatabase(None, logfile_basename, friendly_name=self.friendly_name)

        self.record_reader = AuditRecordReader(AuditRecordReader.TEXT_FORMAT)
        self.record_receiver = AuditRecordReceiver()
        self.analyzer = Analyze()
        if not get_config('test', 'analyze', bool):
            self.report_receiver = PluginReportReceiver(self.database)
        else:
            self.report_receiver = TestPluginReportReceiver(self.database)

        return True

    def run(self):
        log_debug('%s.run(%s)' % (self.__class__.__name__, self.file))
        self.idle_proc_id = GObject.idle_add(self.task().next)
        return True

    def close(self):
        if self.file is not None:
            new_data = os.read(self.fileno, self.read_size)
            self.file = None
            self.fileno = None

        if self.n_bytes_read < self.file_size:
            # ok to read more (meanwhile, new messages got appended)
            import errno as Errno
            strerror = "failed to read complete file, %d bytes read out of total %d bytes (%s)" % \
                       (self.n_bytes_read, self.file_size, self.logfile_path)
            log_debug(strerror)
            self.errno = Errno.EIO
            self.strerror = strerror

        if self.record_receiver is not None:
            # All done, flush all buffered events out
            for audit_event in self.record_receiver.close():
                self.avc_event_handler(audit_event)

        if not self.cancelled:
            self.emit('progress', 1.0)

    def task(self):
        self.emit('state-changed', 'running')
        while self.fileno:
            try:
                new_data = os.read(self.fileno, self.read_size)
                if new_data == '':
                    log_debug("EOF on %s" % self.logfile_path)
                    self.close()
            except EnvironmentError as e:
                self.errno = e.errno
                self.strerror = e.strerror
                self.close()
                self.emit('state-changed', 'stopped')
                yield False
            except ValueError as e:
                print("\n", e, file=sys.stderr)

            self.n_bytes_read += len(new_data)
            if self.file_size > 0:
                self.progress = float(self.n_bytes_read) / float(self.file_size)
            self.emit('progress', self.progress)

            for (record_type, event_id, body_text, fields, line_number) in self.record_reader.feed(new_data):
                self.new_audit_record_handler(record_type, event_id, body_text, fields, line_number)
                yield True
                if self.cancelled:
                    yield False
            yield True
        self.emit('state-changed', 'stopped')
        yield False

    def avc_event_handler(self, audit_event):
        log_debug('avc_event_handler() audit_event=%s' % audit_event)
        if audit_event.is_avc() and not audit_event.is_granted() and audit_event.num_records() > 0:
            avc = AVC(audit_event)

            self.analyzer.analyze_avc(avc, self.report_receiver, False)


    def new_audit_record_handler(self, record_type, event_id, body_text, fields, line_number):
        'called to enter a new audit record'
        log_debug('new_audit_record_handler() record_type=%s event_id=%s body_text=%s' % (record_type, event_id, body_text))

        self.record_count += 1

        audit_record = AuditRecord(record_type, event_id, body_text, fields, line_number)
        for audit_event in self.record_receiver.feed(audit_record):
            try:
                self.avc_event_handler(audit_event)
            except ValueError as e:
                print(e, file=sys.stderr)


GObject.type_register(LogfileAnalyzer)

