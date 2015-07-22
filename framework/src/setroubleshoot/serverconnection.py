import syslog
import setroubleshoot.default_encoding_utf8
import gobject
import errno as Errno
import gettext
import os
import Queue
import re
import signal
import selinux
import socket as Socket
import fcntl
import sys

from setroubleshoot.config import parse_config_setting, get_config

from setroubleshoot.rpc import RpcChannel,ConnectionState
from setroubleshoot.rpc_interfaces import SETroubleshootServerInterface
from setroubleshoot.rpc_interfaces import SETroubleshootDatabaseInterface
from setroubleshoot.util import Retry, get_error_from_socket_exception

__all__ = [
    "ServerConnectionHandler"
]

class ServerConnectionHandler(RpcChannel,
                              SETroubleshootServerInterface,
                              SETroubleshootDatabaseInterface,
                              gobject.GObject):
    __gsignals__ = {
        'alert':
        (gobject.SIGNAL_RUN_LAST, gobject.TYPE_NONE, (gobject.TYPE_PYOBJECT,)),
        'connection_state_changed': # callback(connection_state, flags, flags_added, flags_removed):
        (gobject.SIGNAL_RUN_LAST, gobject.TYPE_NONE, (gobject.TYPE_PYOBJECT, gobject.TYPE_INT, gobject.TYPE_INT, gobject.TYPE_INT)),
        'signatures_updated': 
        (gobject.SIGNAL_RUN_LAST, gobject.TYPE_NONE, (gobject.TYPE_PYOBJECT, gobject.TYPE_PYOBJECT)),
        'database_bind': 
        (gobject.SIGNAL_RUN_LAST, gobject.TYPE_NONE, (gobject.TYPE_PYOBJECT, gobject.TYPE_PYOBJECT)),
        'async-error': # callback(method, errno, strerror)
        (gobject.SIGNAL_RUN_LAST, gobject.TYPE_NONE, (gobject.TYPE_STRING, gobject.TYPE_INT, gobject.TYPE_STRING)),
        }

    def __init__(self, username):
        RpcChannel.__init__(self, channel_type = 'sealert')
        gobject.GObject.__init__(self)
        self.connection_state.connect('changed', self.on_connection_state_change)

        self.connect_rpc_interface('SEAlert', self)
        self.connect_rpc_interface('SETroubleshootDatabaseNotify', self)

        self.pkg_version = get_config('general','pkg_version')
        self.rpc_version = get_config('general','rpc_version')
        self.username = username
        self.retry_connection_if_closed = False
        self.connection_retry = Retry(self.retry_connection, self.get_connection_retry_interval, notify_interval=1.0)
        self.report_connect_failure = True
        self.database_name = 'audit_listener'

    def on_connection_state_change(self, connection_state, flags, flags_added, flags_removed):
        self.emit('connection_state_changed', connection_state, flags, flags_added, flags_removed)

        if (flags_removed & ConnectionState.OPEN) or (flags_added & (ConnectionState.HUP | ConnectionState.ERROR)):
            if self.retry_connection_if_closed and not (flags & ConnectionState.RETRY):
                self.connection_state.update(ConnectionState.RETRY)
                self.connection_retry.start()

    # Retry Behavior:
    #
    # Started when:
    # Connection lost is detected, however must not start if deliberate close is requested
    # Stopped when:
    # 1) successful open
    # 2) deliberate close

    def open(self, socket_address = None):
        if socket_address is not None:
            self.socket_address = socket_address

        if self.connection_state.flags & ConnectionState.OPEN:
            return True

        try:
            self.connection_state.update(ConnectionState.CONNECTING, ConnectionState.OPEN | ConnectionState.ERROR)

            self.socket_address.socket = Socket.socket(self.socket_address.family, self.socket_address.type)
            fcntl.fcntl(self.socket_address.socket.fileno(), fcntl.F_SETFD, fcntl.FD_CLOEXEC)
            self.socket_address.socket.connect(self.socket_address.get_py_address())
            self.io_watch_add(self.handle_client_io)
            self.connection_state.update(ConnectionState.OPEN, ConnectionState.CONNECTING | ConnectionState.RETRY)
            self.connection_retry.stop()
            self.report_connect_failure = True
            self.do_logon()
        except Socket.error as e:
            errno, strerror = get_error_from_socket_exception(e)
            if self.report_connect_failure == True:
                syslog.syslog(syslog.LOG_ERR, "attempt to open server connection failed: %s" % strerror)
                self.report_connect_failure = False
            if errno == Errno.EPIPE:
                add_flags = ConnectionState.HUP
            else:
                add_flags = ConnectionState.ERROR
            self.close_connection(add_flags, ConnectionState.CONNECTING, errno, strerror)
            return False
        return True
            
    def retry_connection(self, retry, user_data):
        if self.open(self.socket_address):
            return True
        else:
            return False
        
    def get_connection_retry_interval(self, retry, user_data):
        if retry.failed_attempts < 5:
            return 10
        else:
            return 60

    def async_error_callback(self, method, errno, strerror):
        syslog.syslog(syslog.LOG_ERR, "async_error: method=%s errno=%s: %s" % (method, errno, strerror))
        self.emit('async-error', method, errno, strerror)

    def bind(self):
        def database_bind_callback(properties):
            self.emit('database_bind', self, properties)

        async_rpc = self.database_bind(self.database_name)
        async_rpc.add_callback(database_bind_callback)
        async_rpc.add_errback(self.async_error_callback)

    def do_logon(self):

        def logon_callback(pkg_version, rpc_version):
            self.connection_state.update(ConnectionState.AUTHENTICATED)

        self.channel_name = self.username
        async_rpc = self.logon(self.channel_type, self.username, 'passwd')
        async_rpc.add_callback(logon_callback)
        async_rpc.add_errback(self.async_error_callback)

    def set_filter(self, sig, user, filter_type, data):
        async_rpc = SETroubleshootDatabaseInterface.set_filter(self, sig, user, filter_type, data)
        async_rpc.add_errback(self.async_error_callback)

    # ------

    def alert(self, siginfo):
        self.emit('alert', siginfo)

    def signatures_updated(self, type, item):
        self.emit('signatures_updated', type, item)
