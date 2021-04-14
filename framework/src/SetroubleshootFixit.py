#!/usr/bin/python3

import dbus
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib
import os
import signal
import subprocess

class RunFix(dbus.service.Object):
    default_polkit_auth_required = "org.fedoraproject.setroubleshootfixit.write"

    def __init__(self, *p, **k):
        super(RunFix, self).__init__(*p, **k)
        self.timeout = 10
        self.alarm(self.timeout)

    def alarm(self, timeout=10):
        signal.alarm(timeout)

    def is_authorized(self, sender):
        bus = dbus.SystemBus()

        proxy = bus.get_object('org.freedesktop.PolicyKit1', '/org/freedesktop/PolicyKit1/Authority')
        authority = dbus.Interface(proxy, dbus_interface='org.freedesktop.PolicyKit1.Authority')
        subject = ('system-bus-name', {'name' : sender})
        action_id = 'org.fedoraproject.setroubleshootfixit.write'
        details = {}
        flags = 1            # AllowUserInteraction flag
        cancellation_id = '' # No cancellation id
        result = authority.CheckAuthorization(subject, action_id, details, flags, cancellation_id)
        return result[0]

    @dbus.service.method("org.fedoraproject.SetroubleshootFixit", sender_keyword="sender", in_signature='ss', out_signature='s')
    def run_fix(self, local_id, analysis_id, sender):
        self.alarm(0)
        command = ["sealert", "-f", local_id, "-P", analysis_id]

        if self.is_authorized(sender):
            result = subprocess.check_output(command, universal_newlines=True)
        else:
            result = "Authorization failed"

        self.alarm(self.timeout)
        return result


if __name__ == "__main__":
    mainloop = GLib.MainLoop()
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    system_bus = dbus.SystemBus()
    name = dbus.service.BusName("org.fedoraproject.SetroubleshootFixit", system_bus)
    object = RunFix(system_bus, "/org/fedoraproject/SetroubleshootFixit/object")
    mainloop.run()
