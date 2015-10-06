#!/usr/bin/python3

import dbus
import dbus.service
import dbus.mainloop.glib
import gobject
import slip.dbus.service
from slip.dbus import polkit
import os
class RunFix(slip.dbus.service.Object):
    default_polkit_auth_required = "org.fedoraproject.setroubleshootfixit.write"
    def __init__ (self, *p, **k):
        super(RunFix, self).__init__(*p, **k)

    @dbus.service.method ("org.fedoraproject.SetroubleshootFixit", in_signature='ss', out_signature='s')
    def run_fix(self, local_id, analysis_id):
        import subprocess
        command = "sealert -f %s -P %s" % (local_id, analysis_id)
        return subprocess.getoutput(command)

if __name__ == "__main__":
    mainloop = gobject.MainLoop ()
    dbus.mainloop.glib.DBusGMainLoop (set_as_default=True)
    system_bus = dbus.SystemBus ()
    name = dbus.service.BusName("org.fedoraproject.SetroubleshootFixit", system_bus)
    object = RunFix(system_bus, "/org/fedoraproject/SetroubleshootFixit/object")
    slip.dbus.service.set_mainloop (mainloop)
    mainloop.run ()
