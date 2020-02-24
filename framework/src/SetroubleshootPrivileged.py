#!/usr/bin/python3

# Authors: Petr Lautrbach <plautrba@redhat.com>
#
# Copyright (C) 2020 Red Hat, Inc.

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
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import dbus
import dbus.service
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib
import setroubleshoot.util
import signal

DBusGMainLoop(set_as_default=True)

class Privileged(dbus.service.Object):

    def __init__(self, timeout=10):
        self.timeout = timeout
        self.alarm(self.timeout)

        bus = dbus.SystemBus()
        bus.request_name("org.fedoraproject.SetroubleshootPrivileged")
        bus_name = dbus.service.BusName("org.fedoraproject.SetroubleshootPrivileged", bus=bus)
        dbus.service.Object.__init__(self, bus_name, "/org/fedoraproject/SetroubleshootPrivileged/object")

    def alarm(self, timeout=10):
        signal.alarm(timeout)

    @dbus.service.method("org.fedoraproject.SetroubleshootPrivileged", in_signature='s', out_signature='s')
    def get_rpm_nvr_by_scontext(self, scontext):
        signal.alarm(self.timeout)
        rpmnvr = setroubleshoot.util.get_rpm_nvr_by_scontext(scontext)
        if rpmnvr is None:
            return ""

        return rpmnvr

if __name__ == "__main__":
    privileged = Privileged()

    loop = GLib.MainLoop()
    loop.run()
