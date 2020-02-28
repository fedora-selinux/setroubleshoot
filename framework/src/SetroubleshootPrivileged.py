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

from gi.repository import GLib
from pydbus import SystemBus
import setroubleshoot.util
import signal

loop = GLib.MainLoop()

class Privileged(object):
    """
		<node>
			<interface name='org.fedoraproject.SetroubleshootPrivileged'>
				<method name='get_rpm_nvr_by_scontext'>
					<arg type='s' name='scontext' direction='in'/>
    				<arg type='s' name='rpmnvr' direction='out'/>
				</method>
				<method name='finish'/>
			</interface>
		</node>
    """

    def __init__(self, timeout=10):
        self.timeout = timeout
        self.alarm(self.timeout)

    def alarm(self, timeout=10):
        signal.alarm(timeout)

    def get_rpm_nvr_by_scontext(self, scontext):
        """Finds an SELinux module which defines given SELinux context"""
        signal.alarm(self.timeout)
        rpmnvr = setroubleshoot.util.get_rpm_nvr_by_scontext(scontext)
        if rpmnvr is None:
            return ""

        return rpmnvr

    def finish(self):
        loop.quit()

if __name__ == "__main__":
    bus = SystemBus()
    bus.publish("org.fedoraproject.SetroubleshootPrivileged", Privileged())
    loop.run()
