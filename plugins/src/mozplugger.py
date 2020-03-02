#
# Authors: Dan Walsh <dwalsh@redhat.com>
#
# Copyright (C) 2012 Red Hat, Inc.
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

import gettext
translation=gettext.translation('setroubleshoot-plugins', fallback=True)
_=translation.gettext

from setroubleshoot.util import *
from setroubleshoot.Plugin import Plugin

class plugin(Plugin):
    summary = _('''SELinux is preventing $SOURCE_PATH "$ACCESS" access.''')

    problem_description = _('''
    SELinux denied access requested by $SOURCE. It is not expected that this access is required by $SOURCE and this access may signal an intrusion attempt. It is also possible that the specific version or configuration of the application is causing it to require additional access.  mozplugger and spice-xpi run applications within mozilla-plugins that require access to the desktop, that the mozilla_plugin lockdown will not allow, so either you need to turn off the mozilla_plugin lockdown or not use these packages.
    ''')

    fix_description = _('''
Either remove the mozplugger or spice-xpi package by executing 'yum remove mozplugger spice-xpi' or turn off enforcement of SELinux over the Firefox plugins. setsebool -P unconfined_mozilla_plugin_transition 0
    ''')
    if_text = _("If you want to use the %s package")

    def get_if_text(self, avc, args):
        return self.if_text % args[0]

    then_text = _("you must turn off SELinux controls on the Firefox plugins.")
    do_text = """# setsebool -P unconfined_mozilla_plugin_transition 0"""

    fix_cmd = "setsebool -P unconfined_mozilla_plugin_transition 0"

    def __init__(self):
        Plugin.__init__(self, __name__)
        self.set_priority(75)

    def analyze(self, avc):
        if avc.matches_source_types(['mozilla_plugin_t']):
            reports = []
            if get_package_nvr_by_name("mozplugger"):
                reports.append(self.report(("mozplugger", None)))
            if get_package_nvr_by_name("spice-xpi"):
                reports.append(self.report(("spice-xpi", None)))
            if len(reports) > 0:
                return reports
            else:
                reports.append(self.report(("plugin", None)))
                return reports

        return None
