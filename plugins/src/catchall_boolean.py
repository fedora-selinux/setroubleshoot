
#
# Authors: Dan Walsh <dwalsh@redhat.com>
#
# Copyright (C) 2008 Red Hat, Inc.
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
import os
translation=gettext.translation('setroubleshoot-plugins', fallback=True)
_=translation.gettext

from setroubleshoot.util import *
from setroubleshoot.Plugin import Plugin
import seobject

class plugin(Plugin):
    summary = _('''
    SELinux is preventing $SOURCE_PATH "$ACCESS" access on $TARGET_PATH.
    ''')

    problem_description = _('''

    SELinux denied access requested by $SOURCE. The current boolean
    settings do not allow this access.  If you have not setup $SOURCE to
    require this access this may signal an intrusion attempt. If you do intend
    this access you need to change the booleans on this system to allow
    the access.
    ''')

    fix_description = _('''
    Confined processes can be configured to run requiring different access, SELinux provides booleans to allow you to turn on/off
    access as needed.

    ''')

    fix_cmd = ''

    def __init__(self):
        Plugin.__init__(self, __name__)
        self.set_priority(8)
        self.level = "yellow"

    def get_if_text(self, avc, args):
        txt=seobject.boolean_desc(args[0])
        if not isinstance(txt, unicode):
            txt=unicode(txt, encoding="utf8")
        return _("You want to %s") % (txt[0].lower() + txt[1:])

    def get_do_text(self, avc, args):
        return _("setsebool -P %s %s") % (args[0], args[1])

    def get_then_text(self, avc, args):
        text = _("You must tell SELinux about this by enabling the '%s' boolean.\n") % args[0]
        try:
            if args[2]:
                text += _("You can read '%s' man page for more details.") % args[2]
        except IndexError:
            pass

        return text

    def analyze(self, avc):
        man_page = self.check_for_man(avc.scontext.type)
        if  len(avc.bools) > 0:
            reports = []
            fix = self.fix_description
            fix_cmd = ""
            bools = avc.bools
            for b in bools:
                if not man_page:
                    man_page = self.check_for_man(b[0])
                reports.append(self.report((b[0], b[1], man_page)))

            return reports
        return None
