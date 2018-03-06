
#
# Authors: Dan Walsh <dwalsh@redhat.com>
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

import gettext
translation=gettext.translation('setroubleshoot-plugins', fallback=True)
_=translation.gettext

from setroubleshoot.Plugin import Plugin

class plugin(Plugin):
    summary = _('''SELinux is preventing $SOURCE_PATH "$ACCESS" access.''')

    problem_description = _('''

    SELinux denied access requested by $SOURCE. It is not
    expected that this access is required by $SOURCE and this access
    may signal an intrusion attempt. It is also possible that the specific
    version or configuration of the application is causing it to require
    additional access.

    ''')

    fix_description = _('''
    You can generate a local policy module to allow this
    access - see <a href="http://docs.fedoraproject.org/selinux-faq-fc5/#id2961385">FAQ</a>

    Please file a bug report.
    ''')

    def get_if_text(self, avc, args):
        if args[1] in ["process", "process2"]:
            return _('If you believe that $SOURCE_BASE_PATH should be allowed $ACCESS access on processes labeled $TARGET_TYPE by default.')
        if args[1] in ["capability", "capability2"]:
            return _('If you believe that $SOURCE_BASE_PATH should have the $ACCESS capability by default.')
        if (len(args) >= 3) and (args[2] in ["(null)", "Unknown"]):
            return _('If you believe that $SOURCE_BASE_PATH should be allowed $ACCESS access on $TARGET_CLASS labeled $TARGET_TYPE by default.')
        return _('If you believe that $SOURCE_BASE_PATH should be allowed $ACCESS access on the $TARGET_BASE_PATH $TARGET_CLASS by default.')

    then_text = _('You should report this as a bug.\nYou can generate a local policy module to allow this access.')
    do_text = _("""Allow this access for now by executing:
# ausearch -c '$SOURCE' --raw | audit2allow -M my-$MODULE_NAME
# semodule -X 300 -i my-$MODULE_NAME.pp""")

    def __init__(self):
        Plugin.__init__(self, __name__)
        self.set_priority(1)
        self.report_bug = True

    def analyze(self, avc):
        if avc.tpath:
            summary = self.summary + " on " + avc.tpath + "."
        else:
            summary = self.summary + "."

        return self.report((0, avc.tclass, avc.tpath))
