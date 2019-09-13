#
# Copyright (C) 2006-2019 Red Hat, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
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

import selinux
from stat import *
import gettext
translation=gettext.translation('setroubleshoot-plugins', fallback=True)
_=translation.gettext

from setroubleshoot.util import *
from setroubleshoot.Plugin import Plugin

class plugin(Plugin):
    summary =_('''
    SELinux is preventing $SOURCE_PATH from creating an executable memory mapping.
    ''')

    problem_description = _('''
    The $SOURCE application attempted to create an anonymous executable memory mapping,
    or a writable executable file mapping. This is a potential security problem. Most
    applications do not need this permission. The 
    <a href="http://people.redhat.com/drepper/selinux-mem.html">SELinux Memory Protection Tests</a>
    web page explains why SELinux intervened and how to work around it if needed.
    ''')

    unsafe_if_text = "If this issue occurred during normal system operation."

    unsafe_then_text = "This alert could be a serious issue and your system could be compromised."

    unsafe_do_text = "Contact your security administrator and report this issue"

    if_text = "If you know why $SOURCE needs to map a memory region that is both executable and writable and understand that this is a potential security problem."

    then_text = "You can allow the mapping by switching one of the following booleans: "

    do_text = "Follow the advice of the catchall_boolean plugin, otherwise contact your security administrator and report this issue"

    def get_problem_description(self, avc, args):
        return self.problem_description

    def get_if_text(self, avc, args):
        if len(args) > 0:
            return self.if_text
        return self.unsafe_if_text

    def get_then_text(self, avc, args):
        if len(args) > 0:
            return self.then_text + ", ".join(args)
        return self.unsafe_then_text

    def get_do_text(self, avc, args):
        if len(args) > 0:
            return self.do_text
        return self.unsafe_do_text

    def __init__(self):
        Plugin.__init__(self,__name__)
        self.fixable = False
        self.report_bug = True
        self.set_priority(10)

    def analyze(self, avc):
        import subprocess
        if avc.has_any_access_in(['execmem']):
            # MATCH
            if len(avc.bools) > 0:
                return self.report([b[0] for b in avc.bools])
            else:
                return self.report()
        return None
