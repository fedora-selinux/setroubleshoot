# @author Miroslav Grepl<mgrepl@redhat.com>
#
# Copyright (C) 2010 Red Hat, Inc.
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
    summary =_('''
    SELinux is preventing $SOURCE_PATH the "sys_resource" capability.
    ''')

    problem_description = _('''
    Confined domains should not require "sys_resource". This usually means that     your system is running out some system resource like disk space, memory, quota etc. Please clear up the disk and this
    AVC message should go away. If this AVC continues after you clear up the disk space, please report this as a bug.
    ''')

    fix_description = "Fix the cause of the SYS_RESOURCE on your system."

    if_text = _("If you do not want processes to require capabilities to use up all the system resources on your system;")
    then_text = _("""you need to diagnose why your system is running out of system resources and fix the problem.

According to /usr/include/linux/capability.h, sys_resource is required to:

/* Override resource limits. Set resource limits. */
/* Override quota limits. */
/* Override reserved space on ext2 filesystem */
/* Modify data journaling mode on ext3 filesystem (uses journaling
   resources) */
/* NOTE: ext2 honors fsuid when checking for resource overrides, so
   you can override using fsuid too */
/* Override size restrictions on IPC message queues */
/* Allow more than 64hz interrupts from the real-time clock */
/* Override max number of consoles on console allocation */
/* Override max number of keymaps */
""")
    do_text = "Fix the cause of the SYS_RESOURCE on your system."

    def __init__(self):
        Plugin.__init__(self, __name__)
        self.level="green"

    def analyze(self, avc):
        if avc.has_any_access_in(['sys_resource']):
            # MATCH
            return self.report()
        return None
