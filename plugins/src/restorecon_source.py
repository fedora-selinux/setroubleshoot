#
# Authors: Dan Walsh <dwalsh@redhat.com>
#
# Copyright (C) 2013 Red Hat, Inc.
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
import os
from stat import *
import selinux

import selinux
class plugin(Plugin):
    summary = _('''
    SELinux is preventing $SOURCE_PATH "$ACCESS" access to $TARGET_PATH.
    ''')

    fix_cmd = "/sbin/restorecon $SOURCE_PATH"

    fix_description = _('''
    You can restore the default system context to this file by executing the
    restorecon command.  restorecon '$SOURCE_PATH'.
    ''')

    def get_problem_description(self, avc, args):
        return _('''
    SELinux denied access requested by $SOURCE. $SOURCE_PATH may
    be mislabeled.  $SOURCE_PATH default SELinux type is
    <B>%s</B>, but its current type is <B>$SOURCE_TYPE</B>. Changing
    this file back to the default type may fix your problem.
    <p>
    This file could have been mislabeled either by user error, or if an normally confined application
    was run under the wrong domain.
    <p>
    However, this might also indicate a bug in SELinux because the file should not have been labeled
    with this type.
    <p>
    If you believe this is a bug, please file a bug report against this package.
    ''') % args[1]

    if_text = _("If you want to fix the label. \n$SOURCE_PATH default label should be %s.")

    def get_if_text(self, avc, args):
        return self.if_text % args[1]

    then_text = _('you can run restorecon.')
    do_text = '# /sbin/restorecon -v $SOURCE_PATH'

    def __init__(self):
        Plugin.__init__(self, __name__)
        self.set_priority(100)
        self.level = "green"
        self.fixable = True
        self.button_text=_("Restore\nContext")

    def analyze(self, avc):
        if not avc.query_environment: return None

        if avc.spath is None: return None
        if avc.spath[0] != '/': return None
        try:
            mcon = selinux.matchpathcon(avc.spath.strip('"'), S_IFREG)[1]
            mcon_type=mcon.split(":")[2]
            gcon = selinux.getfilecon(avc.spath.strip('"'))[1]
            gcon_type = gcon.split(":")[2]
            if mcon_type != gcon_type:
                return self.report((0, mcon_type))
        except OSError:
            pass

        return None
