# @author Miroslav Grepl<mgrepl@redhat.com>
#
# Copyright (C) 2011 Red Hat, Inc.
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
    SELinux is preventing $SOURCE_PATH the "$ACCESS" capability.
    ''')

    problem_description = _('''
	dac_override and dac_read_search capabilities usually indicates that the root process does not have access to a file based on the permission flags.  This usually mean you have some file with the wrong ownership/permissions on it.
    ''')

    fix_description = ""
    fix_cmd = ""
    if_text = _("If you want to help identify if domain needs this access or you have a file with the wrong permissions on your system")
    then_text = _("turn on full auditing to get path information about the offending file and generate the error again.")
    do_text = _("""
Turn on full auditing
# auditctl -w /etc/shadow -p w
Try to recreate AVC. Then execute
# ausearch -m avc -ts recent
If you see PATH record check ownership/permissions on file, and fix it,
otherwise report as a bugzilla.""")

    def __init__(self):
        Plugin.__init__(self, __name__)
        self.level="green"

    def analyze(self, avc):
        if avc.has_any_access_in(['dac_override','dac_read_search']):
            # MATCH
            return self.report()
        return None
