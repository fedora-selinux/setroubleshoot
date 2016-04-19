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
import os
from stat import *

import selinux
class plugin(Plugin):
    summary = _('''
    SELinux is preventing $SOURCE_PATH "$ACCESS" access to $TARGET_PATH.
    ''')

    def get_problem_description(self, avc, args):
        return _('''
You tried to place a type on a %s that is not a file type.  This is not allowed, you must assigne a file type.  You can list all file types using the seinfo command.

seinfo -afile_type -x

    ''') % args[1]

    if_text = _("If you want to change the label of $TARGET_PATH to %s, you are not allowed to since it is not a valid file type.")

    def get_if_text(self, avc, args):
        return self.if_text % args[1]

    then_text = _('you must pick a valid file label.')
    do_text = 'select a valid file type.  List valid file labels by executing: \n# seinfo -afile_type -x'

    def __init__(self):
        Plugin.__init__(self, __name__)
        self.set_priority(100)

    def analyze(self, avc):
        if avc.tcontext.type not in file_types:
            if avc.all_accesses_are_in(["relabelto"]):
                return self.report((0, avc.tcontext.type))
            if avc.all_accesses_are_in(["associate"]):
                return self.report((0, avc.scontext.type))
        return None
