#
# Authors: Dan Walsh <dwalsh@redhat.com>
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
import os
from stat import *

class plugin(Plugin):
    summary = _('''
    SELinux is preventing $SOURCE_PATH "$ACCESS" access to $TARGET_PATH.
    ''')

    problem_description = _('''
    SELinux denied access requested by $SOURCE. $TARGET_PATH may
    be mislabeled. openvpn is allowed to read content in home directory if it
    is labeled correctly.
    ''')

    fix_description = _('''
    You can restore the default system context to this file by executing the
    restorecon command.  
    # restorecon -R /root/.ssh
    ''')

    def get_if_text(self, avc, args):
        if (args[0] == "move"):
            return _('If you want to mv $TARGET_BASE_PATH to standard location so that $SOURCE_BASE_PATH can have $ACCESS access')
        else:
            return _('If you want to modify the label on $TARGET_BASE_PATH so that $SOURCE_BASE_PATH can have $ACCESS access on it')

    def get_then_text(self, avc, args):
        if (args[0] == "move"):
            return _('you must move the cert file to the ~/.cert directory')
        else:
            return _('you must fix the labels.')

    def get_do_text(self, avc, args):
        if (args[0] == "move"):
            return """# mv $TARGET_PATH ~/.cert
# restorecon -R -v ~/.cert
"""
        else:
            return """# semanage fcontext -a -t home_cert_t $TARGET_PATH
# restorecon -R -v $TARGET_PATH
"""

    def __init__(self):
        Plugin.__init__(self, __name__)
        self.set_priority(8)
        self.level="yellow"

    def analyze(self, avc):
        if (avc.matches_source_types(['openvpn_t']) and
                avc.matches_target_types(['user_home_t', 'user_tmp_t']) and
                avc.all_accesses_are_in(avc.read_file_perms) and
                avc.has_tclass_in(['file'])):
            return [self.report(("move",None)), self.report(("fixlabel",None))]

        return None
