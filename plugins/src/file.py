#
# Copyright (C) 2006 Red Hat, Inc.
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
    SELinux is preventing access to a file labeled unlabeled_t.
    ''')

    problem_description = _('''
    SELinux permission checks on files labeled unlabeled_t are being
    denied. unlabeled_t is a context the SELinux kernel gives to files
    that do not have a label. This indicates a serious labeling
    problem. No files on an SELinux box should ever be labeled unlabeled_t.
    If you have just added a disk drive to the system, you can
    relabel it using the restorecon command. For example if you saved the
home directory from a previous installation that did not use SELinux, 'restorecon -R -v /home' will fix the labels.  Otherwise you should
    relabel the entire file system.
    ''')

    fix_description = _('''
    You can execute the following command as root to relabel your
    computer system: "touch /.autorelabel; reboot"
    ''')

    def get_if_text(self, avc, args):
        if args == (1,0):
            return _('This is caused by a newly created file system.')
        else:
            return _('If you think this is caused by a badly mislabeled machine.')

    def get_then_text(self, avc, args):
        if args == (1,0):
            return _('you need to add labels to it.')
        else:
            return _('you need to fully relabel.')

    def get_do_text(self, avc, args):
        if args == (1,0):
            return '/sbin/restorecon -R -v $TARGET_PATH'
        else:
            return 'touch /.autorelabel; reboot'

    def get_fix_cmd(self, avc, args):
        if args == (1,0):
            return '/sbin/restorecon -R -v $TARGET_PATH'
        else:
            return 'touch /.autorelabel; reboot'

    def init_args(self, args):
        if args == (1,0):
            self.button_text = _("Try to fix the label.")
            self.set_priority(70)
        else:
            self.button_text = _("Relabel the whole file system. Includes reboot!")
            self.set_priority(30)

    def __init__(self):
        Plugin.__init__(self,__name__)
        self.level="green"
        self.fixable=True

    def analyze(self, avc):
        if avc.matches_target_types(['unlabeled_t']):
            # MATCH
            reports = []
            reports.append(self.report((1,0)))
            reports.append(self.report((2,0)))
            return reports
        else:
            return None
