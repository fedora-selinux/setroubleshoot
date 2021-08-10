#
# Authors: Dan Walsh <dwalsh@redhat.com>
#
# Copyright (C) 2007-2013 Red Hat, Inc.
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

customizable_types = None
def customizable(target):
    global customizable_types
    if not customizable_types:
        fd = open(selinux.selinux_customizable_types_path())
        customizable_types = fd.read().split("\n")
        fd.close()
    return target in customizable_types


# List of path prefixes for which this plugin is not executed
excluded_paths = ["/sys/", "/proc/", "/memfd:"]
# Test if the specified path starts with some excluded prefix
def excluded_path(target_path):
    for path in excluded_paths:
        if target_path.startswith(path): return True
    return False

import selinux
class plugin(Plugin):
    summary = _('''
    SELinux is preventing $SOURCE_PATH "$ACCESS" access to $TARGET_PATH.
    ''')

    fix_cmd = "/sbin/restorecon $TARGET_PATH"

    fix_description = _('''
    You can restore the default system context to this file by executing the
    restorecon command.  restorecon '$TARGET_PATH', if this file is a directory,
    you can recursively restore using restorecon -R '$TARGET_PATH'.
    ''')

    def get_problem_description(self, avc, args):
        return _('''
    SELinux denied access requested by $SOURCE. $TARGET_PATH may
    be mislabeled.  $TARGET_PATH default SELinux type is
    <B>%s</B>, but its current type is <B>$TARGET_TYPE</B>. Changing
    this file back to the default type may fix your problem.
    <p>
    File contexts can be assigned to a file in the following ways.
    <ul>
        <li>Files created in a directory receive the file context of the parent directory by default.
        <li>The SELinux policy might override the default label inherited from the parent directory by
            specifying a process running in context A which creates a file in a directory labeled B
            will instead create the file with label C. An example of this would be the dhcp client running
            with the dhcpc_t type and creating a file in the directory /etc. This file would normally
            receive the etc_t type due to parental inheritance but instead the file
            is labeled with the net_conf_t type because the SELinux policy specifies this.
        <li>Users can change the file context on a file using tools such as chcon, or restorecon.
    </ul>
    This file could have been mislabeled either by user error, or if an normally confined application
    was run under the wrong domain.
    <p>
    However, this might also indicate a bug in SELinux because the file should not have been labeled
    with this type.
    <p>
    If you believe this is a bug, please file a bug report against this package.
    ''') % args[1]

    if_text = _("If you want to fix the label. \n$TARGET_PATH default label should be %s.")

    def get_if_text(self, avc, args):
        return self.if_text % args[1]


    then_text = _('you can run restorecon. The access attempt may have been stopped due to insufficient' \
         + ' permissions to access a parent directory in which case try to change the following command accordingly.')
    do_text = '# /sbin/restorecon -v $TARGET_PATH'

    def __init__(self):
        Plugin.__init__(self, __name__)
        self.set_priority(100)
        self.level = "green"
        self.fixable = True
        self.button_text=_("Restore\nContext")

    def analyze(self, avc):
        if not avc.query_environment: return None
        if avc.tcontext.type in [ "cifs_t", "nfs_t" ]: return None
        if avc.tcontext.type not in file_types: return None
        if avc.all_accesses_are_in("relabelto"): return None
        restorecon_files = {}
        restorecon_files['dir'] = S_IFDIR
        restorecon_files['file'] = S_IFREG
        restorecon_files['lnk_file'] = S_IFLNK
        restorecon_files['chr_file'] = S_IFCHR
        restorecon_files['blk_file'] = S_IFBLK

        if avc.has_tclass_in(restorecon_files.keys()):
            if avc.tpath is None: return None
            if avc.tpath == "/": return None
            if avc.tpath[0] != '/': return None
            if excluded_path(avc.tpath): return None
            if customizable(avc.tcontext.type):
                return None
            try:
                mcon = selinux.matchpathcon(avc.tpath.strip('"'), restorecon_files[avc.tclass])[1]
                mcon_type=mcon.split(":")[2]
                if mcon_type != avc.tcontext.type:
                    return self.report((0, mcon_type))
            except OSError as e:
                pass

        return None
