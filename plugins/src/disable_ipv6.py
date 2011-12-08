# @author Dan Walsh <dwalsh@redhat.com>
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
_=translation.ugettext

from setroubleshoot.util import *
from setroubleshoot.Plugin import Plugin
import re
import os, commands

class plugin(Plugin):
    summary =_('''
Disable IPV6 properly.
    ''')

    problem_description = ""

    fix_description = ""

    fix_cmd = ""

    if_text = _("you want to disable IPV6 on this machine")
    then_text = _("you need to set /proc/sys/net/ipv6/conf/all/disable_ipv6 to 1 and do not blacklist the module'")
    do_text = _("""Add 
net.ipv6.conf.all.disable_ipv6 = 1
to /etc/sysctl.conf
""")

    def __init__(self):
        Plugin.__init__(self, __name__)

    def analyze(self, avc):
        if avc.has_any_access_in(['module_request']) and avc.kmod == "net-pf-10":
            # MATCH, White means ignore avc
            return self.report()
        return None
