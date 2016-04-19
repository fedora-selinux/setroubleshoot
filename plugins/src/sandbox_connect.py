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

class plugin(Plugin):
    summary =_('''
    SELinux is preventing $SOURCE_PATH from connecting to port $PORT_NUMBER.
    ''')

    problem_description = _('''
    SELinux has denied $SOURCE from connecting to a network port $PORT_NUMBER within a sandbox.
    If $SOURCE should be allowed to connect on $PORT_NUMBER, you need to use a different sandbox type like sandbox_web_t or sandbox_net_t.  
    # sandbox -X -t sandbox_net_t $SOURCE
    \n\nIf $SOURCE is not supposed
    to connect to $PORT_NUMBER, this could signal an intrusion attempt.
    ''')

    fix_description = _('''
    If you want to allow $SOURCE to connect to $PORT_NUMBER, you can execute \n
    # sandbox -X -t sandbox_net_t $SOURCE
    ''')

    fix_cmd = ''
    if_text = _("If you want to allow $SOURCE_PATH to connect to network port $PORT_NUMBER")

    then_text =  _("""you need to modify the sandbox type. sandbox_web_t or sandbox_net_t.
For example:
sandbox -X -t sandbox_net_t $SOURCE_PATH
Please read 'sandbox' man page for more details.
""")

    def __init__(self):
        Plugin.__init__(self, __name__)
        self.set_priority(75)

    def analyze(self, avc):
        if (avc.matches_source_types(['sandbox_x_client_t']) and
            avc.has_any_access_in(['name_connect'])):
            return self.report()

        return None
