# Authors: John Dennis <jdennis@redhat.com>
#
# Copyright (C) 2007 Red Hat, Inc.
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


__all__ = [
    'escape_html',
    'unescape_html',
    'html_to_text',
]

import syslog
import sys
import textwrap
if sys.version_info > (3,):
    from html.parser import HTMLParser
else:
    from HTMLParser import HTMLParser

#------------------------------------------------------------------------------

class HTMLFilter(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self)
        self.text = ""

    def handle_data(self, data):
        self.text += data

#------------------------------------------------------------------------------

def escape_html(s):
    if s is None:
        return None
    try:
        s = s.replace("&", "&amp;")  # Must be done first!
        s = s.replace("<", "&lt;")
        s = s.replace(">", "&gt;")
        s = s.replace("'", "&apos;")
        s = s.replace('"', "&quot;")
    except:
        pass
    return s


def unescape_html(s):
    if s is None:
        return None
    if '&' not in s:
        return s
    s = s.replace("&lt;", "<")
    s = s.replace("&gt;", ">")
    s = s.replace("&apos;", "'")
    s = s.replace("&quot;", '"')
    s = s.replace("&amp;", "&")  # Must be last
    return s


def html_to_text(html, maxcol=80):
    try:
        filter = HTMLFilter()
        filter.feed(html)
        return textwrap.fill(filter.text, width=maxcol)
    except Exception as e:
        syslog.syslog(syslog.LOG_ERR, 'cannot convert html to text: %s' % e)
        return None
