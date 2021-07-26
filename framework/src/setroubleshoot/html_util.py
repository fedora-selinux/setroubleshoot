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

    'html_document',
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


def html_document(*body_components):
    '''Wrap the body components in a HTML document structure with a valid header.
    Accepts a variable number of arguments of of which canb be:
    * string
    * a sequences of strings (tuple or list).
    * a callable object taking no parameters and returning a string or sequence of strings.
    '''
    head = '<html>\n  <head>\n    <meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>\n  </head>\n  <body>\n'
    tail = '\n  </body>\n</html>'

    doc = head

    for body_component in body_components:
        if isinstance(body_component, six.string_types):
            doc += body_component
        elif isinstance(body_component, (tuple, list)):
            for item in body_component:
                doc += item
        elif callable(body_component):
            result = body_component()
            if isinstance(result, (tuple, list)):
                for item in result:
                    doc += item
            else:
                doc += result
        else:
            doc += body_component

    doc += tail
    return doc
