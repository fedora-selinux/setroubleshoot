# Authors: John Dennis <jdennis@redhat.com>
# Authors: Dan Walsh <dwalsh@redhat.com>
#
# Copyright (C) 2006-2010 Red Hat, Inc.
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

# Needed to silence warnings if X display is not present
import warnings
warnings.filterwarnings('ignore', 'could not open display')

import gtk

#------------------------------------------------------------------------------

__all__ = ['get_display',
           'display_traceback',
          ]


#------------------------------------------------------------------------------

def get_display():
    try:
        dpy = gtk.gdk.Display('')
        dpy_name = dpy.get_name()
        return dpy_name
    except RuntimeError as e:
        return None

    # --- Interaction Dialogs ---

def display_traceback(who,  parent=None):
    if get_display() is None:
        return None

    import traceback

    stacktrace = traceback.format_exc()
    message = _("Opps, %s hit an error!" % who)

    title= who + ' ' + _("Error")
    dlg = gtk.Dialog(title, parent, 0, (gtk.STOCK_OK, gtk.RESPONSE_OK))
    dlg.set_position(gtk.WIN_POS_CENTER)
    dlg.set_default_size(600, 400)

    text_buffer = gtk.TextBuffer()
    text_buffer.set_text(message+'\n\n'+stacktrace)

    text_view = gtk.TextView(text_buffer)
    text_view.set_editable(False)

    scrolled_window = gtk.ScrolledWindow()
    scrolled_window.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
    scrolled_window.add(text_view)

    dlg.vbox.pack_start(scrolled_window, True, True, 0)

    dlg.show_all()
    rc = dlg.run()
    dlg.destroy()
    if rc == gtk.RESPONSE_OK:
        return True
    return None
