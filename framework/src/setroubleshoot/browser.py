#!/usr/bin/python -Es
# Author: Thomas Liu <tliu@redhat.com>
# Author: Dan Walsh <dwalsh@redhat.com>
# Copyright (C) 2006-2011 Red Hat, Inc.
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
from math import pi
from subprocess import *
from gettext import ngettext as P_
from setroubleshoot.config import parse_config_setting, get_config
domain = get_config('general', 'i18n_text_domain')
gettext.install(domain    = domain,
                unicode = True,
                localedir = get_config('general', 'i18n_locale_dir'))
translation=gettext.translation(domain, fallback=True)
_=translation.ugettext
import sys, os
from xml.dom import minidom
from xmlrpclib  import ProtocolError
import gtk, glib
import gtk.glade
from setroubleshoot.errcode import *
from setroubleshoot.signature import *
from setroubleshoot.util import *
from setroubleshoot.html_util import html_to_text
import re
import dbus
import slip.dbus.service
from slip.dbus import polkit
import report
import report.io
import report.io.GTKIO
import report.accountmanager

import gio

cmp = lambda x, y: (x > y) - (x < y)

GLADE_DIRECTORY = "/usr/share/setroubleshoot/gui/"
OLD_PATH = os.environ['HOME'] + "/.setroubleshoot"
PREF_PATH = glib.get_user_config_dir() + "/sealert.conf"
UPDATE_PROGRAM = "/usr/bin/gpk-update-viewer"

dict = { "file": "text-x-generic",
         "dir":"inode/directory",
         "chr_file":"inode/chardevice",
         "blk_file":"inode/blockdevice",
         "lnk_file":"inode/symlink",
         "sock_file":"inode/socket",
         "executable":"application/x-executable",
         "socket":"text-x-generic",
         "capability":"text-x-generic",
         "process":"text-x-generic",
         "*":"text-x-generic",
 }

def msg(message):
    dlg = gtk.MessageDialog(None, 0, gtk.MESSAGE_INFO,
                            gtk.BUTTONS_CLOSE,
                            message)
    dlg.set_position(gtk.WIN_POS_MOUSE)
    dlg.show_all()
    dlg.run()
    dlg.destroy()

def fullpath(cmd):
       for i in [ "/", "./", "../" ]:
              if cmd.startswith(i):
                     return cmd
       for i in  os.environ["PATH"].split(':'):
              f = "%s/%s" % (i, cmd)
              if os.access(f, os.X_OK):
                     return f
       return cmd

def old():
    sealert_app_info = None
    desktop_icon_dict = {}
    for desktop_app_info in gio.app_info_get_all():
        exe = fullpath(desktop_app_info.get_executable())
        rpmver = get_rpm_nvr_by_file_path(exe)
        if rpmver:
            if rpmver in desktop_icon_dict:
                desktop_icon_dict[rpmver].append(desktop_app_info)
            else:
                desktop_icon_dict[rpmver] = [ desktop_app_info ]

        basename = os.path.basename(exe)
        if basename in desktop_icon_dict:
            desktop_icon_dict[basename].append(desktop_app_info)
        else:
            desktop_icon_dict[basename] = [ desktop_app_info ]

def get_icon(path, tclass="*"):
    try:
        base = os.path.basename(path)
        if base in desktop_icon_dict:
            for m in desktop_icon_dict[base]:
                icon = m.get_icon()
                if icon:
                    return icon

        rpmver = get_rpm_nvr_by_file_path(path)
        if rpmver in desktop_icon_dict:
            for m in desktop_icon_dict[rpmver]:
                icon = m.get_icon()
                if icon:
                    return icon

        file = gio.File(path)
        info = file.query_info("standard::*", flags=gio.FILE_QUERY_INFO_NOFOLLOW_SYMLINKS)
        icon = info.get_icon()
        if icon:
            icon.append_name("text-x-generic")
            return icon

    except gio.Error:
        pass

    if tclass in dict:
        return gio.content_type_get_icon(dict[tclass])
    else:
        return gio.content_type_get_icon(dict["*"])

package_list = set()
# The main security alert window
class BrowserApplet:
    """Security Alert Browser"""

    def on_troubleshoot_button_clicked(self, widget):
        widget.set_sensitive(False)
        self.solutions_pane.show()
        self.troubleshoot_visible = True
        self.window.set_size_request(self.width,self.height)

    def empty_load(self):
        self.clear_rows()
        self.alert_count_label.set_label("No alerts.")
        self.date_label.set_label("")

    def __init__(self, username=None, server=None, list=False, domain=None):
        self.RECT_SIZE = 20
        size = gtk.gdk.Screen().get_monitor_geometry(0)
        self.width = min(900, int(size.width * .90))
        self.height = min(500, int(size.height * .90))

        self.read_config()
        builder = gtk.Builder()
#        builder.set_translation_domain("setroubleshoot")
        builder.add_from_file("/usr/share/setroubleshoot/gui/browser.glade")
        self.plugins = load_plugins()

        self.alert_list = []
        server.connect('signatures_updated', self.update_alerts)
        self.pane = builder.get_object("solutions_pane")
        self.table = builder.get_object("solutions_table")
        self.window = builder.get_object("window")
        self.window.set_title(_("SELinux Alert Browser"))
        self.window.connect("destroy", self.quit)
        self.source_label = builder.get_object("source_label")
        self.source_title_label = builder.get_object("source_title_label")
        self.source_title_label.set_text(_("The source process:"))
#        self.source_image = builder.get_object("source_image")
        self.target_label = builder.get_object("target_label")
#        self.target_image = builder.get_object("target_image")
        self.yes_radiobutton = builder.get_object("yes_radiobutton")
        self.yes_radiobutton.set_label(_("Yes"))
        self.no_radiobutton = builder.get_object("no_radiobutton")
        self.no_radiobutton.set_label(_("No"))
        self.no_radiobutton.set_active(self.alert_disabled())
        self.class_label = builder.get_object("class_label")
        self.access_label = builder.get_object("access_label")
        self.access_title_label = builder.get_object("access_title_label")
        self.access_title_label.set_text(_("Attempted this access:"))
        self.severity_label = builder.get_object("severity_label")
        self.likelihood_label = builder.get_object("likelihood_label")
        self.if_label = builder.get_object("if_label")
        self.then_label = builder.get_object("then_label")
        self.do_label = builder.get_object("do_label")
        self.alert_count_label = builder.get_object("alert_count_label")
        self.date_label = builder.get_object("date_label")
        self.selinux_label = builder.get_object("selinux_label")
        self.current_policy_label = builder.get_object("current_policy_label")
        self.newer_policy_label = builder.get_object("newer_policy_label")
        self.details_window = builder.get_object("details_window")
        self.details_textview = builder.get_object("details_textview")
        self.details_window.connect("delete-event", self.on_close_details_button_clicked)
        self.details_window.set_title(_("SETroubleshoot Details Window"))

        label1 = builder.get_object("label1")
        label1.set_text(_("Would you like to receive alerts?"))
        self.next_button = builder.get_object("next_button")
        self.previous_button = builder.get_object("previous_button")
        self.report_button = builder.get_object("report_button")
        self.report_button.set_label(_("Notify Admin"))
        self.ignore_button = builder.get_object("ignore_button")
        self.troubleshoot_button = builder.get_object("troubleshoot_button")
        self.troubleshoot_button.set_label(_("Troubleshoot"))
        self.delete_button = builder.get_object("delete_button")
        self.details_button = builder.get_object("details_button")
        self.details_button.set_label(_("Details"))
        self.delete_list_button = builder.get_object("delete_list_button")
        self.troubleshoot_list_button = builder.get_object("troubleshoot_list_button")
        self.troubleshoot_list_button.set_label(_("Troubleshoot"))
        self.grant_button = builder.get_object("grant_button")
        self.alert_list_window = builder.get_object("alert_list_window")
        self.alert_list_window.connect("delete-event", self.close_alert_window)
        self.alert_list_window.set_title(_("SETroubleshoot Alert List"))
        self.list_all_button = builder.get_object("list_all_button")
        self.list_all_button.set_label(_("List All Alerts"))
        self.treeview_window = builder.get_object("treeview_window")
        self.treeview = builder.get_object("treeview")
        self.treeview.get_selection().set_mode(gtk.SELECTION_MULTIPLE)
        self.treeview.get_selection().connect("changed", self.itemSelected)
        self.solutions_pane = builder.get_object("solutions_pane")
        self.solutions_pane.hide()

        self.solutions_vbox = builder.get_object("solutions_vbox")
        self.bug_report_window = None

        builder.connect_signals(self)
        self.username = username
        self.database = server
        self.server = server
        self.domain = domain
        self.window.show()
        self.alert_list_window.hide()
        self.empty_load()
        self.load_data()
        self.liststore = gtk.ListStore(int, str, str, str, int, str)
        self.make_treeview()
        self.troubleshoot_visible=False
        self.current_alert = -1
        self.accounts = report.accountmanager.AccountManager()

    def get_current_alert(self):
        try:
            alert = self.alert_list[self.current_alert]
            return alert
        except:
            return None

    def itemSelected(self, widget):
           self.troubleshoot_list_button.set_sensitive(widget.count_selected_rows() == 1)
           self.delete_list_button.set_sensitive(widget.count_selected_rows() > 0)

    def install_button_clicked(self, widget):
        if not os.access(UPDATE_PROGRAM, os.X_OK):
            return

        if os.fork() == 0:
            os.execv(UPDATE_PROGRAM, [UPDATE_PROGRAM])

    def make_treeview(self):
        tmsort = gtk.TreeModelSort(self.liststore)

        cols = [_("#"), _("Source Process"), _("Attempted Access"), _("On this"), _("Occurred"), _("Status")]
        self.treeview.set_model(tmsort)
        x = 0
        for c in cols:
            cell = gtk.CellRendererText()
            col = gtk.TreeViewColumn(c)
            col.width = 20
            col.pack_start(cell, True)
            col.set_attributes(cell, text=x)
            col.set_sort_column_id(x)
            col.set_resizable(True)
            self.treeview.append_column(col)
            x +=1
        self.treeview.set_headers_clickable(True)
        self.treeview.connect("row-activated", self.row_activated)

    def row_activated(self, x, y, z):
        self.on_troubleshoot_list_button_clicked(None)

    def show_date(self, alert):
        from setroubleshoot.util import TimeStamp
        # Format the data that we get and display it in the appropriate places
        date_format = "%a %b %e, %Y %R %Z"
        alert_date = alert.last_seen_date
        start_date = alert.first_seen_date
        self.date_label.set_label(alert_date.format(date_format))

    def on_receive_button_changed(self, widget):
        found = False
        run_seapplet = self.yes_radiobutton.get_active()
        if run_seapplet:
            os.system("/usr/bin/seapplet &")
        else:
            os.system("/usr/bin/killall -9 seapplet 2>/dev/null")
        infile = open("/etc/xdg/autostart/sealertauto.desktop", "r")
        buf = infile.readlines()
        infile.close()
        try:
            os.makedirs(os.path.expanduser("~/.config/autostart"))
        except OSError:
            pass

        outfile = open(os.path.expanduser("~/.config/autostart/sealertauto.desktop"), "w")
        for line in buf:
            if line.startswith("X-GNOME-Autostart-enabled="):
                continue
            else:
                outfile.write(line)
        outfile.write("X-GNOME-Autostart-enabled=%s\n" % str(run_seapplet).lower())
        outfile.close()

    def alert_disabled(self):
           import re
           desktop_file = os.path.expanduser("~/.config/autostart/sealertauto.desktop")
           try:
                  infile = open(desktop_file , "r")
                  buf = infile.readlines()
                  infile.close()
                  for line in buf:
                         if re.search("X-GNOME-Autostart-enabled *= *false", line):
                                return True
           except:
                  pass
           return False

    def on_report_button_clicked(self, widget):
        alert = self.get_current_alert()
        if alert:
            report = alert.format_text()
            report += alert.format_details()
            Popen(["/usr/bin/xdg-email", "--subject", alert.summary(), "--body", report], stdout=PIPE)

    def set_ignore_sig(self, sig, state):
        if state == True:
            self.ignore_button.set_label(_("Notify"))
            self.ignore_button.set_tooltip_text(_("Notify alert in the future."))
            self.server.set_filter(sig, self.username, FILTER_ALWAYS, '')
        else:
            self.ignore_button.set_label(_("Ignore"))
            self.ignore_button.set_tooltip_text(_("Ignore alert in the future."))
            self.server.set_filter(sig, self.username, FILTER_NEVER, '')

    def on_ignore_button_clicked(self, widget):
        alert = self.get_current_alert()
        if alert:
            self.set_ignore_sig(alert.sig, alert.evaluate_filter_for_user(self.username) != "ignore")

    def load_data(self):
        if self.database is not None:
            criteria = "*"
            async_rpc = self.database.query_alerts(criteria)
            async_rpc.add_callback(self.first_load)
            async_rpc.add_errback(self.database_error)

    def first_load(self, alerts):
        for alert in alerts.siginfos():
            self.alert_list.append(alert)

        if self.current_alert < 0:
            self.current_alert = len(self.alert_list) -1

        self.show_current_alert()

    # TODO
    def database_error(self, method, errno, strerror):
        pass

    def clear_rows(self):
        self.radio = gtk.RadioButton(None)
        for child in self.table.get_children():
            self.table.remove(child)
        cols = int(self.table.get_property("n-columns"))
        self.table.resize(1, cols)
        col = 0
        label = gtk.Label()
        label.set_markup(_("<b>If you were trying to...</b>"))
        label.set_justify(gtk.JUSTIFY_LEFT)
        label.set_alignment(-1.0, 0.0)
        label.show()
        self.table.attach(label, col, col + 1, 0, 1, xoptions=0, yoptions=0)

        label = gtk.Label()
        label.set_justify(gtk.JUSTIFY_LEFT)
        label.set_alignment(0.0, 0.0)
        label.set_markup(_("<b>Then this is the solution.</b>"))
        label.show()
        col += 1
        self.table.attach(label, col, col + 1, 0, 1, xoptions=0, yoptions=0)

    def wrap(self,if_text):
        lines = ""
        line = ""
        for i in if_text.split():
            if len(line) + len(i) >  40:
                lines += line.strip() + "\n"
                line = ""
            line += i.strip() + " "

        lines += line
        return lines

    def add_row(self, plugin, alert, args):
        avc = alert.audit_event.records
        if_text = _("If ") + alert.substitute(plugin.get_if_text(avc, args))
        then_text = alert.substitute(plugin.get_then_text(avc, args))
        then_text += "\n" + alert.substitute(plugin.get_do_text(avc, args))

        if not if_text:
            return

        rows = int(self.table.get_property("n-rows"))
        cols = int(self.table.get_property("n-columns"))

        black = gtk.gdk.Color(0,0,0)
        if plugin.level == "red":
            color = gtk.gdk.Color(65535,0,0)
        elif plugin.level == "yellow":
            color = gtk.gdk.Color(65535,65525,0)
        elif plugin.level == "green":
            color = gtk.gdk.Color(0,65535,0)

        sev_toggle = gtk.ToggleButton()
#        sev_toggle.set_size_request(20,20)
        sev_toggle.modify_bg(gtk.STATE_PRELIGHT, color)
        sev_toggle.modify_bg(gtk.STATE_SELECTED, black)
        sev_toggle.modify_bg(gtk.STATE_ACTIVE, color)
        sev_toggle.modify_bg(gtk.STATE_NORMAL, color)

        sev_toggle.modify_fg(gtk.STATE_PRELIGHT, color)
        sev_toggle.modify_fg(gtk.STATE_SELECTED, black)
        sev_toggle.modify_fg(gtk.STATE_ACTIVE, black)
        sev_toggle.modify_fg(gtk.STATE_NORMAL, color)

        sev_toggle.modify_base(gtk.STATE_SELECTED, black)

        sev_toggle.set_alignment(0.5, 0.0)

        self.toggles.append(sev_toggle)
        sev_toggle.show()

        if_label = gtk.Label()
        if_label.set_text(self.wrap(if_text))
        if_label.set_justify(gtk.JUSTIFY_LEFT)
        if_label.set_alignment(0.5, 0.0)
        if_label.set_line_wrap(True)
        if_label.show()

        if_button = gtk.Button()
        if_box = gtk.HBox(False, 5)
        if_box.add(sev_toggle)
        if_box.set_child_packing(sev_toggle, expand=False, fill=False, padding=0, pack_type=0)
        if_box.add(if_label)
        if_button.add(if_box)
        if_box.show()
        if_button.show()

        then_label = gtk.Label()
        then_label.set_text(then_text)
        then_label.set_selectable(True)
        then_label.set_alignment(0.0, 0.0)
        then_label.set_justify(gtk.JUSTIFY_LEFT)
        then_label.show()

        then_scroll = gtk.ScrolledWindow()
        then_scroll.set_shadow_type(gtk.SHADOW_NONE)
        then_scroll.set_border_width(0)
        then_scroll.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        then_scroll.add_with_viewport(then_label)
        then_scroll.show()
        then_scroll.set_sensitive(False)
        then_scroll.set_size_request(450, 90)

        self.table.resize(rows, cols)
#        sev_toggle.connect("toggled", self.on_sev_togglebutton_activated, rows)
#        col = 0
#        self.table.attach(sev_toggle, col, col+1, rows, rows + 1, xoptions=0, yoptions=0)

        col = 0
#        col += 1
        if_button.connect("clicked", self.on_sev_togglebutton_activated, rows)
        self.table.attach(if_button, col, col+1, rows, rows + 1) # xoptions=gtk.EXPAND|gtk.FILL) #yoptions=gtk.FILL)

        col += 1
        self.table.attach(then_scroll, col, col+1, rows, rows + 1, xoptions=gtk.EXPAND|gtk.FILL, yoptions=gtk.EXPAND|gtk.FILL)
#, col, col+1, rows, rows + 1, xoptions=gtk.EXPAND|gtk.FILL,

        self.table.resize(rows + 1, cols + 1)
        col += 1

        vbox = gtk.VBox(spacing=5)
        report_button = gtk.Button()
        report_button.set_label(_("Plugin\nDetails"))
        report_button.show()

        report_button.connect("clicked", self.details, alert, plugin, args)
        vbox.add(report_button)

        if plugin.fixable:
            report_button = gtk.Button()
            report_button.set_label(plugin.button_text)
            report_button.show()
            report_button.connect("clicked", self.fix_bug, alert.local_id, plugin.analysis_id)
            vbox.add(report_button)

        elif plugin.report_bug:
               report_button = gtk.Button()
               report_button.set_label(_("Report\nBug"))
               report_button.show()
               report_button.connect("clicked", self.report_bug, alert)
               vbox.add(report_button)

        vbox.set_sensitive(False)
        vbox.show()
        self.table.attach(vbox, col, col+1, rows, rows + 1,xoptions=0, yoptions=0)

        return sev_toggle
    def on_sev_togglebutton_activated(self, widget, row):
        for child in self.table.get_children():
            r, c = self.table.child_get(child, "top_attach", "left_attach")
            if r == 0:
                continue

            if (c > 0):
                child.set_sensitive(r == row)

            try:
                if (c == 0) and child != widget:
                    child.set_active(False)
            except:
                pass

    def details(self, widget, alert, plugin, args):
           avc = alert.audit_event.records
           message = alert.substitute(alert.summary()) + "\n\n"
           message += _("Plugin: %s ") % plugin.analysis_id + "\n"
           msg = ""
           for i in plugin.get_problem_description(avc, args).split("\n"):
               msg += alert.substitute(i.strip()) + "\n"
           message += html_to_text(msg)
           message += alert.substitute(_("If ") + plugin.get_if_text(avc, args)) + "\n"
           message += alert.substitute(plugin.get_then_text(avc, args)) + "\n"
           message += alert.substitute(plugin.get_do_text(avc, args)) + "\n"
#           message += alert.substitute(alert.format_details()) + "\n"

           self.details_textview.get_buffer().set_text(message)
           self.details_window.show_all()

    def on_close_details_button_clicked(self, widget, args=None):
           self.details_window.hide()
           return True

    def read_config(self):
        filename = PREF_PATH
        self.checkonlogin=1
        if not os.path.exists(filename):
            if os.path.exists(OLD_PATH):
                fd = open(OLD_PATH, "r")
                buf = fd.read()
                fd.close()
                fd = open(filename, "w")
                fd.write(buf)
                fd.close()
                os.unlink(OLD_PATH)
        try:
            fd = open(filename, "r")
            for i in fd.readlines():
                rec=i.split("=")
                if rec[0] == "checkonlogin":
                    self.checkonlogin=int(rec[1])
                    fd.close()
        except IOError:
            pass
        return

    def quit(self, widget):
        filename = PREF_PATH
        try:
            fd = open(filename, "w")
        except IOError:
            gtk.main_quit()
            return

        if len(self.alert_list) > 0:
            fd.write("last=" + self.alert_list[-1].local_id)
        else:
            fd.write("last=")

        fd.write("\n");
        fd.write("checkonlogin=%d\n" % self.checkonlogin)
        fd.close()
        gtk.main_quit()

    def fix_bug(self, widget, local_id, analysis_id):
        # Grant access here
        # Stop showing the current alert that we've just granted access to
        try:
            dbus_proxy = DBusProxy()
            resp = dbus_proxy.run_fix(local_id, analysis_id)
            MessageDialog(resp)
        except dbus.DBusException as e:
            print(e)
            FailDialog(_("Unable to grant access."))

    def report_bug(self, widget, alert):
        # If we don't have a bug_report_window yet, make a new one
        if self.bug_report_window is None:
            br = BugReport(self, alert)
            self.bug_report_window = br
        self.bug_report_window.main_window.show()

    def update_alerts(self, database, type, item):

        def new_siginfo_callback(sigs):
            if self.current_alert == -1:
                self.current_alert = 0

            for alert in sigs.signature_list:
                self.add_alert(alert)
                self.update_num_label()

            self.update_button_visibility()
            self.show_current_alert()
            self.update_list_all()

        if type == "add" or type == "modify":
            async_rpc = self.database.query_alerts(item)
            async_rpc.add_callback(new_siginfo_callback)

    def update_num_label(self, empty=False):
        if empty is True:
            self.alert_count_label.set_text("")
            return
        self.alert_count_label.set_text(_("Alert %d of %d") % (self.current_alert+1, len(self.alert_list)))

    def foreach(self, model, path, iter, selected):
           selected.append(model.get_value(iter, 0))

    def on_delete_list_button_clicked(self, widget):
           selected = []
           self.treeview.get_selection().selected_foreach(self.foreach, selected)
           if len(selected) == 0:
               return

           alert = self.get_current_alert()
           selected.sort(reverse=True)
           for i in selected:
               key = self.alert_list[i - 1]
               self.database.delete_signature(key.sig)
               del self.alert_list[i - 1]
           try:
               self.current_alert = self.alert_list.index(alert)
           except ValueError:
               self.current_alert = 0
           self.update_list_all()
           self.show_current_alert()

    def on_troubleshoot_list_button_clicked(self, widget):
           selected = []
           self.treeview.get_selection().selected_foreach(self.foreach, selected)
           if len(selected) != 1:
                  return

           self.current_alert = selected[0] - 1
           self.alert_list_window.hide()
           self.show_current_alert()
           self.on_troubleshoot_button_clicked(self.troubleshoot_button)

    def on_details_button_clicked(self, widget):
        alert = self.get_current_alert()
        if alert:
            message = alert.format_text()
            message += alert.format_details()
            self.details_textview.get_buffer().set_text(message)
            self.details_window.show_all()

    def on_delete_button_clicked(self, widget):
        alert = self.get_current_alert()
        if alert:
            self.database.delete_signature(alert.sig)
            self.delete_current_alert()
            self.show_current_alert()

    def delete_current_alert(self):
        try:
            del self.alert_list[self.current_alert]
            if len(self.alert_list) == 0:
                self.empty_load()
            else:
                if self.current_alert > len(self.alert_list)-1:
                    self.current_alert = len(self.alert_list)-1
                    self.show_current_alert()
            self.update_list_all()
        except ValueError:
            pass

    def add_alert(self, new_alert):
        try:
            for alert in self.alert_list:
                if alert.local_id == new_alert.local_id:
                    index = self.alert_list.index(alert)
                    self.alert_list[index] = new_alert
                    return
        except:
            pass

        self.alert_list.append(new_alert)

    def show_current_alert(self):
        self.clear_rows()
        size = len(self.alert_list)
        self.update_button_visibility()

        if size  == 0:
            return

        size = size - 1

        if size < self.current_alert:
            self.current_alert = size

        self.target_label.set_label("")
        self.target_label.set_tooltip_text("")

        alert = self.get_current_alert()
        if not alert:
            return
        if not alert.spath:
            alert.spath = alert.scontext.type
        if len(alert.spath) > 30:
            self.source_label.set_label(os.path.basename(alert.spath))
        else:
            self.source_label.set_label(alert.spath)

        self.source_label.set_tooltip_text(alert.spath + "\n" + str(alert.scontext))
        path = ""
        tooltip = ""

        if alert.tpath and not alert.tpath == _("Unknown"):
            if len(alert.tpath) > 30:
                path = os.path.basename(alert.tpath)
            else:
                path = alert.tpath
            tooltip = alert.tpath

            if alert.tcontext:
                tooltip += "\n" + str(alert.tcontext)
        else:
            if alert.tcontext:
                tooltip = str(alert.tcontext)

        self.target_label.set_label(path)
        self.target_label.set_tooltip_text(tooltip)

        if alert.tclass == "dir":
            tclass = "directory"
        else:
            tclass = alert.tclass
        self.class_label.set_label(_("On this %s:") % tclass)
        self.access_label.set_label(",".join(alert.sig.access))

        total_priority, plugins = alert.get_plugins()

        alert.update_derived_template_substitutions()

        self.toggles=[]
        for p, args in plugins:
               rb = self.add_row(p, alert, args)

        if len(plugins) == 1:
               rb.set_active(True)
               self.on_sev_togglebutton_activated(rb, 1)

        self.show_date(alert)

        self.alert_count_label.set_label(_("Alert %d of %d") % (self.current_alert + 1, len(self.alert_list)))
        if alert.evaluate_filter_for_user(self.username) == "ignore":
            self.ignore_button.set_label(_("Notify"))
        else:
            self.ignore_button.set_label(_("Ignore"))

    def on_close_button_clicked(self, widget):
        gtk.main_quit()

    def close_alert_window(self, widget, event=None):
        self.alert_list_window.hide()
        return True

    def on_about_activate(self, widget):
        self.about_dialog.show()

    def on_previous_button_clicked(self, widget):
        if self.current_alert > 0:
            self.current_alert -= 1
            self.show_current_alert()

    def on_next_button_clicked(self, widget):
        if self.current_alert < len(self.alert_list)-1:
            self.current_alert += 1
            self.show_current_alert()

    def update_list_all(self):
        self.liststore.clear()
        ctr = 1
        for alert in self.alert_list:
            if not alert.spath:
                spath = _("N/A")
            else:
                spath = os.path.basename(alert.spath)

            tpath = alert.tpath
            if not tpath:
                tpath = _("N/A")
            elif tpath == _("Unknown"):
                tpath = alert.tclass
            elif len(tpath) > 1:
                tpath = os.path.basename(tpath.rstrip("/"))

            if alert.evaluate_filter_for_user(self.username) == "ignore":
                status = _("Ignore")
            else:
                status = _("Notify")

            self.liststore.append([ctr, spath, ",".join(alert.sig.access), tpath, alert.report_count, status])
            ctr = ctr + 1

    def on_list_all_button_clicked(self, widget):
        self.update_list_all()
        self.alert_list_window.show_all()

    def update_button_visibility(self):
        size = len(self.alert_list)

        if size < 2:
            self.next_button.set_sensitive(False)
            self.previous_button.set_sensitive(False)

        if size == 0:
            self.delete_button.set_sensitive(False)
            self.details_button.set_sensitive(False)
            self.ignore_button.set_sensitive(False)
            self.report_button.set_sensitive(False)
            self.list_all_button.set_sensitive(False)
            self.alert_count_label.set_sensitive(False)
            self.source_title_label.hide()
            self.source_label.hide()
#            self.source_image.hide()
            self.target_label.hide()
#            self.target_image.hide()
            self.class_label.hide()
            self.access_label.hide()
            self.date_label.hide()
            self.access_title_label.hide()
            self.alert_count_label.set_text(_("No Alerts"))
            self.selinux_label.set_text(_("No Alerts"))
            return

        self.delete_button.set_sensitive(True)
        self.details_button.set_sensitive(True)
        self.ignore_button.set_sensitive(True)
        self.report_button.set_sensitive(True)
        self.list_all_button.set_sensitive(True)
        self.alert_count_label.set_sensitive(True)
        self.source_title_label.show()
        self.source_label.show()
#        self.source_image.show()
        self.target_label.show()
#        self.target_image.show()
        self.class_label.show()
        self.access_label.show()
        self.access_title_label.show()
        self.date_label.show()
        self.selinux_label.set_text(_("SELinux has detected a problem."))
        if size > 1:
            self.next_button.set_sensitive(True)
            self.previous_button.set_sensitive(True)

        self.next_button.set_sensitive(self.current_alert < (size - 1))
        self.previous_button.set_sensitive(self.current_alert != 0)

    def show(self):
        self.window.show()

    def hide(self):
        self.main_window.hide()

class DBusProxy (object):
    def __init__ (self):
        self.bus = dbus.SystemBus ()
        self.dbus_object = self.bus.get_object ("org.fedoraproject.SetroubleshootFixit", "/org/fedoraproject/SetroubleshootFixit/object")

    @polkit.enable_proxy
    def run_fix (self, local_id, plugin_name):
        return self.dbus_object.run_fix (local_id, plugin_name, dbus_interface = "org.fedoraproject.SetroubleshootFixit")

# BugReport is the window that pops up when you press the Report Bug button
class BugReport:
    def __init__(self, parent, alert):

        self.parent = parent
        self.gladefile = GLADE_DIRECTORY + "bug_report.glade"
        self.widget_tree = gtk.glade.XML(self.gladefile, domain=parent.domain)
        self.alert = alert
        self.hostname = self.alert.sig.host
        self.alert.host = "(removed)"
        self.alert.environment.hostname = "(removed)"
        self.alert.sig.host = "(removed)"

        hash = self.alert.get_hash()
        self.summary = self.alert.untranslated(self.alert.summary)
        # Get the widgets we need
        self.main_window = self.widget("bug_report_window")
        self.error_submit_text = self.widget("error_submit_text")
        self.submit_button = self.widget("submit_button")
        self.cancel_button = self.widget("cancel_button")
        self.error_submit_text = self.widget("error_submit_text")

        # Construct and connect the dictionary
        dic = { "on_cancel_button_clicked" : self.cancel_button_clicked,
                "on_submit_button_clicked" : self.submit_button_clicked}

        self.main_window.connect("destroy", self.destroy)
        self.widget_tree.signal_autoconnect(dic)

        text_buf = gtk.TextBuffer()
        text = self.alert.untranslated(self.alert.format_text, replace = True)
        text += self.alert.untranslated(self.alert.format_details, replace = True)
        text_buf.set_text(text)
        self.error_submit_text.set_buffer(text_buf)

    def destroy(self, widget):
        # When we close the window let the parent know that it no longer exists
        self.parent.bug_report_window = None
        self.main_window.destroy()

    def cancel_button_clicked(self, widget):
        self.destroy(self.main_window)

    def idle_func(self):
        while gtk.events_pending():
            gtk.main_iteration()

    def submit_button_clicked(self, widget):
        main_window = self.main_window.get_root_window()
        busy_cursor = gtk.gdk.Cursor(gtk.gdk.WATCH)
        ready_cursor = gtk.gdk.Cursor(gtk.gdk.LEFT_PTR)
        main_window.set_cursor(busy_cursor)
        self.idle_func()

        self.submit()

        main_window.set_cursor(ready_cursor)
        self.idle_func()

    def submit(self):
        text_buf = self.error_submit_text.get_buffer()
        content = text_buf.get_text(text_buf.get_start_iter(), text_buf.get_end_iter())
        signature = report.createAlertSignature("selinux-policy",
                                                "setroubleshoot",
                                                self.alert.get_hash(),
                                                self.summary,
                                                content,
                                                package=self.alert.get_policy_rpm())

        try:
            rc = report.report(signature, report.io.GTKIO.GTKIO(self.parent.accounts))
        except ProtocolError as e:
            FailDialog(e)
        self.destroy(self.main_window)

    def widget(self, name):
        return self.widget_tree.get_widget(name)

class FailDialog():
    def __init__(self, message):
        dlg = gtk.MessageDialog(None, 0, gtk.MESSAGE_ERROR,
                                gtk.BUTTONS_OK,
                                message)
        dlg.set_title(_("Sealert Error"))
        dlg.set_position(gtk.WIN_POS_MOUSE)
        dlg.show_all()
        rc = dlg.run()
        dlg.destroy()

class MessageDialog():
    def __init__(self, message):
        dlg = gtk.MessageDialog(None, 0, gtk.MESSAGE_INFO,
                                gtk.BUTTONS_OK,
                                message)
        dlg.set_title(_("Sealert Message"))
        dlg.set_position(gtk.WIN_POS_MOUSE)
        dlg.show_all()
        rc = dlg.run()
        dlg.destroy()

def compare_alert(a, b):
    return cmp(a.last_seen_date, b.last_seen_date)
