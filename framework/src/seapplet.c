/*
 * seapplet.c
 *
 * Authors: John Dennis <jdennis@redhat.com>
 * Authors: Dan Walsh <dwalsh@redhat.com>
 *
 * Copyright (C) 2009 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *	   compile command
 *	   gcc -g sealerttrayicon.c -o sealerttrayicon `pkg-config --cflags --libs gtk+-2.0` -lnotify
 *
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <gtk/gtk.h>
#include <libnotify/notify.h>
#include <selinux/selinux.h>

#include <dbus/dbus-glib-lowlevel.h>
#include "sedbus.h"
#include <gio/gdesktopappinfo.h>

#ifdef ENABLE_NLS
#include <locale.h>		/* for setlocale() */
#include <libintl.h>		/* for gettext() */
#define _(msgid) gettext (msgid)
#define P_(msgid, msgid_plural, n) ngettext(msgid, msgid_plural, n)
#else
#define _(msgid) (msgid)
#define P_(msgid, msgid_plural, n) (n==1 ? msgid : msgid_plural)
#endif
#ifndef PACKAGE
#define PACKAGE "setroubleshoot"	/* the name of this package lang translation */
#endif
static const char *PATH="/org/fedoraproject/Setroubleshootd";
static const char *BUSNAME="org.fedoraproject.Setroubleshootd";
static const char *INTERFACE="org.fedoraproject.SetroubleshootdIface";

typedef struct {
	GtkStatusIcon *trayIcon;
	NotifyNotification *notify;
		guint32 need_bubble : 1;
	gchar *redFile;
	gchar *yellowFile;
} sealert;

#define TIMEOUT (10 * 1000)
static gchar *icon_file = "/usr/share/icons/hicolor/scalable/apps/setroubleshoot_icon.svg";
static gchar *redicon_file = "/usr/share/icons/hicolor/scalable/apps/setroubleshoot_red_icon.svg";

static char *configpath = NULL;

static int ignore(const char *local_id) 
{
	char *home;
	const char *DTAG = "dontnotify=";
	size_t dlen = strlen(DTAG);
	char *buf=NULL;
	
	int ret = FALSE;
	FILE *cfg = fopen(configpath, "r");
	if (cfg) {
		size_t size = 0;
		ssize_t len;
		while ((len = getline(&buf, &size, cfg)) > 0) {
			buf[len-1] = 0;
			if (strncmp(buf, DTAG, dlen) == 0) {
				int ctr=1;
				char *ptr = buf+dlen;
				while(*ptr) {
					if (ptr[0] == ',') ctr++;
					ptr++;
				}
				ptr = NULL;
				char *tok = strtok_r(buf+dlen, ",", &ptr);
				ctr=0;
				while (tok) {
					if (strcmp(tok, local_id) == 0) {
						ret = TRUE;
						goto DONE;
					}
					tok = strtok_r(NULL, ",",  &ptr);
					ctr++;
				}
			}
		}
DONE:
		fclose(cfg);
		free(buf);
	}
	return ret;
}

static void show_notification_now(sealert *alert) {
		GError *err = NULL;
//	notify_notification_attach_to_status_icon (alert->notify, alert->trayIcon);
	notify_notification_show (alert->notify, &err);
	if (err) {
		g_warning ("Error showing notification: %s", err->message);
		g_error_free (err);
	}
		alert->need_bubble = FALSE;
}

static void on_notify_embedded_changed (sealert *alert) {
		if (gtk_status_icon_is_embedded (alert->trayIcon) && alert->need_bubble) {
		show_notification_now (alert);
		}
}

static void show_notification(sealert *alert) {

	if (gtk_status_icon_is_embedded (alert->trayIcon)) {
		show_notification_now (alert);
	} else {
		g_signal_connect_swapped (alert->trayIcon, "notify::embedded",
						  G_CALLBACK (on_notify_embedded_changed),
										  alert);
				alert->need_bubble = TRUE;
	}

}

static void trayIconActivated(GObject *notused, gpointer ptr)
{
        GDesktopAppInfo *app;
        GAppLaunchContext *context;
	sealert *alert = (sealert*) ptr;
	gtk_status_icon_set_visible(alert->trayIcon, FALSE);
	alert->need_bubble = FALSE;
	notify_notification_close (alert->notify, NULL);
        app = g_desktop_app_info_new("setroubleshoot.desktop");
        context = (GAppLaunchContext*)gdk_app_launch_context_new ();
        g_app_info_launch ((GAppInfo*) app, NULL, context, NULL);
}


static void on_activate(NotifyNotification *notification, 
			const char *action, 
			sealert *alert) {
	if (strcmp(action, "dismiss") == 0)  {
		gtk_status_icon_set_visible(alert->trayIcon, FALSE);
		alert->need_bubble = FALSE;
		notify_notification_close (alert->notify, NULL);
	} else {
		trayIconActivated(NULL, alert);
	}
}

static void show_star(gpointer ptr, int red, char *local_id) {
	sealert *alert = (sealert *) ptr;
	gchar *file = NULL;
	if (gtk_status_icon_get_visible (alert->trayIcon) && ! red ) {
		return;
	}
	if (ignore(local_id)) 
		return;

	if (red) {
		gtk_status_icon_set_from_file(alert->trayIcon, redicon_file);
		file = alert->redFile;

	} else {
		gtk_status_icon_set_from_file(alert->trayIcon, icon_file);
		file = alert->yellowFile;
	}
	if ((! gtk_status_icon_get_visible (alert->trayIcon) || red ) &&
		alert->need_bubble == FALSE) {
		gtk_status_icon_set_visible(alert->trayIcon, TRUE);
		alert->notify = notify_notification_new(_("New SELinux security alert"),_("AVC denial, click icon to view"), red ? file : GTK_STOCK_DIALOG_WARNING);
		if (!red) {
			notify_notification_set_timeout (alert->notify, NOTIFY_EXPIRES_DEFAULT);

			notify_notification_add_action(alert->notify, 
							   "dismiss", 
							   _("Dismiss"),
							   (NotifyActionCallback) on_activate,
							   alert,
							   NULL);
		} else {
			notify_notification_set_timeout (alert->notify, NOTIFY_EXPIRES_NEVER);
		}

		notify_notification_add_action(alert->notify, 
						   "show", 
						   _("Show"),
						   (NotifyActionCallback) on_activate,
						   alert,
						   NULL);
		show_notification (alert);
	}
}

static void show_login_star(gpointer ptr, int yellow, int red) {
	
	sealert *alert = (sealert *) ptr;
	gchar *file = NULL;
	if (red) {
		gtk_status_icon_set_from_file(alert->trayIcon, redicon_file);
		file = alert->redFile;

	} else {
		gtk_status_icon_set_from_file(alert->trayIcon, icon_file);
		file = alert->yellowFile;
	}
	char msg [256];
	
	sprintf(msg, P_("Since your last login, there is %d new security alert to view.", \
				"Since your last login, there are %d new security alerts to view.", yellow+red), yellow+red);  
	
	if (red)
		sprintf(msg+strlen(msg), "  ");
		sprintf(msg+strlen(msg), P_("%d of the alerts may be very serious security violations.", \
					"%d of the alerts may be very serious security violations.", red), red);

	char title[50];
	sprintf(title, P_("%d New Security Alert", "%d New Security Alerts", yellow+red), yellow+red);
	gtk_status_icon_set_visible(alert->trayIcon, TRUE);
	alert->notify = notify_notification_new(title,
						msg,
						red ? file : GTK_STOCK_DIALOG_WARNING);
	if (!red) {
		notify_notification_set_timeout (alert->notify, NOTIFY_EXPIRES_DEFAULT);

		notify_notification_add_action(alert->notify, 
						   "dismiss", 
						   _("Dismiss"),
						   (NotifyActionCallback) on_activate,
						   alert,
						   NULL);
	} else {
		notify_notification_set_timeout (alert->notify, NOTIFY_EXPIRES_NEVER);
	}

	notify_notification_add_action(alert->notify, 
					   "show", 
					   _("Show"),
					   (NotifyActionCallback) on_activate,
					   alert,
					   NULL);
	alert->need_bubble = TRUE;
	show_notification_now (alert);
}

static int sedbus_send_check_new(DBusConnection* conn, gpointer ptr, char *local_id) {

	DBusMessage* msg;
	DBusMessageIter args;
	DBusPendingCall* pending;
	dbus_int32_t new_avcs = 0;
	dbus_int32_t red_avcs = 0;

	msg = dbus_message_new_method_call(BUSNAME, 
					   PATH, 
					   INTERFACE,
					   "check_for_new"); // method name
	if (NULL == msg) { 
		fprintf(stderr, "Can't communicate with setroubleshootd\n");
		return -1;
	}

	int index = 0;
	int id_found = 0;
	int newlines = 0;
	FILE *conf_file;
	char c;
	// append arguments 
	dbus_message_iter_init_append(msg, &args);
	if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &local_id)) { 
		fprintf(stderr, "Out Of Memory!\n"); 
		return -1;
	}

	// send message and get a handle for a reply
	if ( ! dbus_connection_send_with_reply (conn, msg, &pending, -1)) { 
		// -1 is default timeout
		fprintf(stderr, "Out Of Memory!\n"); 
		return -1;
	}
	if (NULL == pending) { 
		fprintf(stderr, "Pending Call Null\n"); 
		return -1;
	}
	dbus_connection_flush(conn);
	
	// free message
	dbus_message_unref(msg);

	// block until we receive a reply
	dbus_pending_call_block(pending);
   
	// get the reply message
	msg = dbus_pending_call_steal_reply(pending);
	if (NULL == msg) {
		fprintf(stderr, "Reply Null\n"); 
		return -1; 
	}
	// free the pending message handle
	dbus_pending_call_unref(pending);

	// read the parameters
	if (!dbus_message_iter_init(msg, &args))
		fprintf(stderr, "Message has no arguments!\n"); 
	else if (DBUS_TYPE_INT32!= dbus_message_iter_get_arg_type(&args)) 
		fprintf(stderr, "Argument is not int!\n"); 
	else
		dbus_message_iter_get_basic(&args, &new_avcs);


	if (!dbus_message_iter_next(&args))
		fprintf(stderr, "Message has no arguments!\n");
	else if (DBUS_TYPE_INT32 != dbus_message_iter_get_arg_type(&args))
		fprintf(stderr, "Argument is not int!\n");
	else
		dbus_message_iter_get_basic(&args, &red_avcs);


	// free reply and close connection
	dbus_message_unref(msg);   
	
	if (new_avcs + red_avcs == 0)
		return 0;
	
	
	show_login_star(ptr, new_avcs, red_avcs);
	return 0;
}

static int check_for_avcs(char *pos[]) 
{
	const char *PTAG = "last=";
	const char *CTAG = "checkonlogin=";
	size_t plen = strlen(PTAG);
	size_t clen = strlen(CTAG);
	char *buf=NULL;
	int check_on_login = 0;
	FILE *cfg = fopen(configpath, "r");
	char *last = NULL;
	if (cfg) {
		size_t size = 0;
		ssize_t len;
		while ((len = getline(&buf, &size, cfg)) > 0) {
			buf[len-1] = 0;
			if (strncmp(buf, PTAG, plen) == 0) {
				if (last) free(last);
				last=strdup(buf + plen);
			}
			if (strncmp(buf, CTAG, clen) == 0) {
				check_on_login=atoi(buf + clen);
			}
		}
		fclose(cfg);
		free(buf);
	}

	if (check_on_login) {
		if (last)
			*pos = last;
		else
			*pos = calloc(sizeof(char*),1);			
	} else {
		*pos = NULL;
		free(last);
	}

	return check_on_login;  
}

int main(int argc, char *argv[])
{
	#ifdef ENABLE_NLS
	bindtextdomain(PACKAGE, LOCALEDIR);
	bind_textdomain_codeset(PACKAGE, "UTF-8");
	textdomain(PACKAGE);
	#endif

	sealert alert;

	char *local_id=NULL;

	char *home;

	if (is_selinux_enabled() != 1) {
		fprintf(stderr, "SELinux Troubleshooter: Applet requires SELinux be enabled to run.\n");
		return 1;
	}

	home = getenv("HOME");	
	if (asprintf(&configpath, "%s/.setroubleshoot", home) < 0)
		return FALSE;

	int ctr = 0;

	gtk_init (&argc, &argv);
	
	notify_init ("Sealert notification");

	GtkWidget *window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
	gtk_widget_set_size_request (window, 200, -1);
	
	alert.yellowFile = g_filename_to_uri (icon_file, NULL, NULL);
	alert.redFile = g_filename_to_uri (redicon_file, NULL, NULL);
	alert.trayIcon  = gtk_status_icon_new_from_file (icon_file);

	//check with setroubleshoot server

	DBusError err;
	DBusConnection* conn;
	dbus_error_init(&err);
	conn = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
	if (dbus_error_is_set(&err)) {
		perror("error");
		dbus_error_free(&err);
	}
	if (NULL == conn){
		goto EXIT;
	}


	//set tooltip
	gtk_status_icon_set_tooltip (alert.trayIcon, _("SELinux AVC denial, click to view"));
	g_signal_connect(alert.trayIcon, "activate", GTK_SIGNAL_FUNC (trayIconActivated), &alert);
	gtk_status_icon_set_visible(alert.trayIcon, FALSE); //set icon initially invisible
	alert.need_bubble = FALSE;
	
	if (check_for_avcs(&local_id)  == TRUE) {
		sedbus_send_check_new(conn, (void *) &alert, local_id);
	}
	DBusConnection *conn2 = sedbus_receive(show_star, (void *) &alert);
	dbus_connection_setup_with_g_main(conn2, NULL);
	gtk_main ();

EXIT:
	free(configpath);
	free(local_id);
	ctr=0;
	return 0;
}

