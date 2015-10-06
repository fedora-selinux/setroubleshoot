from __future__ import absolute_import
# Authors: John Dennis <jdennis@redhat.com>
#
# Copyright (C) 2006,2007,2008 Red Hat, Inc.
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

__all__ = ['email_alert',
          ]

import syslog
import re
from email.MIMEText import MIMEText
from email.MIMEMultipart import MIMEMultipart
from email.Utils import formatdate

from setroubleshoot.config import get_config
from setroubleshoot.util import *

email_addr_re = re.compile('^\s*([^@ \t]+)(@([^@ \t]+))?\s*$')

def parse_email_addr(addr):
    match = email_addr_re.search(addr)
    user = None
    domain = None
    if match:
        user = match.group(1)
        domain = match.group(3)
    return (user, domain)
    
def email_alert(siginfo, to_addrs):
    smtp_host    = get_config('email','smtp_host')
    smtp_port    = get_config('email','smtp_port', int)
    from_address = get_config('email','from_address')

    from_user, from_domain = parse_email_addr(from_address)
    if from_user is None:
        from_user = "SELinuxTroubleshoot"
    if from_domain is None:
        from_domain = get_hostname()
    from_address = '%s@%s' % (from_user, from_domain)

    log_debug("alert smtp=%s:%d  -> %s" % (smtp_host, smtp_port, ','.join(to_addrs)))

    siginfo.update_derived_template_substitutions()
    summary = siginfo.substitute(siginfo.summary())
    subject = '[%s] %s' % (get_config('email','subject'), summary)
    text = siginfo.format_text() + siginfo.format_details() 

    email_msg            = MIMEMultipart('alternative')
    email_msg['Subject'] = subject
    email_msg['From']    = from_address
    email_msg['To']      = ', '.join(to_addrs)
    email_msg['Date']    = formatdate()

    email_msg.attach(MIMEText(text))

    import smtplib
    try:
        smtp = smtplib.SMTP(smtp_host, smtp_port)
        smtp.sendmail(from_address, to_addrs, email_msg.as_string())
        smtp.quit()
    except smtplib.SMTPException as e:
        syslog.syslog(syslog.LOG_ERR, "email failed: %s" % e)

#-----------------------------------------------------------------------------

if __name__ == "__main__":
    email_alert('This is the sig', 'This is the solution')
