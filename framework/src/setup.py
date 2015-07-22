#!/usr/bin/python

# Author: Dan Walsh <dwalsh@redhat.com>
import os
import sys
from distutils.core import setup, Extension

ext_modules = []
if sys.version_info < (3,):
    default_encoding_utf8 = Extension("setroubleshoot.default_encoding_utf8",
            sources=[ "default_encoding.c"]
            )
    ext_modules = [default_encoding_utf8]


setup(name = "setroubleshoot",
      version="1.1",
      description="Python SELinux Troubleshooter",
      author="Dan Walsh", author_email="dwalsh@redhat.com",
      url= '',
      download_url     = '',
      license          = 'GPLv3+',
      platforms        = 'posix',
      ext_modules=ext_modules,
      packages=["setroubleshoot"])
