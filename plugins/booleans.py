#!/usr/bin/python
import seobject
fd = open('booleans_trans.py', 'w')
for i in seobject.booleans_dict:
    desc = seobject.booleans_dict[i][2]
    fd.write('_("If you want to ' + desc[0].lower() + desc[1:] + '")\n')
fd.close()
#    print "Then you must tell SELinux about this by enabling the %s boolean" % i
#    print "Do # setsebool -P %s 1 " % i
#    print "======================================================================"
#    print desc[0].lower() + desc[1:]

