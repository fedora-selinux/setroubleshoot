#!/usr/bin/python3
import sepolicy
sepolicy.gen_bool_dict()
for i in sepolicy.booleans_dict:
    desc = sepolicy.booleans_dict[i][2]
    print('_("If you want to ' + desc[0].lower() + desc[1:] + '")\n')

