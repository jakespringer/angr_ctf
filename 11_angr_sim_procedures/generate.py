#!/usr/bin/env python

import sys, random, os, tempfile
sys.path.append('/home/jake/templite')
from templite import Templite

description = ''
with open('description.txt', 'r') as desc_file:
  description = desc_file.read().encode('string_escape').replace('\"', '\\\"')

userdef_charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
userdef = [''.join(random.choice(userdef_charset) for _ in range(8)) for _ in range(4)]
template = open('11_angr_sim_procedures.c.templite', 'r').read()
c_code = Templite(template).render(description=description, userdef0=userdef[0], userdef1=userdef[1], userdef2=userdef[2], userdef3=userdef[3])
print userdef

with tempfile.NamedTemporaryFile(delete=False, suffix='.c') as temp:
  temp.write(c_code)
  temp.seek(0)
  os.system('gcc -m32 -o 11_angr_sim_procedures ' + temp.name)
