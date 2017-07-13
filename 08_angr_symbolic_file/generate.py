#!/usr/bin/env python

import sys, random, os, tempfile
sys.path.append('/home/jake/templite')
from templite import Templite

description = ''
with open('description.txt', 'r') as desc_file:
  description = desc_file.read().encode('string_escape')

userdef_charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
userdef0 = ''.join(random.choice(userdef_charset) for _ in range(8))
userdef1 = ''.join(random.choice(userdef_charset) for _ in range(8))
template = open('08_angr_symbolic_file.c.templite', 'r').read()
c_code = Templite(template).render(description=description, userdef0=userdef0, userdef1=userdef1)
print userdef0
print userdef1

with tempfile.NamedTemporaryFile(delete=False, suffix='.c') as temp:
  temp.write(c_code)
  temp.seek(0)
  os.system('gcc -m32 -o 08_angr_symbolic_file ' + temp.name)
