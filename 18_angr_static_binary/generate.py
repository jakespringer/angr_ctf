#!/usr/bin/env python

import sys, random, os, tempfile
sys.path.append('/home/jake/templite')
from templite import Templite

description = ''
with open('description.txt', 'r') as desc_file:
  description = desc_file.read().encode('string_escape')

userdef_charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
userdef = ''.join(random.choice(userdef_charset) for _ in range(8))
template = open('18_angr_static_binary.c.templite', 'r').read()
c_code = Templite(template).render(description=description, USERDEF=userdef)
print userdef

with tempfile.NamedTemporaryFile(delete=False, suffix='.c') as temp:
  temp.write(c_code)
  temp.seek(0)
  os.system('gcc -static -m32 -o 18_angr_static_binary ' + temp.name)