#!/usr/bin/env python

import sys, random, os, tempfile
sys.path.append('/home/jake/templite')
from templite import Templite

userdef_charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
userdef = ''.join(random.choice(userdef_charset) for _ in range(8))
template = open('lib19_angr_shared_library.so.c.templite', 'r').read()
c_code = Templite(template).render(USERDEF=userdef)

with tempfile.NamedTemporaryFile(delete=False, suffix='.c') as temp:
  temp.write(c_code)
  temp.seek(0)
  os.system('gcc -static -fpic -shared -m32 -o lib19_angr_shared_library.so ' + temp.name)

template = open('19_angr_shared_library.c.templite', 'r').read()
c_code = Templite(template).render()

with tempfile.NamedTemporaryFile(delete=False, suffix='.c') as temp:
  temp.write(c_code)
  temp.seek(0)
  os.system('gcc -m32 -L . -l19_angr_shared_library -o 19_angr_shared_library ' + temp.name)
