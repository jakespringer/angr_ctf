#!/usr/bin/env python

import sys, random, os, tempfile
sys.path.append('/home/jake/templite')
from templite import Templite

description = ''
with open('description.txt', 'r') as desc_file:
  description = desc_file.read().encode('string_escape')

userdef_charset = '01234567'
userdef = [(''.join(random.choice('0123')) + ''.join(random.choice(userdef_charset) for _ in range(10))) for _ in range(6)]
template = open('09_angr_constraints.c.templite', 'r').read()
c_code = Templite(template).render(description=description, userdef0=userdef[0], userdef1=userdef[1], userdef2=userdef[2], userdef3=userdef[3], userdef4=userdef[4], userdef5=userdef[5])
print '\n'.join([str(int(userdef[i], 8)) for i in range(6)])

with tempfile.NamedTemporaryFile(delete=False, suffix='.c') as temp:
  temp.write(c_code)
  temp.seek(0)
  os.system('gcc -m32 -o 09_angr_constraints ' + temp.name)
