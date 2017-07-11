#!/usr/bin/env python

import sys, random, os, tempfile
sys.path.append('/home/jake/templite')
from templite import Templite

template = open('02_angr_avoid.c.templite', 'r').read()
c_code = Templite(template).render(USERDEF0=random.randint(0, 0xFFFF), 
  USERDEF1=random.randint(0, 0xFFFF), USERDEF2=random.randint(0, 0xFFFF),
  USERDEF3=random.randint(0, 0xFFFF), USERDEF4=random.randint(0, 0xFFFF),
  USERDEF5=random.randint(0, 0xFFFF))

with tempfile.NamedTemporaryFile(delete=False, suffix='.c') as temp:
  temp.write(c_code)
  temp.seek(0)
  os.system('gcc -m32 -o 02_angr_avoid ' + temp.name)
