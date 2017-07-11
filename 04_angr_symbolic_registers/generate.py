#!/usr/bin/env python

import sys, random, os, tempfile
sys.path.append('/home/jake/templite')
from templite import Templite

template = open('04_angr_symbolic_registers.c.templite', 'r').read()
c_code = Templite(template).render()

with tempfile.NamedTemporaryFile(delete=False, suffix='.c') as temp:
  temp.write(c_code)
  temp.seek(0)
  os.system('gcc -m32 -o 04_angr_symbolic_registers ' + temp.name)
