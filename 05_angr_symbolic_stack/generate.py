#!/usr/bin/env python

import sys, random, os, tempfile
sys.path.append('/home/jake/templite')
from templite import Templite

description = ''
with open('description.txt', 'r') as desc_file:
  description = desc_file.read().encode('string_escape').replace('\"', '\\\"')

userdef0 = random.randint(0, 0xFFFFFFFF)
userdef1 = random.randint(0, 0xFFFFFFFF)
userdef2 = random.randint(0, 0xFFFFFFFF)
userdef3 = random.randint(0, 0xFFFFFFFF)
template = open('05_angr_symbolic_stack.c.templite', 'r').read()
c_code = Templite(template).render(description=description, userdef0=userdef0, userdef1=userdef1, userdef2=userdef2, userdef3=userdef3)

with tempfile.NamedTemporaryFile(delete=False, suffix='.c') as temp:
  temp.write(c_code)
  temp.seek(0)
  os.system('gcc -fno-stack-protector -m32 -o 05_angr_symbolic_stack ' + temp.name)
