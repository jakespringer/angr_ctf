#!/usr/bin/env python

import sys, random, os, tempfile
sys.path.append('/home/jake/templite')
from templite import Templite

description = ''
with open('description.txt', 'r') as desc_file:
  description = desc_file.read().encode('string_escape').replace('\"', '\\\"')

template = open('13_angr_unconstrained.c.templite', 'r').read()
c_code = Templite(template).render(description=description)
with tempfile.NamedTemporaryFile(delete=False, suffix='.c') as temp:
  temp.write(c_code)
  temp.seek(0)
  os.system('gcc -fno-stack-protector -Wl,--section-start=.text=0x34343434 -m32 -o 13_angr_unconstrained ' + temp.name)
