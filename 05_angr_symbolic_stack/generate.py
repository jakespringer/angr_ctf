#!/usr/bin/env python

import sys, random, os, tempfile
from templite import Templite

if len(sys.argv) != 3:
  print 'Usage: pypy generate.py [seed] [output_file]'
  sys.exit()

seed = sys.argv[1]
output_file = sys.argv[2]

random.seed(seed)

description = ''
with open('description.txt', 'r') as desc_file:
  description = desc_file.read().encode('string_escape').replace('\"', '\\\"')

template = open('05_angr_symbolic_stack.c.templite', 'r').read()
c_code = Templite(template).render(description=description)

with tempfile.NamedTemporaryFile(delete=False, suffix='.c') as temp:
  temp.write(c_code)
  temp.seek(0)
  os.system('gcc -fno-stack-protector -m32 -o ' + output_file + ' ' + temp.name)
