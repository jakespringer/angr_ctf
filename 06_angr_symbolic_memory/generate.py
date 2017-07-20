#!/usr/bin/env python

import sys, random, os, tempfile, string
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

padding0 = random.randint(0, 2**26)
padding1 = random.randint(0, 2**26)

template = open('06_angr_symbolic_memory.c.templite', 'r').read()
c_code = Templite(template).render(description=description, padding0=padding0, padding1=padding1)

with tempfile.NamedTemporaryFile(delete=False, suffix='.c') as temp:
  temp.write(c_code)
  temp.seek(0)
  os.system('gcc -m32 -o 06_angr_symbolic_memory ' + temp.name)
