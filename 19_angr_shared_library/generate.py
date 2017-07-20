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

template = open('19_angr_shared_library_so.c.templite', 'r').read()
c_code = Templite(template).render(description=description)

with tempfile.NamedTemporaryFile(delete=False, suffix='.c') as temp:
  temp.write(c_code)
  temp.seek(0)
  os.system('gcc -fno-stack-protector -fpic -m32 -c -o 19_angr_shared_library.o ' + temp.name)
  os.system('gcc -shared -m32 -o lib19_angr_shared_library.so 19_angr_shared_library.o')
  os.system('rm 19_angr_shared_library.o')
  os.system('chmod -x lib19_angr_shared_library.so')

template = open('19_angr_shared_library.c.templite', 'r').read()
c_code = Templite(template).render()

with tempfile.NamedTemporaryFile(delete=False, suffix='.c') as temp:
  temp.write(c_code)
  temp.seek(0)
  os.system('gcc -m32 -I . -L . -o 19_angr_shared_library ' + temp.name + ' -l19_angr_shared_library')
