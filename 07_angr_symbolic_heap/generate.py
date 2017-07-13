#!/usr/bin/env python

import sys, random, os, tempfile, string
sys.path.append('/home/jake/templite')
from templite import Templite

description = ''
with open('description.txt', 'r') as desc_file:
  description = desc_file.read().encode('string_escape')

userdef_charset = [chr(i) for i in range(33, 127)]
userdef = repr(''.join(random.choice(userdef_charset) for _ in range(32)))[1:-1].replace('\"', '\\\"')
padding2 = random.randint(0, 2**26)

# todo: remove & edit above
padding2 = 8

template = open('07_angr_symbolic_heap.c.templite', 'r').read()
c_code = Templite(template).render(description=description, userdef=userdef, padding2=padding2)
print userdef

with tempfile.NamedTemporaryFile(delete=False, suffix='.c') as temp:
  temp.write(c_code)
  temp.seek(0)
  os.system('gcc -m32 -o 07_angr_symbolic_heap ' + temp.name)
