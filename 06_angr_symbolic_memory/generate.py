#!/usr/bin/env python

import sys, random, os, tempfile, string
sys.path.append('/home/jake/templite')
from templite import Templite

userdef_charset = [chr(i) for i in range(33, 127)]
userdef = repr(''.join(random.choice(userdef_charset) for _ in range(32)))[1:-1].replace('\"', '\\\"')
padding0 = random.randint(0, 2**26)
padding1 = random.randint(0, 2**26)

# todo: remove & edit above
padding0 = 4
padding1 = 2

template = open('06_angr_symbolic_memory.c.templite', 'r').read()
c_code = Templite(template).render(userdef=userdef, padding0=padding0, padding1=padding1)
print userdef

with tempfile.NamedTemporaryFile(delete=False, suffix='.c') as temp:
  temp.write(c_code)
  temp.seek(0)
  os.system('gcc -m32 -o 06_angr_symbolic_memory ' + temp.name)
