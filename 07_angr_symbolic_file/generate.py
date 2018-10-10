#!/usr/bin/env pypy

import sys, random, os, tempfile
from templite import Templite

def generate(argv):
  if len(argv) != 3:
    print('Usage: pypy generate.py [seed] [output_file]')
    sys.exit()

  seed = argv[1]
  output_file = argv[2]

  random.seed(seed)

  with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'description.txt'), 'r') as desc_file:
    description = desc_file.read().strip()

  userdef_charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
  userdef1 = ''.join(random.choice(userdef_charset) for _ in range(8))
  with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), '07_angr_symbolic_file.c.templite'), 'r') as temp_file:
    template = temp_file.read()

  c_code = Templite(template).render(description=description, userdef1=userdef1)

  with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.c') as temp:
    temp.write(c_code)
    temp.seek(0)
    os.system('gcc -m32 -o ' + output_file + ' ' + temp.name)

if __name__ == '__main__':
  generate(sys.argv)
