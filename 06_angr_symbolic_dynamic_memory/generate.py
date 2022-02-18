#!/usr/bin/env python3

import sys, random, os, tempfile, string
from templite import Templite

def generate(argv):
  if len(argv) != 3:
    print('Usage: ./generate.py [seed] [output_file]')
    sys.exit()

  seed = argv[1]
  output_file = argv[2]

  random.seed(seed)

  description = ''
  with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'description.txt'), 'r') as desc_file:
    description = desc_file.read().encode('unicode_escape')

  padding = random.randint(0, 2**26)

  template = open(os.path.join(os.path.dirname(os.path.realpath(__file__)), '06_angr_symbolic_dynamic_memory.c.templite'), 'r').read()
  c_code = Templite(template).render(description=description, padding=padding)

  with tempfile.NamedTemporaryFile(delete=False, suffix='.c', mode='w') as temp:
    temp.write(c_code)
    temp.seek(0)
    os.system('gcc -fno-pie -no-pie -m32 -o ' + output_file + ' ' + temp.name)

if __name__ == '__main__':
  generate(sys.argv)
