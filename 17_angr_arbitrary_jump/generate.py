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

  text_tail_modifier0 = 0x10
  text_tail_modifier1 = 0x01
  text_parts = ''.join([ chr(random.randint(ord('A'), ord('Z'))) for _ in range(2) ]
    + [ chr(random.randint(ord('A') - text_tail_modifier1, ord('Z') - text_tail_modifier1)) ]
    + [ chr(random.randint(ord('A') - text_tail_modifier0, ord('Z') - text_tail_modifier0)) ])
  text_address = '0x' + text_parts.encode('utf-8').hex()

  with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'description.txt'), 'r') as desc_file:
    description = desc_file.read().strip()

  with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), '17_angr_arbitrary_jump.c.templite'), 'r') as temp_file:
    template = temp_file.read()

  c_code = Templite(template).render(description=description)

  with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.c') as temp:
    temp.write(c_code)
    temp.seek(0)
    os.system('gcc -fno-stack-protector -Wl,--section-start=.text=' + text_address + ' -m32 -o ' + output_file + ' ' + temp.name)

if __name__ == '__main__':
  generate(sys.argv)
