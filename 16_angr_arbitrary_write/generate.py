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

  rodata_tail_modifier = 0x2c
  rodata_parts = ''.join([ chr(random.randint(ord('A'), ord('Z'))) for _ in range(3) ]
    + [ chr(random.randint(ord('A') - rodata_tail_modifier, ord('Z') - rodata_tail_modifier)) ])
  rodata_address = '0x' + rodata_parts.encode('utf-8').hex()

  userdef_charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
  userdef = ''.join(random.choice(userdef_charset) for _ in range(8))

  with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'description.txt'), 'r') as desc_file:
    description = desc_file.read().strip()

  with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), '16_angr_arbitrary_write.c.templite'), 'r') as temp_file:
    template = temp_file.read()

  c_code = Templite(template).render(description=description, userdef=userdef)

  with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.c') as temp:
    temp.write(c_code)
    temp.seek(0)
    os.system('gcc -m32 -fno-stack-protector -Wl,--section-start=.data=' + rodata_address + ' -o ' + output_file + ' ' + temp.name)

if __name__ == '__main__':
  generate(sys.argv)
