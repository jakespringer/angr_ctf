import binascii
import sys
import random
import os
import tempfile
from templite import Templite


def generate(argv):
  if len(argv) != 3:
    print('Usage: ./generate.py [seed] [output_file]')
    sys.exit()

  seed = argv[1]
  output_file = argv[2]

  random.seed(seed)

  rodata_tail_modifier = 0x14
  rodata_parts = ''.join([chr(random.randint(ord('A'), ord('Z'))) for _ in range(3)]
                         + [chr(random.randint(ord('A') - rodata_tail_modifier, ord('Z') - rodata_tail_modifier))])
  rodata_address = '0x' + binascii.hexlify(rodata_parts.encode('utf8')).decode('utf8')

  description = ''
  with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'description.txt'), 'r') as desc_file:
    description = desc_file.read().encode('unicode_escape')

  template = open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'main.c.templite'), 'r').read()
  c_code = Templite(template).render(description=description)

  with tempfile.NamedTemporaryFile(delete=False, suffix='.c', mode='w') as temp:
    temp.write(c_code)
    temp.seek(0)
    os.system('gcc -m32 -fno-stack-protector -Wl,--section-start=.rodata=' +
              rodata_address + ' -o ' + output_file + ' ' + temp.name)


if __name__ == '__main__':
  generate(sys.argv)
