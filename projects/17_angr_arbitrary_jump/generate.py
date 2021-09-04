import binascii
import os
import random
import sys
import tempfile

from templite import Templite


def generate(argv):
  if len(argv) != 3:
    print('Usage: ./generate.py [seed] [output_file]')
    sys.exit()

  seed = argv[1]
  output_file = argv[2]

  random.seed(seed)

  text_tail_modifier0 = 0x10
  text_tail_modifier1 = 0x01
  text_parts = ''.join([chr(random.randint(ord('A'), ord('Z'))) for _ in range(2)]
                       + [chr(random.randint(ord('A') - text_tail_modifier1, ord('Z') - text_tail_modifier1))]
                       + [chr(random.randint(ord('A') - text_tail_modifier0, ord('Z') - text_tail_modifier0))])
  text_address = '0x' + binascii.hexlify(text_parts.encode('utf8')).decode('utf8')

  description = ''
  with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'description.txt'), 'r') as desc_file:
    description = desc_file.read().encode('unicode_escape')

  template = open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'main.c.templite'), 'r').read()
  c_code = Templite(template).render(description=description)

  with tempfile.NamedTemporaryFile(delete=False, suffix='.c', mode='w') as temp:
    temp.write(c_code)
    temp.seek(0)
    os.system('gcc -fno-stack-protector -Wl,--section-start=.text=' +
              text_address + ' -m32 -o ' + output_file + ' ' + temp.name)


if __name__ == '__main__':
  generate(sys.argv)
