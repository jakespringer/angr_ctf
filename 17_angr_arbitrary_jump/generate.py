#!/usr/bin/env python3
import binascii, sys, random, os, tempfile, jinja2

def generate(argv):
  if len(argv) != 3:
    print('Usage: ./generate.py [seed] [output_file]')
    sys.exit()

  seed = argv[1]
  output_file = argv[2]
  random.seed(seed)

# cs492
#  text_tail_modifier0 = 0x05
  text_tail_modifier0 = 0x30
  text_tail_modifier1 = 0x01
  text_parts = ''.join([ chr(random.randint(ord('A'), ord('Z'))) for _ in range(2) ]
    + [ chr(random.randint(ord('A') - text_tail_modifier1, ord('Z') - text_tail_modifier1)) ]
    + [ chr(random.randint(ord('A') - text_tail_modifier0, ord('Z') - text_tail_modifier0)) ])
  text_address = '0x' + binascii.hexlify(text_parts.encode('utf8')).decode('utf8')

  padding0 = random.randint(0, 32)
  padding1 = random.randint(0, 32)

  template = open(os.path.join(os.path.dirname(os.path.realpath(__file__)), '17_angr_arbitrary_jump.c.jinja'), 'r').read()
  t = jinja2.Template(template)
  c_code = t.render(description='', padding0=padding0, padding1=padding1)

  with tempfile.NamedTemporaryFile(delete=False, suffix='.c', mode='w') as temp:
    temp.write(c_code)
    temp.seek(0)
    os.system('gcc -fno-stack-protector -Wl,--section-start=.text=' + text_address + ' -fno-pie -no-pie -m32 -o ' + output_file + ' ' + temp.name)

if __name__ == '__main__':
  generate(sys.argv)
