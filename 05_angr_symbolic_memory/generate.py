#!/usr/bin/env python3
import sys, random, os, tempfile, jinja2

def generate(argv):
  if len(argv) != 3:
    print('Usage: ./generate.py [seed] [output_file]')
    sys.exit()

  seed = argv[1]
  output_file = argv[2]
  random.seed(seed)

  userdef_charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
  userdef = repr(''.join(random.choice(userdef_charset) for _ in range(32)))[1:-1].replace('\"', '\\\"')
  padding0 = random.randint(0, 2**26)
  padding1 = random.randint(0, 2**26)

  template = open(os.path.join(os.path.dirname(os.path.realpath(__file__)), '05_angr_symbolic_memory.c.jinja'), 'r').read()
  t = jinja2.Template(template)
  c_code = t.render(description='', padding0=padding0, padding1=padding1, userdef=userdef)

  with tempfile.NamedTemporaryFile(delete=False, suffix='.c', mode='w') as temp:
    temp.write(c_code)
    temp.seek(0)
    os.system('gcc -fno-pie -no-pie -m32 -o ' + output_file + ' ' + temp.name)

if __name__ == '__main__':
  generate(sys.argv)
