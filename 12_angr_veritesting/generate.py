#!/usr/bin/env python3
import sys, random, os, tempfile, jinja2

def generate(argv):
  if len(argv) != 3:
    print('Usage: ./generate.py [seed] [output_file]')
    sys.exit()

  seed = argv[1]
  output_file = argv[2]
  random.seed(seed)

  letter0 = random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
  integer = random.randint(0, 256)
  lamb = random.choice([2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71])


  template = open(os.path.join(os.path.dirname(os.path.realpath(__file__)), '12_angr_veritesting.c.jinja'), 'r').read()
  t = jinja2.Template(template)
  c_code = t.render(description='', integer=integer, letter0=letter0, lamb=lamb)

  with tempfile.NamedTemporaryFile(delete=False, suffix='.c', mode='w') as temp:
    temp.write(c_code)
    temp.seek(0)
    os.system('gcc -fno-pie -no-pie -m32 -o ' + output_file + ' ' + temp.name)

if __name__ == '__main__':
  generate(sys.argv)
