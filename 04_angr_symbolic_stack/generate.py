#!/usr/bin/env python3
import sys, random, os, tempfile, jinja2

def generate(argv):
  if len(argv) != 3:
    print('Usage: ./generate.py [seed] [output_file]')
    sys.exit()

  seed = argv[1]
  output_file = argv[2]
  random.seed(seed)

  userdef0 = random.randint(0, 0xFFFFFFFF)
  userdef1 = random.randint(0, 0xFFFFFFFF)
  complex_function0_string = ''.join([ (f'value ^= {random.randint(0,0xFFFFFFFF)};') for _ in range(32) ])
  complex_function1_string = ''.join([ (f'value ^= {random.randint(0,0xFFFFFFFF)};') for _ in range(32) ])

  template = open(os.path.join(os.path.dirname(os.path.realpath(__file__)), '04_angr_symbolic_stack.c.jinja'), 'r').read()
  t = jinja2.Template(template)
  c_code = t.render(description = '', complex_function0=complex_function0_string, complex_function1=complex_function1_string, userdef0=userdef0, userdef1=userdef1)

  with tempfile.NamedTemporaryFile(delete=False, suffix='.c', mode='w') as temp:
    temp.write(c_code)
    temp.seek(0)
    os.system('gcc -fno-stack-protector -fno-pie -no-pie -m32 -o ' + output_file + ' ' + temp.name + ' 2>/dev/null')

if __name__ == '__main__':
  generate(sys.argv)


