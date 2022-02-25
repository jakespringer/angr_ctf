#!/usr/bin/env python3
import sys, random, os, tempfile, jinja2

def randomly_modify(var):
  operator = random.choice(['+=', '^='])
  random_int = random.randint(0, 0xFFFFFFFF)
  return var + operator + str(random_int) + ';'

def generate(argv):
  if len(argv) != 3:
    print('Usage: ./generate.py [seed] [output_file]')
    sys.exit()

  seed = argv[1]
  output_file = argv[2]
  random.seed(seed)

  complex_function_1_string = ''
  for i in range(0, random.randint(16, 48)):
    complex_function_1_string += randomly_modify('input')
  complex_function_2_string = ''
  for i in range(0, random.randint(16, 48)):
    complex_function_2_string += randomly_modify('input')
  complex_function_3_string = ''
  for i in range(0, random.randint(16, 48)):
    complex_function_3_string += randomly_modify('input')

  template = open(os.path.join(os.path.dirname(os.path.realpath(__file__)), '03_angr_symbolic_registers.c.jinja'), 'r').read()
  t = jinja2.Template(template)
  c_code = t.render(description = '', complex_function_1=complex_function_1_string, complex_function_2=complex_function_2_string, complex_function_3=complex_function_3_string)

  with tempfile.NamedTemporaryFile(delete=False, suffix='.c', mode='w') as temp:
    temp.write(c_code)
    temp.seek(0)
    os.system('gcc -fno-pie -no-pie -m32 -o ' + output_file + ' ' + temp.name + ' 2>/dev/null')

if __name__ == '__main__':
  generate(sys.argv)
