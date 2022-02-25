#!/usr/bin/env python3
import sys, random, os, tempfile, jinja2

def check_string_recursive(array0, array1, random_list, bit):
  if bit < 0:
    return f'maybe_good({array0}, {array1});'
  else:
    if random_list[0]:
      ret_str = f'if (CHECK_BIT({array0}, {bit}) == CHECK_BIT({array1}, {bit}))' + '{' + check_string_recursive(array0, array1, random_list[1:], bit-1) + '} else { avoid_me(); ' + check_string_recursive(array0, array1, random_list[1:], bit-1) + '}'
    else:
      ret_str = f'if (CHECK_BIT({array0}, {bit}) != CHECK_BIT({array1}, {bit}))' + '{ avoid_me();' + check_string_recursive(array0, array1, random_list[1:], bit-1) + '} else { ' + check_string_recursive(array0, array1, random_list[1:], bit-1) + '}'
    return ret_str

def generate(argv):
  if len(argv) != 3:
    print('Usage: ./generate.py [seed] [output_file]')
    sys.exit()

  seed = argv[1]
  output_file = argv[2]
  random.seed(seed)

  description = ''

  random_list = [random.choice([True, False]) for _ in range(64)]
  userdef_charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
  userdef = ''.join(random.choice(userdef_charset) for _ in range(8))
  random_list = [random.choice([True, False]) for _ in range(64)]
  check_string = check_string_recursive('buffer', 'password', random_list, 12)

  template = open(os.path.join(os.path.dirname(os.path.realpath(__file__)), '01_angr_avoid.c.jinja'), 'r').read()
  t = jinja2.Template(template)
  c_code = t.render(userdef=userdef, len_userdef=len(userdef), description = '', check_string=check_string)

  with tempfile.NamedTemporaryFile(delete=False, suffix='.c', mode='w') as temp:
    temp.write(c_code)
    temp.seek(0)
    os.system('gcc -fno-pie -no-pie -m32 -o ' + output_file + ' ' + temp.name)

if __name__ == '__main__':
  generate(sys.argv)
