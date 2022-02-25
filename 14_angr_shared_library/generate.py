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
  userdef = ''.join(random.choice(userdef_charset) for _ in range(8))

  template = open(os.path.join(os.path.dirname(os.path.realpath(__file__)), '14_angr_shared_library_so.c.jinja'), 'r').read()
  t = jinja2.Template(template)
  c_code = t.render(description='', userdef=userdef, len_userdef=len(userdef))

  with tempfile.NamedTemporaryFile(delete=False, suffix='.c', mode='w') as temp:
    temp.write(c_code)
    temp.seek(0)
    os.system('gcc -I' + os.path.dirname(os.path.realpath(__file__))  + ' -fno-stack-protector -fpic -m32 -c -o 14_angr_shared_library.o ' + temp.name)
    os.system('gcc -shared -m32 -o ' + os.path.join('/'.join(output_file.split('/')[0:-1]), 'lib' + output_file.split('/')[-1] + '.so') + ' 14_angr_shared_library.o')
    os.system('rm 14_angr_shared_library.o')
    os.system('chmod -x ' + os.path.join('/'.join(output_file.split('/')[0:-1]), 'lib' + output_file.split('/')[-1] + '.so'))

  c_code = open(os.path.join(os.path.dirname(os.path.realpath(__file__)), '14_angr_shared_library.c'), 'r').read()

  with tempfile.NamedTemporaryFile(delete=False, suffix='.c', mode='w') as temp:
    temp.write(c_code)
    temp.seek(0)
    os.system('gcc -fno-pie -no-pie -m32 -Wl,-R . -I . -L ' + '/'.join(output_file.split('/')[0:-1]) + ' -o ' + output_file + ' ' + temp.name + ' -l' + output_file.split('/')[-1])

if __name__ == '__main__':
  generate(sys.argv)
