#!/usr/bin/env python

import sys, random, os, tempfile
from templite import Templite

def generate(argv):
  if len(sys.argv) != 3:
    print 'Usage: pypy generate.py [seed] [output_file]'
    sys.exit()

  seed = sys.argv[1]
  output_file = sys.argv[2]

  random.seed(seed)

  description = ''
  with open('description.txt', 'r') as desc_file:
    description = desc_file.read().encode('string_escape').replace('\"', '\\\"')

  template = open('19_angr_shared_library_so.c.templite', 'r').read()
  c_code = Templite(template).render(description=description)

  with tempfile.NamedTemporaryFile(delete=False, suffix='.c') as temp:
    temp.write(c_code)
    temp.seek(0)
    os.system('gcc -fno-stack-protector -fpic -m32 -c -o 19_angr_shared_library.o ' + temp.name)
    os.system('gcc -shared -m32 -o ' + '/'.join(output_file.split('/')[0:-1]) + 'lib' + output_file.split('/')[-1] + '.so 19_angr_shared_library.o')
    os.system('rm 19_angr_shared_library.o')
    os.system('chmod -x ' + '/'.join(output_file.split('/')[0:-1]) + 'lib' + output_file.split('/')[-1] + '.so')

  template = open('19_angr_shared_library.c.templite', 'r').read()
  c_code = Templite(template).render()

  with tempfile.NamedTemporaryFile(delete=False, suffix='.c') as temp:
    temp.write(c_code)
    temp.seek(0)
    os.system('gcc -m32 -I . -L . -o ' + output_file + ' ' + temp.name + ' -l' + output_file.split('/')[-1])

if __name__ == '__main__':
  generate(sys.argv)
