#!/usr/bin/env python3
import binascii, sys, random, os, tempfile, jinja2

def expanded_switch_statement(variable, miss_statement, hit_statement, samples):
  target = random.choice(samples)

  ret_str = 'switch (%s) {' % (variable,)
  for sample in samples:
    ret_str += 'case %d: %s; break;' % (sample, hit_statement if sample == target else miss_statement)
  ret_str += 'default: %s; break; }' % (miss_statement,)
  return ret_str

def generate(argv):
  if len(argv) != 3:
    print('Usage: ./generate.py [seed] [output_file]')
    sys.exit()

  seed = argv[1]
  output_file = argv[2]

  random.seed(seed)
  
#  cs492 branch
#  rodata_tail_modifier = 0x30 
#  rodata_parts = ''.join([ chr(random.randint(ord('A'), ord('Z'))) for _ in xrange(3) ] + [ chr(random.randint(0,16) + rodata_tail_modifier) ])
  rodata_tail_modifier = 0x14 
  rodata_parts = ''.join([ chr(random.randint(ord('A'), ord('Z'))) for _ in range(3) ] 
    + [ chr(random.randint(ord('A') - rodata_tail_modifier, ord('Z') - rodata_tail_modifier)) ])
  rodata_address = '0x' + binascii.hexlify(rodata_parts.encode('utf8')).decode('utf8')

  hit_statement = 'puts(locals.to_print);'
  miss_statement = 'puts(try_again);'
  expanded_switch_statement_string = expanded_switch_statement('key', miss_statement, hit_statement, random.sample(range(2**26-1), 2))

  template = open(os.path.join(os.path.dirname(os.path.realpath(__file__)), '15_angr_arbitrary_read.c.jinja'), 'r').read()
  t = jinja2.Template(template)
  c_code = t.render(description='', expanded_switch_statement=expanded_switch_statement_string)

  with tempfile.NamedTemporaryFile(delete=False, suffix='.c', mode='w') as temp:
    temp.write(c_code)
    temp.seek(0)
    os.system('gcc -fno-pie -no-pie -m32 -fno-stack-protector -Wl,--section-start=.rodata=' + rodata_address + ' -o ' + output_file + ' ' + temp.name)

if __name__ == '__main__':
  generate(sys.argv)
