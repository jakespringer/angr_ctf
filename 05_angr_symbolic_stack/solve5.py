#!/usr/bin/pypy

import angr
import claripy
import sys

def main():
  proj = angr.Project(sys.argv[1])
  bs = proj.factory.blank_state(addr=0x80485c4)
  
  var_int = bs.se.BVS('int', 32)
  var_str = [bs.se.BVS('str', 8*4) for _ in range(16/4)]

  bs.regs.ebp = bs.regs.esp

  for _ in range(2):
    bs.stack_push(claripy.BVV(0x0, 32))

  bs.stack_push(var_int)
  for var_chr in var_str:
    bs.stack_push(var_chr)

  pg = proj.factory.path_group(bs)
  pg.explore(find=lambda p: 'Success.' in p.state.posix.dumps(1), avoid=lambda p: 'Try again.' in p.state.posix.dumps(1))
  s = pg.found[0].state
  print pg
  print repr(str(s.se.any_int(var_int)) + ' ' + ''.join(map(s.se.any_str, var_str))[::-1])

if __name__ == '__main__':
  main()
