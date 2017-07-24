#!/usr/bin/pypy

import angr
import sys

def main():
  proj = angr.Project(sys.argv[1])
  bs = proj.factory.blank_state(addr=0x8048987)
  
  var_eax = bs.se.BVS('eax', 32)
  var_ebx = bs.se.BVS('ebx', 32)
  var_edx = bs.se.BVS('edx', 32)
  bs.regs.eax = var_eax
  bs.regs.ebx = var_ebx
  bs.regs.edx = var_edx
  pg = proj.factory.path_group(bs)
  pg.explore(find=lambda p: 'Success.' in p.state.posix.dumps(1))
  print pg
  print hex(pg.found[0].state.se.any_int(var_eax)), hex(pg.found[0].state.se.any_int(var_ebx)), hex(pg.found[0].state.se.any_int(var_edx))

if __name__ == '__main__':
  main()
