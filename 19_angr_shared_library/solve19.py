#!/usr/bin/pypy

import angr
import claripy
import sys
import os

def main():
  base = 0x3000000
  proj = angr.Project(sys.argv[1], load_options={ 'main_opts' : { 'custom_base_addr' : base } })

  str_addr = 0x6000006
  str_len = 8
  initial_state = proj.factory.call_state(base + 0x6c7, claripy.BVV(str_addr, 32), claripy.BVV(str_len, 32))
  
  solution = claripy.BVS('str', 8*8)
  initial_state.memory.store(str_addr, solution)

  pg = proj.factory.path_group(initial_state, veritesting=False)
  pg.explore(find=(base + 0x78e))
  s = pg.found[0].state
  s.add_constraints(s.regs.eax == 0)
  print pg
  print repr(s.se.any_str(solution))

if __name__ == '__main__':
  main()
