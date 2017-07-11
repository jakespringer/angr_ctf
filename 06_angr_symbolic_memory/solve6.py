#!/usr/bin/pypy

import angr, claripy
import sys

def main():
  proj = angr.Project(sys.argv[1])
  initial_state = proj.factory.blank_state(addr=0x804860f)
  param0 = claripy.BVS('userinput0', 8*8)
  param1 = claripy.BVS('userinput1', 8*8)
  param2 = claripy.BVS('userinput2', 8*8)
  param3 = claripy.BVS('userinput3', 8*8)
  global_var = 0x804a0a0
  initial_state.memory.store(global_var, param0)
  initial_state.memory.store(global_var + 8, param1)
  initial_state.memory.store(global_var + 16, param2)
  initial_state.memory.store(global_var + 24, param3)
  pg = proj.factory.path_group(initial_state)
  pg.explore(find=lambda p: 'Success.' in p.state.posix.dumps(1))
  #print pg
  print (pg.found[0].state.se.any_str(param0) + ' ' + pg.found[0].state.se.any_str(param1) + ' ' + pg.found[0].state.se.any_str(param2) + ' ' + pg.found[0].state.se.any_str(param3))

if __name__ == '__main__':
  main()
