#!/usr/bin/pypy

import angr, claripy
import sys, functools
from angr import Hook
from simuvex import SimProcedure

def main():
  proj = angr.Project(sys.argv[1])
  initial_state = proj.factory.entry_state()

  class IntStrScanf(SimProcedure):
    def run(self, format_str, int_addr, str_addr):
      int_var = claripy.BVS('int_var', 32)
      str_var = claripy.BVS('str_var', 16*8)
      self.state.memory.store(int_addr, int_var, endness='Iend_LE')
      self.state.memory.store(str_addr, str_var, endness='Iend_LE')
      self.state.memory.store(0x4000000, int_var, endness='Iend_LE')
      self.state.memory.store(0x4000004, str_var, endness='Iend_LE')
  
  target_str = claripy.BVV('aaaaaaaa', 8*8)
 
  @Hook.wrap(length=0)
  def check_strcpy(state):
    dest = state.stack_read(offset=4, length=4)
    src = state.stack_read(offset=8, length=4)
    if state.satisfiable(extra_constraints=(state.memory.load(src, 8, endness='Iend_LE') == target_str,)):
      state.memory.store(0x4002000, claripy.BVV(1, 8))
      print '----- found path -----'
      print state.se.any_int(state.memory.load(0x4000000, 4, endness='Iend_LE'))
      print '--- end found path ---'
 
  proj.hook_symbol('__isoc99_scanf', Hook(IntStrScanf))
  proj.hook(0x08048430, check_strcpy)

  initial_state.memory.store(0x4002000, claripy.BVV(0, 8))

  pg = proj.factory.path_group(initial_state, veritesting=False)
  pg.explore(find=lambda p: p.state.se.max(p.state.memory.load(0x4002000, 1)) == 1)
  pg.drop(stash='active')
  pg.move(from_stash='found', to_stash='active')
  pg.explore(find=lambda p: 'Success.' in p.state.posix.dumps(1))
  print pg
  for i in xrange(0, 16):
    chr_solution = pg.found[0].state.memory.load(0x4000004 + i, 1, endness='Iend_LE')
    pg.found[0].state.add_constraints(chr_solution >= 33, chr_solution <= 126)
  print repr(str(pg.found[0].state.se.any_int(pg.found[0].state.memory.load(0x4000000, 4, endness='Iend_LE'))) + ' '
    + pg.found[0].state.se.any_str(pg.found[0].state.memory.load(0x4000004, 32)))

if __name__ == '__main__':
  main()
