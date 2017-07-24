#!/usr/bin/pypy

import angr, claripy
import sys, functools
from angr import Hook
from simuvex import SimProcedure

def compose(*functions):
  return functools.reduce(lambda f, g: lambda x: f(g(x)), functions, lambda x: x)

def main():
  proj = angr.Project(sys.argv[1])
  ss = proj.factory.entry_state()

  class TwoIntScanf(SimProcedure):
    def run(self, string, int0, int1):
      bvs_str = claripy.BVS('var_str', 8*4)
      bvs_int = claripy.BVS('var_int', 8*4)
      self.state.memory.store(int0, bvs_str, endness='Iend_LE')
      self.state.memory.store(int1, bvs_int, endness='Iend_LE')

      num_elements = self.state.memory.load(0x4000000, 4)
      self.state.memory.store(0x4000004 + (num_elements * 4), bvs_str)
      self.state.memory.store(0x4000008 + (num_elements * 4), bvs_int)
      self.state.memory.store(0x4000000, num_elements + 2)

  proj.hook_symbol('__isoc99_scanf', Hook(TwoIntScanf))
  ss.memory.store(0x4000000, claripy.BVV(0x0, 32))

  pg = proj.factory.path_group(ss)
  pg.explore(find=lambda p: 'Success.' in p.state.posix.dumps(1))
  print pg
  s = pg.found[0].state
  solution = []
  for i in xrange(0, s.se.any_int(s.memory.load(0x4000000, 4)), 2):
    solution.append(s.memory.load(0x4000004 + (i * 4), 4))
    solution.append(s.memory.load(0x4000008 + (i * 4), 4))

  print ' '.join(map(compose(str, s.se.any_int), solution))

if __name__ == '__main__':
  main()
