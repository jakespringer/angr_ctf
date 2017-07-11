#!/usr/bin/pypy

import angr, claripy
import sys, functools
from angr import Hook

def compose(*functions):
  return functools.reduce(lambda f, g: lambda x: f(g(x)), functions, lambda x: x)

def main():
  proj = angr.Project(sys.argv[1])
  ss = proj.factory.entry_state()


  @Hook.wrap(length=5)
  def skip_scanf(state):
    bvs_str = claripy.BVS('var_str', 8*4)
    bvs_int = claripy.BVS('var_int', 8*4)
    state.memory.store(0x804a050, bvs_str, endness='Iend_LE')
    state.memory.store(0x804a058, bvs_int, endness='Iend_LE')
    
    num_elements = state.memory.load(0x4000000, 4)
    state.memory.store(0x4000004 + (num_elements * 4), bvs_str)
    state.memory.store(0x4000008 + (num_elements * 4), bvs_int)
    state.memory.store(0x4000000, num_elements + 2)

  proj.hook(0x8048737, skip_scanf)
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
