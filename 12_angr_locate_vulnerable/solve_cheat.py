#!/usr/bin/pypy

import angr, claripy
import sys, functools
from angr import Hook
from simuvex import SimProcedure

def main():
  proj = angr.Project(sys.argv[1])
  initial_state = proj.factory.entry_state()

  target_str = claripy.BVV('Dsa2mFBx', 8*8)
  class CheckStrcpy(SimProcedure):
    def run(self, dest, src):
      source = self.state.memory.load(src + 8, 8, endness='Iend_LE')
      if self.state.satisfiable(extra_constraints=(source == target_str,)):
        print '----- found path -----'
        print self.state.posix.dumps(0)
        print '--- end found path ---'

  proj.hook_symbol('strcpy', Hook(CheckStrcpy))

  pg = proj.factory.path_group(initial_state, veritesting=False)
  pg.explore(find=lambda p: 'Success.' in p.state.posix.dumps(1))
  print pg
  print repr(pg.found[0].state.posix.dumps(0))

if __name__ == '__main__':
  main()
