#!/usr/bin/pypy

import angr, claripy
import sys, functools
from angr import Hook
from simuvex import SimProcedure

def main():
  proj = angr.Project(sys.argv[1])
  es = proj.factory.entry_state()

  #print_success_addr = proj.kb.labels.lookup('print_success')
  print_success_addr = 0x34343434

  def fully_symbolic(state, variable, length):
    for i in xrange(length):
      if not state.se.symbolic(variable[i]):
        return False
    return True

  def check_unconstrained(state):
    if fully_symbolic(state, state.regs.eip, 32):
      print 'found unconstrained state'
      return True
    else:
      return False

  #class CharScanf(SimProcedure):
  #  def run(self, format_str, char_addr):
  #    bvs_char = claripy.BVS('char', 8)
  #    self.state.memory.store(char_addr, bvs_char, endness='Iend_LE')
  #    num_elements = self.state.memory.load(0x4000000, 4)
  #    self.state.memory.store(0x4000004 + num_elements, bvs_char)
  #    self.state.memory.store(0x4000000, num_elements + 1)
  #
  #proj.hook_symbol('__isoc99_scanf', Hook(CharScanf))
  #es.memory.store(0x4000000, claripy.BVV(0x0, 32))

  pg = proj.factory.path_group(es, save_unconstrained=True)

  while len(pg.active) > 0 or len(pg.unconstrained) > 0:
    for uncstr in pg.unconstrained:
      print 'found unconstrained, determining if eip is symbolic'
      if check_unconstrained(uncstr.state):
        pg.drop(stash='active')
        pg.move(from_stash='unconstrained', to_stash='found', filter_func=lambda p: p == uncstr)
        break
    else:
      pg.drop(stash='unconstrained')
      pg.step()
      continue
    break 

  print pg
  found_s = pg.found[0].state
  found_s.add_constraints(found_s.regs.eip == print_success_addr)
  print repr(found_s.posix.dumps(0))
  #pg.explore(find=lambda p: 'Success.' in p.state.posix.dumps(1))
  #solution = []
  #for i in xrange(0, found_s.se.any_int(s.memory.load(0x4000000, 4))):
  #  solution.append(found_s.memory.load(0x4000004 + i, 1))
  #print ''.join(map(found_s.se.any_str, solution))

if __name__ == '__main__':
  main()
