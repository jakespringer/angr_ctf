#!/usr/bin/pypy

import angr, claripy
import sys

def main():
  proj = angr.Project(sys.argv[1])
  ss = proj.factory.blank_state(addr=0x8048687)
  ss.regs.ebp = ss.regs.esp
  ss.stack_push(0x8048687)
  global_var = 0x804b1c8



  # todo: store as little endian (with the value above it doesn't matter)
  ss.memory.store(global_var, data, endness=proj.arch.memory_endness)
  param0 = ss.memory.load(data, 8)
  param1 = ss.memory.load(data + 8, 8)
  param2 = ss.memory.load(data + 16, 8)
  param3 = ss.memory.load(data + 24, 8)
  pg = proj.factory.path_group(ss)
  pg.explore(find=lambda p: 'Success.' in p.state.posix.dumps(1))
  s = pg.found[0].state
  print pg.found[0].state.se.any_str(param0) + ' ' + pg.found[0].state.se.any_str(param1) + ' ' + pg.found[0].state.se.any_str(param2) + ' ' + pg.found[0].state.se.any_str(param3)

if __name__ == '__main__':
  main()
