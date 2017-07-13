#!/usr/bin/pypy

import angr
import sys
import simuvex

def main():
  proj = angr.Project(sys.argv[1])
  
  proj.hook(0x804edb0, angr.Hook(simuvex.SimProcedures['libc.so.6']['__isoc99_scanf']))
  proj.hook(0x804ed70, angr.Hook(simuvex.SimProcedures['libc.so.6']['printf']))
  proj.hook(0x804f380, angr.Hook(simuvex.SimProcedures['libc.so.6']['puts']))

  initial_state = proj.factory.blank_state(addr=0x080488d5, add_options={"BYPASS_UNSUPPORTED_SYSCALL"})
  pg = proj.factory.path_group(initial_state)

  pg.explore(find=lambda path: "Success." in path.state.posix.dumps(1))
  print pg
  print repr(pg.found[0].state.posix.dumps(0))

if __name__ == '__main__':
  main()
