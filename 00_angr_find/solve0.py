#!/usr/bin/pypy

import angr
import sys
import os

def main():
  proj = angr.Project(sys.argv[1])
  initial_state = proj.factory.entry_state()
  pg = proj.factory.path_group(initial_state, veritesting=False)
  pg.explore(find=0x804866c)
  print pg
  print repr(pg.found[0].state.posix.dumps(0))

if __name__ == '__main__':
  main()
