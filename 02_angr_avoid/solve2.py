#!/usr/bin/pypy

import angr
import sys

def main():
  proj = angr.Project(sys.argv[1])
  initial_state = proj.factory.entry_state()
  pg = proj.factory.path_group(initial_state)
  pg.explore(find=0x8048698, avoid=0x80484bb)
  print pg
  print pg.found[0].state.posix.dumps(0)

if __name__ == '__main__':
  main()
