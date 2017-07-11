#!/usr/bin/pypy

import angr
import sys

def main():
  proj = angr.Project(sys.argv[1])
  initial_state = proj.factory.entry_state()
  pg = proj.factory.path_group(initial_state, veritesting=False)
  pg.explore(find=lambda p: 'Success.' in p.state.posix.dumps(1))
  print pg
  print repr(pg.found[0].state.posix.dumps(0))

if __name__ == '__main__':
  main()
