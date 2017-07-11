#!/usr/bin/pypy

import angr, claripy, simuvex
import sys

def main():
  proj = angr.Project(sys.argv[1])
  ss = proj.factory.blank_state(addr=0x80488e4)
  
  filename = 'Fg9eOyBX.txt'
  bytes_len = 8
  password = claripy.BVS('password', bytes_len * 8)
  content = simuvex.SimSymbolicMemory(memory_id="file_%s" % filename)
  content.set_state(ss)
  content.store(0, password)

  password_file = simuvex.SimFile(filename, 'rw', content=content, size=bytes_len*8)

  fs = {
    filename: password_file
  }

  ss.posix.fs = fs
  
  pg = proj.factory.path_group(ss)
  #pg.explore(find=lambda p: 'Success.' in p.state.posix.dumps(1), avoid=0x8048520)
  pg.explore(find=0x8048987, avoid=0x80485a0)
  print pg

  for e in pg.errored:
    print list(e.trace)
    e.retry()  

  for a in pg.avoid:
    print '\n'.join(list(a.trace))

  s = pg.found[0].state
  print s.se.any_str(password)

if __name__ == '__main__':
  main()
