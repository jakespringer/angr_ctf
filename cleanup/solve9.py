#!/usr/bin/pypy

import angr, claripy, simuvex
import sys

def main():
  proj = angr.Project(sys.argv[1])
  ss = proj.factory.blank_state(addr=0x8048708)
  
  a = claripy.BVS('a', 32)
  b = claripy.BVS('b', 32)
  c = claripy.BVS('c', 32)
  d = claripy.BVS('d', 32)
  e = claripy.BVS('e', 32)
  f = claripy.BVS('f', 32)

  ss.memory.store(0x804a07c, a, endness='Iend_LE')
  ss.memory.store(0x804a064, b, endness='Iend_LE')
  ss.memory.store(0x804a078, c, endness='Iend_LE')
  ss.memory.store(0x804a060, d, endness='Iend_LE')
  ss.memory.store(0x804a074, e, endness='Iend_LE')
  ss.memory.store(0x804a068, f, endness='Iend_LE')

  pg = proj.factory.path_group(ss)
  pg.explore(find=0x8048767)
  print pg

  for e in pg.errored:
    print '\n'.join(list(e.trace))
    e.retry()  

  s = pg.found[0].state
  
  def read(addr):
    return s.memory.load(addr, 4, endness='Iend_LE')
 
  z = 166055521 
  y = 623870071
  x = 2269857555
  w = 3860378946
  v = 3711798022
  u = 3267279183
 
  s.add_constraints(read(0x804a058) == u, read(0x804a06c) == v, read(0x804a080) == w, read(0x804a05c) == x, read(0x804a070) == y, read(0x804a084) == z)
  print ' '.join(map(str, [s.se.any_int(a), s.se.any_int(b), s.se.any_int(c), s.se.any_int(d), s.se.any_int(e), s.se.any_int(f)]))

if __name__ == '__main__':
  main()
