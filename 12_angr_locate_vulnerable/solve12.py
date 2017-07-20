#!/usr/bin/pypy

import angr, claripy
import sys, functools
from angr import Hook
from simuvex import SimProcedure

def main():
  proj = angr.Project(sys.argv[1])
  initial_state = proj.factory.entry_state()

  class IntStrScanf(SimProcedure):
    def run(self, format_str, int_addr, str_addr):
      int_var = claripy.BVS('int_var', 32)
      str_var = claripy.BVS('str_var', 16*8)
      self.state.memory.store(int_addr, int_var, endness='Iend_LE')
      self.state.memory.store(str_addr, str_var, endness='Iend_LE')
      self.state.memory.store(0x4000000, int_var, endness='Iend_LE')
      self.state.memory.store(0x4000004, str_var, endness='Iend_LE')
  
  target_str = claripy.BVV('aaaaaaaa', 8*8)
  def check_strcpy(state):
    dest = state.stack_read(offset=4, length=4)
    src = state.stack_read(offset=8, length=4)
    return state.satisfiable(extra_constraints=(state.memory.load(src, 8, endness='Iend_LE') == target_str,))
 
  proj.hook_symbol('__isoc99_scanf', Hook(IntStrScanf))

  initial_state.memory.store(0x4002000, claripy.BVV(0, 8))

  found = False
  exploit_path = None
  pg = proj.factory.path_group(initial_state)
  pg.found = []
  while len(pg.active) > 0 and len(pg.found) == 0 and not found:
    pg.step()
    for path in pg.active:
      #if path.state.ip.args[0] == 0x8048789:
      block = proj.factory.block(path.addr) 
      for insn in block.capstone.insns:
        if insn.insn.address == 0x8048789:
          print insn.insn.mnemonic
          print insn.insn.operands[0].type, insn.insn.operands[0].value.reg
          print insn.insn.operands[1].type, hex(insn.insn.operands[1].value.mem.disp)
          print insn.insn.reg_name(19)

  print pg
  print exploit_path.state.se.any_int(exploit_path.state.memory.load(0x4000000, 4, endness='Iend_LE')), 'aaaaaaaaaaaa'

if __name__ == '__main__':
  main()
