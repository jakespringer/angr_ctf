import angr
import claripy
import simuvex
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  # You can either use a blank state or an entry state; just make sure to start
  # at the beginning of the program.
  initial_state = project.factory.entry_state()

  global_symbols_key = 'things'
  class ReplacementScanf(simuvex.SimProcedure):
    # Hint: scanf("%u %20s")
    def run(self, format_string, int_param, str_param):
      # %u
      scanf0 = claripy.BVS('scanf0', 32)
      
      # %20s
      scanf1 = claripy.BVS('scanf1', 20*8)

      for char in scanf1.chop(bits=8):
        self.state.add_constraints(char >= '!', char <= '~')

      self.state.memory.store(int_param, scanf0, endness=project.arch.memory_endness)
      self.state.memory.store(str_param, scanf1)

      self.state.procedure_data.global_variables[global_symbols_key] = (scanf0, scanf1)

  scanf_symbol = '__isoc99_scanf'  # :string
  project.hook_symbol(scanf_symbol, angr.Hook(ReplacementScanf))

  # In this challenge, we want to check strncpy to determine if we can control
  # both the source and the destination. It is common that we will be able to
  # control at least one of the parameters, (such as when the program copies a
  # string that it received via stdin).
  def check_strncpy(path):
    # The stack will look as follows:
    # ...          ________________
    # esp + 15 -> /                \
    # esp + 14 -> |     param2     |
    # esp + 13 -> |      len       |
    # esp + 12 -> \________________/
    # esp + 11 -> /                \
    # esp + 10 -> |     param1     |
    #  esp + 9 -> |      src       |
    #  esp + 8 -> \________________/
    #  esp + 7 -> /                \
    #  esp + 6 -> |     param0     |
    #  esp + 5 -> |      dest      |
    #  esp + 4 -> \________________/
    #  esp + 3 -> /                \
    #  esp + 2 -> |     return     |
    #  esp + 1 -> |     address    |
    #      esp -> \________________/
    # (!)
    strncpy_src = path.state.memory.load(path.state.regs.esp + 8, 4, endness=project.arch.memory_endness)
    strncpy_dest = path.state.memory.load(path.state.regs.esp + 4, 4, endness=project.arch.memory_endness)
    strncpy_len = path.state.memory.load(path.state.regs.esp + 12, 4, endness=project.arch.memory_endness)

    # We need to find out if src is symbolic, however, we care about the
    # contents, rather than the pointer itself. Therefore, we have to load the
    # the contents of src to determine if they are symbolic.
    # Hint: How many bytes is strncpy copying?
    # (!)
    src_contents = path.state.memory.load(strncpy_src, strncpy_len)

    # Determine if the destination pointer and the source is symbolic.
    # (!)
    if path.state.se.symbolic(strncpy_dest) and path.state.se.symbolic(src_contents):
      # Use ltrace to determine the password. Decompile the binary to determine
      # the address of the buffer it checks the password against. Our goal is to
      # overwrite that buffer to store the password.
      password = 'WQNDNKKW' # :string
      buffer_address = 0x34343458 # :integer, probably in hexadecimal

      # Create an expression that tests if the first n bytes is length. Warning:
      # while typical Python slices (array[start:end]) will work with bitvectors,
      # they are indexed in an odd way. The ranges must start with a high value
      # and end with a low value. Additionally, the bits are indexed from right
      # to left. For example, let a bitvector, b, equal 'ABCDEFGH', (64 bits).
      # The following will read bit 0-7 (total of 1 byte) from the right-most
      # bit (the end of the string).
      #  b[7:0] == 'H'
      # To access the beginning of the string, we need to access the last 16
      # bits, or bits 48-63:
      #  b[63:48] == 'AB'
      does_src_hold_password = src_contents[-1:-64] == password
      
      # Create an expression to check if the dest parameter can be set to
      # buffer_address. If this is true, then we have found our exploit!
      does_dest_equal_buffer_address = strncpy_dest == buffer_address

      # We can pass multiple expressions to extra_constraints!
      if path.state.satisfiable(extra_constraints=(does_src_hold_password, does_dest_equal_buffer_address)):
        path.state.add_constraints(does_src_hold_password, does_dest_equal_buffer_address)
        return True
      else:
        return False
    else: # not path.state.se.symbolic(???)
      return False

  path_group = project.factory.path_group(initial_state)

  def is_successful(path):
    strncpy_address = 0x8048410
    if path.addr == strncpy_address:
      return check_strncpy(path)
    else:
      return False

  path_group.explore(find=is_successful)

  if path_group.found:
    good_path = path_group.found[0]

    int_password, str_password = good_path.state.procedure_data.global_variables[global_symbols_key]
    solution = str(good_path.state.se.any_int(int_password)) + ' ' + good_path.state.se.any_str(str_password)
    print solution
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
