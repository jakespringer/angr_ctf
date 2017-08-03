import angr
import claripy
import simuvex
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  initial_state = project.factory.entry_state()

  global_symbols_key = 'things'
  class ReplacementScanf(simuvex.SimProcedure):
    # Hint: scanf("%u %20")
    def run(self, format_string, int_param, str_param):
      scanf0 = claripy.BVS('scanf0', 32)
      scanf1 = claripy.BVS('scanf1', 20*8)

      #for char in scanf1.chop(bits=8):
      #  self.state.add_constraints(char >= 33, char <= 126)

      self.state.memory.store(int_param, scanf0, endness=project.arch.memory_endness)
      self.state.memory.store(str_param, scanf1)

      self.state.procedure_data.global_variables[global_symbols_key] = (scanf0, scanf1)

  scanf_symbol = '__isoc99_scanf'  # :string
  project.hook_symbol(scanf_symbol, angr.Hook(ReplacementScanf))

  # We will call this whenever puts is called. The goal of this function is to
  # determine if the pointer passed to puts is controllable by the user, such
  # that we can rewrite it to point to the string "Good Job."
  def check_puts(path):
    # Treat the implementation of this function as if puts was just called.
    # The stack, registers, memory, etc should be set up as if the x86 call
    # instruction was just invoked (but, of course, the function hasn't copied
    # the buffers yet.)
    # The stack will look as follows:
    # ...
    # esp + 7 -> /----------------\
    # esp + 6 -> |      puts      |
    # esp + 5 -> |    parameter   |
    # esp + 4 -> \----------------/
    # esp + 3 -> /----------------\
    # esp + 2 -> |     return     |
    # esp + 1 -> |     address    |
    #     esp -> \----------------/
    # (!)
    puts_parameter = path.state.memory.load(path.state.regs.esp + 4, 4, endness=project.arch.memory_endness)

    # The following function takes a bitvector as a parameter and checks if it
    # can take on more than one value. While this does not necessary tell us we
    # have found an exploitable path, it is a strongindication that the 
    # bitvector we checked may be controllable by the user.
    # Use it to determine if the pointer passed to puts is symbolic.
    # (!)
    if path.state.se.symbolic(puts_parameter):
      # Determine the location of the "Good Job.\n" string. We want to print it
      # out, and we will do so by attempting to constrain the puts parameter to
      # equal it.
      # (!)
      good_job_string_address = 0x34343448 # :integer, probably hexadecimal

      # Create an expression that will test if puts_parameter equals
      # good_job_string_address. If we add this as a constraint to our solver,
      # it will try and find an input to make this expression true.
      # (!)
      is_vulnerable_expression = puts_parameter == good_job_string_address # :boolean bitvector expression

      # Have Angr evaluate the state to determine if all the constraints can
      # be met, including the one we specified above. If it can be satisfied,
      # we have found our exploit!
      if path.state.satisfiable(extra_constraints=(is_vulnerable_expression,)):
        # Before we return, let's add the constraint to the solver for real,
        # instead of just querying whether the constraint _could_ be added.
        path.state.add_constraints(is_vulnerable_expression)
        return True
      else:
        return False
    else: # not path.state.se.symbolic(???)
      return False

  path_group = project.factory.path_group(initial_state)

  def is_successful(path):
    # We are looking for puts. Check that the address is at the (very) beginning
    # of the puts function. Warning: while, in theory, you could look for
    # any address in puts, if you execute any instruction that adjusts the stack
    # pointer, the stack diagram above will be incorrect. Therefore, it is
    # recommended that you check for the very beginning of puts.
    # (!)
    puts_address = 0x08048370
    if path.addr == puts_address:
      # Return True if we determine this call to puts is exploitable.
      return check_puts(path)
    else:
      # We have not yet found a call to puts; we should continue!
      return False

  # Determine the situation in which you should avoid. Optionally, you can
  # remove the avoid parameter, although it may cause the program to run more
  # slowly.
  # (!)
  path_group.explore(find=is_successful)
  #path_group.explore(find=0x804853d)

  if path_group.found:
    good_path = path_group.found[0]

    int_param, str_param = good_path.state.procedure_data.global_variables[global_symbols_key]
    int_solution = good_path.state.se.any_int(int_param)
    str_solution = good_path.state.se.any_str(str_param)

    solution = str(int_solution) + ' ' + str_solution
    print solution
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
