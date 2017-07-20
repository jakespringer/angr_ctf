import angr
import claripy
import simuvex
import sys

def main(argv):
  path_to_binary = ???
  project = angr.Project(path_to_binary)

  start_address = ???
  initial_state = project.factory.blank_state(addr=start_address)

  scanf_calls_count_address = ???
  scanf_calls_count_size_bytes = ???
  scanf_set_aside_base_address = ???
  instruction_to_skip_length = ???

  # Define a class that inherits simuvex.SimProcedure in order to take advantage
  # of Angr's SimProcedures.
  class ReplacementScanf(simuvex.SimProcedure):
    # A SimProcedure replaces a function in the binary with a simulated one
    # written in Python. Other than it being written in Python, the function
    # acts largely the same as any function written in C. Any parameter after
    # 'self' will be treated as a parameter to the function you are replacing.
    # The parameters will be bitvectors. Additionally, the Python can return in
    # the ususal Pythonic way. Angr will treat this in the same way it would
    # treat a native function in the binary returning. An example:
    #
    # int add_if_positive(int a, int b) {
    #   if (a >= 0 && b >= 0) return a + b;
    #   else return 0; 
    # }
    # 
    # could be simulated with...
    #
    # class ReplacementAddIfPositive(simuvex.SimProcedure):
    #   def run(self, a, b):
    #     if a >= 0 and b >=0:
    #       return a + b
    #     else:
    #       return 0
    #
    # Finish the parameters to the scanf function. Hint: 'scanf("%u %u", ...)'.
    # The rest of the function should look almost identical to the previous
    # challenge.
    # (!)
    def run(self, format_string, ...???):
      scanf0 = claripy.BVS('scanf0', ???)
      ...

      # Hint: scanf0_address is passed as a parameter, isn't it?
      scanf0_address = ???
      state.memory.store(scanf0_address, scanf0, endness=project.arch.memory_endness)
      ...

      scanf_calls_count = state.memory.load(
        scanf_calls_count_address, 
        scanf_calls_count_size,
        endness=project.arch.memory_endness
      )

      stride = ???
      set_aside_address = scanf_set_aside_base_address + (scanf_calls_count * stride)

      state.memory.store(set_aside_address + ???, scanf0, endness=project.arch.memory_endness)
      ...

      state.memory.store(???, scanf_calls_count + 1, endness=project.arch.memory_endness)

  # Hook the scanf symbol. Angr automatically looks up the address associated
  # with the symbol. Alternatively, you can use 'hook' instead of 'hook_symbol'
  # and specify the address of the function. To find the correct symbol, 
  # disassemble the binary.
  # (!)
  scanf_symbol = ???
  project.hook_symbol(scanf_symbol, Hook(ReplacementScanf)) 
 
  state.memory.store(
    scanf_calls_count_address, 
    claripy.BVV(0, scanf_calls_count_size_bytes * 8), 
    endness=project.arch.memory_endness
  )

  path_group = project.factory.path_group(initial_state)

  def is_successful(path):
    stdout_output = path.state.posix.dumps(sys.stdout.fileno())
    return ???

  def should_abort(path):
    stdout_output = path.state.posix.dumps(sys.stdout.fileno())
    return ???

  path_group.explore(find=is_successful, avoid=should_abort)

  if path_group.found:
    good_path = path_group.found[0]

    scanf_calls_count = good_path.state.se.exactly_int(good_path.state.memory.load(
      scanf_calls_count_address,
      scanf_calls_count_size,
      endness=project.arch.memory_endness
    ))

    solutions = []
    for i in xrange(scanf_calls_count):
      stride = ???
      set_aside_address = scanf_set_aside_base_address + (i * stride)
      password = state.memory.load(
        set_aside_address + ???, 
        ???, 
        endness=project.arch.memory_endness
      )
      solution = good_path.state.se.any_int(password)
      solutions.append(solution)

    print ' '.join(solutions)
  else:
    raise Exception('Could not find the solutioni')

if __name__ == '__main__':
  main(sys.argv)
