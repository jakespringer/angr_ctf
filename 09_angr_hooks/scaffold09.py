import angr
import claripy
import simuvex
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  start_address = ???
  initial_state = project.factory.blank_state(addr=start_address)

  # We will collect a list of all of the symbolic variables accumulated by the
  # scanf function in a dictionary stored with the state. This will make more
  # sense when you see it used.
  global_symbols_key = ??? # :string

  # The length parameter in angr.Hook specifies how many bytes the execution
  # engine should skip after completing the hook. This will allow hooks to
  # replace certain instructions (or groups of instructions).
  # (!)
  instruction_to_skip_length = ???
  @angr.Hook(length=instruction_to_skip_length)
  def skip_scanf(state):
    # The binary calls scanf(%u %u%*[ ]) on each loop iteration. We need to
    # inject two symbolic integers on each call of scanf.
    # (!)
    scanf0 = claripy.BVS('scanf0', ???)
    ...

    # Identify the address where scanf writes the user input.
    # (!)
    scanf0_address = ???
    state.memory.store(scanf0_address, scanf0, endness=project.arch.memory_endness)
    ...

    # Now, we want to 'set aside' references to our symbolic values in the
    # procedure_data plugin included by default with a state. Add the symbol we
    # created for the scanf call to the symbols_list. Why we do not simply store
    # a global Python list of all of the symbolic values we create is left for
    # the reader to figure out (an interesting experiment would be to try it!).
    # (!)
    if not global_symbols_key in state.procedure_data.global_variables:
      state.procedure_data.global_variables[global_symbols_key] = []
    state.procedure_data.global_variables[global_symbols_key].append(???)

  # Hook the address of where scanf is called.
  # (!)
  scanf_called_address = ???
  project.hook(scanf_called_address, skip_scanf)

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

    # Recall where you set aside the symbols and iterate through them and solve
    # them to find the integer solutions to this binary.
    solutions = []
    for password in ???:
      solution = good_path.state.se.any_int(password)
      solutions.append(solution)

    print ' '.join(solutions)
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
