# This level performs complex computations necessary to evaluate user input
# before scanf is called. This means we cannot start the program after scanf is
# called to avoid handling it, as we would miss the initial computations in our
# path. Instead, we need to 'hook' the call to scanf and replace it with our own
# code that injects symbols correctly. This means we need to specify to Angr to
# pause the execution when it arrives at the scanf instruction, run our Python
# function, and then return to the execution with our modified state, skipping
# the call to scanf.

import angr
import claripy
import simuvex
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  start_address = ???
  initial_state = project.factory.blank_state(addr=start_address)

  # We want to store a reference to the symbolic variables we inject when scanf
  # is called. We will store them in a dictionary associated with the state that
  # will be visible in any state that comes after the state where we added them.
  # Why is this necessary? 
  # Imagine the following source code: 
  # 
  #   if exp:
  #     correct = True
  #   else:
  #     correct = False
  #
  #   scanf("%u %u", password0, password1)
  #
  #   if correct and accept_passwords(password0, password1):
  #     print "Good Job."
  #   else:
  #     print "Try again."
  #
  # There are two possible paths that lead to scanf (if exp, if not exp),
  # meaning that our hook function will be called twice. If we have a global
  # Python variable that stores our symbolic values, it would be overwritten
  # on the second call of our scanf replacement. Instead, we want to store the
  # symbolic variables with the state in which they were injected. We can do
  # that by adding it to a dictionary provided by the state to be used for this
  # purpose.
  #
  # This variable is just the key we will be using. It can be any string except
  # the empty string.
  global_symbols_key = ???  # :string

  # The length parameter in angr.Hook specifies how many bytes the execution
  # engine should skip after completing the hook. This will allow hooks to
  # replace certain instructions (or groups of instructions).
  # (!)
  instruction_to_skip_length = ???
  @angr.Hook(length=instruction_to_skip_length)
  def skip_scanf(state):
    # The binary calls scanf(%u %u). We need to inject two integers.
    # (!)
    scanf0 = claripy.BVS('scanf0', ???)
    ...

    # Identify the address where scanf writes the user input.
    # (!)
    scanf0_address = ???
    state.memory.store(scanf0_address, scanf0, endness=project.arch.memory_endness)
    ...

    # Now, we want to 'set aside' references to our symbolic values in the
    # procedure_data plugin included by default with a state. You will need to
    # store multiple bitvectors. You can either use a list, tuple, or multiple
    # keys to reference the different bitvectors.
    # (!)
    state.procedure_data.global_variables[global_symbols_key] = ???

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

    # Recall where you set aside the symbols and solve for them.
    solution = ???

    print solution
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
