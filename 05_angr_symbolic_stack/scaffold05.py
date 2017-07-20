import angr
import claripy
import sys

def main(argv):
  path_to_binary = ???
  project = angr.Project(path_to_binary)

  start_address = ???
  initial_state = project.factory.blank_state(addr=start_address)

  # We are jumping into the middle of a function! The first instruction of the
  # function sets ebp to esp but is not executed since we skip it. We need to
  # make sure we correct for this.
  initial_state.regs.ebp = initial_state.regs.esp

  # scanf("%u %u %u %u") needs to be replaced by injecting four bitvectors. You
  # can either copy and paste the line below or use a Python list.
  # (!)
  password0 = claripy.BVS('password0', ???)
  ...

  # The four variables above are not the only elements on the stack! Determine
  # how many bytes should be on the stack before the scanf variables. Subtract
  # this number of bytes from esp to 'push' this padding to the stack.
  padding_length_in_bytes = ???
  initial_state.regs.esp -= padding_length_in_bytes

  # Push the variables to the stack. Make sure to push them in the right order!
  # The syntax for the following function is:
  #
  # initial_state.stack_push(bitvector)
  #
  # This will push the bitvector on the stack, and increment esp the correct
  # amount. You will need to push multiple bitvectors on the stack.
  # (!)
  initial_state.stack_push(???)
  ...

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

    # Solve for the symbolic values. If there are multiple solutions, we only
    # care about one, so we can use any_int, which returns any (but only one)
    # solution. Pass any_int the bitvector you want to solve for.
    # (!)
    solution0 = good_path.state.se.any_int(password0)
    ...
    
    # Pay attention to the order in which the integers need to be presented as
    # arguments. Look at the binary's dissasembly to determine this. 
    # (!)
    solution = ... + ' ' + str(solution0) + ' ' + ...

    print solution
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
