import angr
import claripy
import sys

def main(argv):
  path_to_binary = '05_angr_symbolic_stack'
  project = angr.Project(path_to_binary)

  start_address = 0x080488cf
  initial_state = project.factory.blank_state(addr=start_address)

  # We are jumping into the middle of a function! The first instruction of the
  # function sets ebp to esp but is not executed since we skip it. We need to
  # make sure we correct for this.
  initial_state.regs.ebp = initial_state.regs.esp

  # scanf("%u %s") needs to be replaced by injecting these two variables.
  # (!)
  passwords = [claripy.BVS('password', 32) for i in xrange(4)]

  padding_length_in_bytes = 8
  initial_state.regs.esp -= padding_length_in_bytes

  #for _ in xrange(2):
  #  initial_state.stack_push(claripy.BVV(0, 32))

  # Push the variables to the stack. Make sure to push them in the right order!
  # The syntax for the following function is:
  #
  # initial_state.stack_push(bitvector)
  #
  # This will push the bitvector on the stack, and increment esp the correct
  # amount. You will need to push multiple bitvectors on the stack.
  # (!)
  for password_elem in passwords:
    initial_state.stack_push(password_elem)

  path_group = project.factory.path_group(initial_state)

  def is_successful(path):
    stdout_output = path.state.posix.dumps(sys.stdout.fileno())
    return 'Success.' in stdout_output

  path_group.explore(find=is_successful, avoid=lambda p: 'Try again.' in p.state.posix.dumps(1))

  if path_group.found:
    good_path = path_group.found[0]

    # Solve for the symbolic values. If there are multiple solutions, we only
    # care about one, so we can use any_int or any_str, which returns any (but
    # only one) solution. Pass any_int and any_str the bitvector you want to 
    # solve for.
    # (!)
    password_order = [passwords[1], passwords[0], passwords[2], passwords[3]]
    solution = ' '.join(map(str, map(good_path.state.se.any_int, password_order)))
    print solution
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
