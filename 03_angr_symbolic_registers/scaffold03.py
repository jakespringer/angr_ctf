import angr
import claripy
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  # Sometimes, you want to specify where the program should start. The variable
  # start_address will specify where the symbolic execution engine should begin.
  # Note that we are using blank_state, not entry_state.
  # (!)
  start_address = ???
  initial_state = project.factory.blank_state(addr=start_address)

  # Create a symbolic bitvector (the datatype Angr uses to inject symbolic
  # values into the binary.) The first parameter is just a name Angr uses
  # to reference it.
  # You will have to construct multiple bitvectors. Copy the two lines below
  # and change the variable names.
  # (!)
  password0_size_in_bits = ???
  password0 = claripy.BVS('password0', password0_size_in_bits)
  ...

  # Set a register to a symbolic value. This is one way to inject symbols into
  # the program.
  # initial_state.regs stores a number of convenient attributes that reference
  # registers by name. For example, to set eax to password0, use:
  #
  # initial_state.regs.eax = password0
  #
  # You will have to set multiple registers to distinct bitvectors. Copy and
  # paste the line below and change the register.
  # (!)
  initial_state.regs.??? = password0
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

    # Aggregate and format the solutions you computed above, and then print
    # the full string. Pay attention to the order of the integers, and the
    # expected base (decimal, octal, hexadecimal, etc).
    solution = ???
    print solution
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
