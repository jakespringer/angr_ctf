# The shared library has the function validate, which takes a string and returns
# either true (1) or false (0). The binary calls this function. If it returns
# true, the program prints "Good Job." otherwise, it prints "Try again."
#
# Note: When you run this script, make sure you run it on
# lib14_angr_shared_library.so, not the executable. This level is intended to
# teach how to analyse binary formats that are not typical executables.

import angr
import claripy
import sys

def main(argv):
  path_to_binary = argv[1]

  # The shared library is compiled with position-independent code. You will need
  # to specify the base address. All addresses in the shared library will be
  # base + offset, where offset is their address in the file.
  # (!)
  base = 0x4000000
  project = angr.Project(path_to_binary, load_options={
    'main_opts' : {
      'base_addr' : base
    }
  })

  # Initialize any symbolic values here; you will need at least one to pass to
  # the validate function.
  # (!)
  buffer_pointer = claripy.BVV(0x3000000, 32)

  # Begin the state at the beginning of the validate function, as if it was
  # called by the program. Determine the parameters needed to call validate and
  # replace 'parameters...' with bitvectors holding the values you wish to pass.
  # Recall that 'claripy.BVV(value, size_in_bits)' constructs a bitvector
  # initialized to a single value.
  # Remember to add the base value you specified at the beginning to the
  # function address!
  # Hint: int validate(char* buffer, int length) { ...
  # (!)
  validate_function_address = base + 0x670
  initial_state = project.factory.call_state(
                    validate_function_address,
                    buffer_pointer,
                    claripy.BVV(8, 32),
                    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                                   angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
                  )

  # Inject a symbolic value for the password buffer into the program and
  # instantiate the simulation. Another hint: the password is 8 bytes long.
  # (!)
  password = claripy.BVS('password', 8*8)
  initial_state.memory.store(buffer_pointer, password)

  simulation = project.factory.simgr(initial_state)

  # We wish to reach the end of the validate function and constrain the
  # return value of the function (stored in eax) to equal true (value of 1)
  # just before the function returns. We could use a hook, but instead we
  # can search for the address just before the function returns and then
  # constrain eax
  # (!)
  check_constraint_address = base + 0x71c
  simulation.explore(find=check_constraint_address)

  if simulation.found:
    solution_state = simulation.found[0]

    # Determine where the program places the return value, and constrain it so
    # that it is true. Then, solve for the solution and print it.
    # (!)
    solution_state.add_constraints(solution_state.regs.eax != 0)
    solution = solution_state.solver.eval(password,cast_to=bytes).decode()
    print(solution)
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
