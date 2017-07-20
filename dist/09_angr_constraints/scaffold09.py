import angr
import claripy
import simuvex
import sys

def main(argv):
  path_to_binary = ???
  project = angr.Project(path_to_binary)

  start_address = ???
  initial_state = project.factory.blank_state(addr=start_address)

  password0 = claripy.BVS('password', ???)
  ...

  password0_address = ???
  initial_state.store(password0_address, password0)
  ...

  path_group = project.factory.path_group(initial_state)

  # Angr will not be able to reach the point at which the binary prints out
  # 'Success.'. We cannot use that as the target anymore.
  # (!)
  success_address = ???
  avoid_address = ???
  path_group.explore(find=success_address, avoid=avoid_address)

  if path_group.found:
    good_path = path_group.found[0]

    # We need to load the output of the complex function. Figure out where these
    # are stored by looking at the disassembly of the binary.
    complex_function_output0_address = ???
    complex_function_output0_size_bytes = ???
    complex_function_output0 = good_path.state.load(
      complex_function_output0_address, 
      complex_function_output0_size_bytes,
      endness=project.arch.memory_endness
    )
    ...

    # Constrain the system to find an input given that the complex function
    # outputs are equal to the desired outputs.
    desired_complex_function_output0 = ???
    good_path.state.add_constraints(complex_function_output0 == desired_complex_function_output0)
    ...

    solution0 = good_path.state.se.any_int(password0)
    ...

    solution = ... + ' ' + str(solution0) + ' ' + ...

    print solution
  else:
    raise Exception('Could not find the solutioni')

if __name__ == '__main__':
  main(sys.argv)
