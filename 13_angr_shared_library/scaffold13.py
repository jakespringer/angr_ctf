import angr
import claripy
import sys

def main(argv):
  path_to_binary = ???

  # The shared library is compiled with position-independent code. You will need
  # to specify the base address. All addresses in the shared library will be
  # base + offset, where offset is their address in the file.
  # (!)
  base = ???
  project = angr.Project(path_to_binary, load_options={ 'main_opts' : { 'custom_base_addr' : base } })

  # Begin the state at the beginning of the validate function, as if it was
  # called by the program. Determine the parameters needed to call validate and
  # replace 'parameters...' with bitvectors holding the values you wish to pass.
  # Recall that 'claripy.BVV(value, size_in_bits)' constructs a bitvector 
  # initialized to a single value.
  # (!)
  validate_function_address = ???
  initial_state = project.factory.call_state(validate_function_address, parameters...)

  # You will need to add code to inject a symbolic value into the program.
  ...

  path_group = project.factory.path_group(initial_state)

  success_address = ???
  path_group.explore(find=success_address)

  if path_group.found:
    good_path = path_group.found[0]
  
    # Determine where the program places the return value, and constrain it so
    # that it is true. Then, solve for the solution and print it.
    # (!)
    solution = ???
    print solution
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
