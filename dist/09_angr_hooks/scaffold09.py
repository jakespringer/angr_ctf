import angr
import claripy
import simuvex
import sys

def main(argv):
  path_to_binary = ???
  project = angr.Project(path_to_binary)

  start_address = ???
  initial_state = project.factory.blank_state(addr=start_address)

  # This will specify the address for the memory location to be used for storing
  # the number of times scanf has been called, so that we can set aside the
  # symbolic values we create each time scanf is called. This will make more 
  # sense later.
  # (!)
  scanf_calls_count_address = ???
  scanf_calls_count_size_bytes = ???

  # Specify the base location of the array of symbolic values used to set aside
  # the simulated output of scanf. For example, let's imagine the program is as
  # follows:
  #
  # 1  ...
  # 2  scanf("%8s", &output)
  # 3  scanf("%8s", &output)
  # 4  ...
  #
  # The 'output' variable is clearly overwritten, but we may want to solve for
  # 'output' at each call of scanf. One approach is, when we intercept scanf,
  # to store the symbolic value elsewhere. The problem: where do we store it?
  # If we picked a random constant address, it would be overwritten on the
  # second call of scanf. Instead, we will save how many times scanf has been
  # called, and then use a constant base address added to the number of times
  # scanf has been called times the 'stride', or the number of bytes in output.
  # Sound familiar? It works the same as a computer handles an array.
  # (!)
  scanf_set_aside_base_address = ???

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

    # Now, we want to 'set aside' references to our symbolic values at any
    # unused part of the memory. Why we do not simply store a Python list of all
    # of the symbolic values we create is left for the reader to figure out (an
    # interesting experiment would be to try it!).
    # You don't know how many times scanf will be called, so we will use a 
    # variable to store how many times it has already been called. Using that
    # number as the offset will allow you to store a list of the scanf outputs.
    scanf_calls_count = state.memory.load(
      scanf_calls_count_address, 
      scanf_calls_count_size,
      endness=project.arch.memory_endness
    )

    # Specify the 'stride' or the amount of data in bytes you will be storing
    # with each call of scanf. Then, calculate the output_address, where you
    # will write the symbolic value for use later.
    # (!)
    stride = ???
    set_aside_address = scanf_set_aside_base_address + (scanf_calls_count * stride)

    # Write one symbolic value to our 'set aside' address. When we specified the
    # output_address, we set aside 'stride' number of bytes. Since there are
    # multiple symbolic values, decide the offset for each one. Ensure that
    # it fits within the 'stride' you allocated. 
    # (!)
    state.memory.store(set_aside_address + ???, scanf0, endness=project.arch.memory_endness)
    ...

    # And, of course, we need to update the number of times scanf was called!
    # (!)
    state.memory.store(???, scanf_calls_count + 1, endness=project.arch.memory_endness)

  # Hook the address of where scanf is called.
  # (!)
  scanf_called_address = ???
  project.hook(scanf_called_address, skip_scanf)
  
  # Initialize our scanf_calls_count variable with 0 (at this point, scanf has
  # been called 0 times. Here we introduce a new function, claripy.BVV. It
  # constructs a new bitvector with a concrete value. Usage:
  # claripy.BVV(value, size_in_bits)
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

    # Now, we recall the memory we set aside. The exactly_int works like any_int
    # except that it throws an exception if the bitvector can be more than one
    # value.
    scanf_calls_count = good_path.state.se.exactly_int(good_path.state.memory.load(
      scanf_calls_count_address,
      scanf_calls_count_size,
      endness=project.arch.memory_endness
    ))

    solutions = []
    for i in xrange(scanf_calls_count):
      # Load one of the symbols we set aside and add it to the solutions list.
      # (!)
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
