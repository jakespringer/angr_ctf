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

  class ReplacementScanf(simuvex.SimProcedure):
    # Hint: scanf("%u %s")
    def run(self, format_string, ...???):
      scanf0 = claripy.BVS('scanf0', ???)
      ...

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

  scanf_symbol = ???
  project.hook_symbol(scanf_symbol, Hook(ReplacementScanf)) 
 
  state.memory.store(
    scanf_calls_count_address, 
    claripy.BVV(0, scanf_calls_count_size_bytes * 8), 
    endness=project.arch.memory_endness
  )

  # Check if strcpy might be vulnerable by checking if the source is symbolic
  # (and therefore might be directly controlled by the user.)
  def check_strcpy_vulnerable(path):
    # Check if we are at the beginning of strcpy.
    strcpy_address = ???
    if path.addr == strcpy_address:
      # Treat the implementation of this function as if strcpy was just called.
      # The stack, registers, memory, etc should be set up as if the x86 call
      # instruction was just invoked (but, of course, the function hasn't copied
      # the buffers yet.)
   
      # Get the bitvector of the src and dest parameter of strcpy. How big should
      # the buffer you load be for each?
      # (!)
      src = ???
      dest = ???
    
      # Check if a the bitvector can take on more than one value. While this does
      # not necessary tell us we have found an exploitable path, it is a strong
      # indication that the bitvector we checked may be controllable by the user.
      # You should check the source bitvector. We make this initial check because
      # it is fast and will likely weed out most negatives.
      # (!)
      if path.state.se.symbolic(???):
        # Load the bytes that we want to exploit. Hint: the dest buffer, in this
        # binary, is always eight bytes. Immediately after those eight bytes is
        # a pointer to a string the binary prints later.
        # (!)
        potential_vulnerable_bytes = ???
 
        # We want to use a buffer overflow attack to overwrite the vulnerable
        # bytes. We will use Angr to determine if there is some user input that
        # will overwrite them with the desired value.
        # (!)
        desired_vulnerable_bytes_value = ???

        # An expression that Angr will later attempt to make True. If it can be
        # made True, that implies that there is a way that we can make the
        # vulnerable bytes equal to the desired value.
        vulnerable = potential_vulnerable_bytes == desired_vulnerable_bytes_value

        # Have Angr evaluate the state to determine if all the constraints can
        # be met, including the one we specified above. If it can be satisfied,
        # we have found our exploit!
        return path.state.satisfiable(extra_constraints=(vulnerable,))
      else: # not path.state.se.symbolic(???)
        return False
    else: # path.addr != strcpy_address
      return False

  path_group = project.factory.path_group(initial_state)

  # (!)
  path_group.explore(find=check_strcpy_vulnerable, avoid=???)  

  if path_group.found:
    good_path = path_group.found[0]

    # Add the constraint to our vulnerable bytes to set them to our desired
    # value. Remember, the state is still immediate after a call strcpy
    # instruction.
    # (!)
    vulnerable_bytes = ???
    vulnerable = ???
    good_path.state.add_constraints(vulnerable)

    scanf_calls_count = good_path.state.se.exactly_int(good_path.state.memory.load(
      scanf_calls_count_address,
      scanf_calls_count_size,
      endness=project.arch.memory_endness
    ))

    solutions = []
    for i in xrange(scanf_calls_count):
      # The following lines have changed since the previous level.
      # (!)
      stride = ???
      set_aside_address = scanf_set_aside_base_address + (i * stride)
      password = state.memory.load(
        set_aside_address + ???, 
        ???, 
        endness=project.arch.memory_endness
      )
      ...
      solution = ???
      solutions.append(solution)

    print ' '.join(solutions)
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
