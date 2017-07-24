import angr
import claripy
import simuvex
import sys

def main(argv):
  path_to_binary = ???
  project = angr.Project(path_to_binary)

  start_address = ???
  initial_state = project.factory.blank_state(addr=start_address)

  # An under-constrained (unconstrained) state occurs when there are too many
  # possible branches from a single instruction. This occurs, among other ways,
  # when the instruction pointer (on x86, eip) is completely symbolic, meaning 
  # that user input can control the address of code the computer executes.
  # For example, imagine the following pseudo assembly:
  # 
  # mov user_input, eax
  # jmp eax
  #
  # The value of what the user entered dictates the next instruction. This
  # is an unconstrained state. It wouldn't usually make sense for the execution
  # engine to continue. (Where should the program jump to if eax could be
  # anything?) Normally, when Angr encounters an unconstrained state, it throws
  # it out. In our case, we want to exploit the unconstrained state to jump to
  # a location of our choosing. We will get to how to disable Angr's default
  # behavior later. For now, test if a state is vulnerable by checking if we
  # can set the instruction pointer to the address of print_good in the binary.
  # (!)
  def check_vulnerable(path):
    # Reimplement me!
    return False

  # The save_unconstrained=True parameter specifies to Angr to not throw out
  # unconstrained states. Instead, it will move them to the list called
  # 'path_group.unconstrained'.
  path_group = project.factory.path_group(initial_state, save_unconstrained=True)

  # Explore will not work for us, since the method specified with the 'find'
  # parameter will not be called on an unconstrained state. Instead, we want to
  # explore the binary ourselves.
  # To get started, construct an exit condition to know when we've found a
  # solution. We will later be able to move paths from the unconstrained list
  # to the path_group.found list. Alternatively, you can create a boolean value
  # that serves the same purpose.
  has_found_solution = len(path_group.found) > 0

  # Check if there are still unconstrained paths left to check. Once we 
  # determine a given unconstrained state is not exploitable, we can throw it
  # out. Use the path_group.unconstrained list.
  # (!)
  has_unconstrained_to_check = ???
  
  # The list path_group.active is a list of all paths that can be explored
  # further.
  # (!)
  has_active = ???
  while (has_active or has_unconstrained_to_check) and (not has_found_solution):
    # Iterate through all unconstrained path and check them.
    # (!)
    for unconstrained_path in ???:
      # Check if the unconstrained state is exploitable.
      # (!)
      if ???:
        # Found an exploit, exit the while loop and keep unconstrained_path as
        # the solution. The way the loops is currently set up, you should move
        # the exploitable unconstrained state to the 'found' stash.
        # A 'stash' should be a string that corresponds to a list that stores
        # all the paths that the path group keeps. Values include: 
        #  'active' = paths that can be stepped
        #  'deadended' = paths that have exited the program
        #  'errored' = paths that encountered an error with Angr
        #  'unconstrained' = paths that are unconstrained
        #  'found' = solutions
        #  anything else = whatever you want, perhaps you want a 'not_needed',
        #                  you can call it whatever you want

        # Moves anything in the stash 'from_stash' to the 'to_stash' if the 
        # function should_move evaluates to true.
        # Reimplement this entire block of code.
        # (!)
        def should_move(path):
          # Reimplement me if you decide to use me
          return False
        path_group.move(from_stash, to_stash, filter_func=should_move)

        # For example, the following moves everything in 'active' to
        # 'not_needed' except if the path is in keep_paths
        keep_paths = [ ... ]
        def should_move(path):
          return path in keep_paths
        path_group.move('active', 'not_needed', filter_func=should_move)
      else: # unconstrained state is not exploitable
        # Move the unconstrained_state that you tested that doesn't work to a
        # different stash, perhaps 'not_needed'.
        # Reimplement me.
        # (!)
        pass

    path_group.step()
        

  if path_group.found:
    good_path = path_group.found[0]

    # Constrain the instruction pointer to target the print_good function and
    # then solve for the user input (recall that this is 
    # 'good_path.state.posix.dumps(sys.stdin.fileno())')
    # (!)
    ...

    solution = ???
    print solution
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
