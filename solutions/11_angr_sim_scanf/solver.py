# This time, the solution involves simply replacing scanf with our own version,
# since Angr does not support requesting multiple parameters with scanf.

import angr
import claripy
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  initial_state = project.factory.entry_state()

  class ReplacementScanf(angr.SimProcedure):
    # Finish the parameters to the scanf function. Hint: 'scanf("%u %u", ...)'.
    # (!)
    def run(self, format_string, param0, param1):
      scanf0 = claripy.BVS('scanf0', 32)
      scanf1 = claripy.BVS('scanf1', 32)

      # The scanf function writes user input to the buffers to which the 
      # parameters point.
      # Hint: scanf0_address is passed as a parameter, isn't it?
      scanf0_address = param0
      self.state.memory.store(scanf0_address, scanf0, endness=project.arch.memory_endness)
      scanf1_address = param1
      self.state.memory.store(scanf1_address, scanf1, endness=project.arch.memory_endness)

      # Now, we want to 'set aside' references to our symbolic values in the
      # globals plugin included by default with a state. You will need to
      # store multiple bitvectors. You can either use a list, tuple, or multiple
      # keys to reference the different bitvectors.
      # (!)
      self.state.globals['solutions'] = (scanf0, scanf1)

  scanf_symbol = '__isoc99_scanf'
  project.hook_symbol(scanf_symbol, ReplacementScanf())

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Good Job.'.encode() in stdout_output

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Try again.'.encode() in stdout_output

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]

    # Grab whatever you set aside in the globals dict.
    stored_solutions = solution_state.globals['solutions']
    solution = ' '.join(map(str, map(solution_state.solver.eval, stored_solutions)))

    print(solution)
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
