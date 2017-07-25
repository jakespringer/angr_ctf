# It is very useful to be able to search for a path that reaches a certain
# instruction. However, in some cases, you may not know the address of the
# specific instruction you want to reach (or perhaps there is no single
# instruction goal.) In this challenge, you don't know which instruction
# grants you success. Instead, you just know that you want to find a path where
# the binary prints "Good Job."
#
# Angr is powerful in that it allows you to search for a path that meets an
# arbitrary condition that you specify in Python, using a predicate you define
# as a function that takes a path and returns True if you have found the path
# you are looking for, and False otherwise.

import angr
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)
  initial_state = project.factory.entry_state()
  path_group = project.factory.path_group(initial_state)

  # Define a function that checks if a given path successfully found the path
  # you are looking for.
  def is_successful(path):
    # Dump whatever has been printed out by the binary so far into a string.
    stdout_output = path.state.posix.dumps(sys.stdout.fileno())

    # Return whether 'Good Job.' has been printed yet.
    # (!)
    return ???  # :boolean

  # Same as above, but this time check if the path should abort. If you return
  # False, Angr will continue to step the path. In this specific challenge, the
  # only time at which you will know you should abort is when the program prints
  # "Try again."
  def should_abort(path):
    stdout_output = path.state.posix.dumps(sys.stdout.fileno())
    return ???  # :boolean

  # Tell Angr to explore the binary and find any path that is_successful identfies
  # as a successful state by returning True.
  path_group.explore(find=is_successful, avoid=should_abort)

  if path_group.found:
    good_path = path_group.found[0]
    print good_path.state.posix.dumps(sys.stdin.fileno())
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
