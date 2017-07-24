import angr
import sys

def main(argv):
  path_to_binary = ???
  project = angr.Project(path_to_binary)
  initial_state = project.factory.entry_state()
  path_group = project.factory.path_group(initial_state)

  # Define a function that checks if a given path successfully found a backdoor.
  def is_successful(path):
    # Dump whatever has been printed out by the binary so far into a string.
    stdout_output = path.state.posix.dumps(sys.stdout.fileno())

    # Return whether 'Good Job.' has been printed yet.
    # (!)
    return ???

  # Same as above, but this time check if the path should abort.
  def should_abort(path):
    stdout_output = path.state.posix.dumps(sys.stdout.fileno())
    return ???

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
