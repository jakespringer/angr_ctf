# Before you begin, here are a few notes about these capture-the-flag
# challenges.
#
# Each binary, when run, will ask for a password, which can be entered via stdin
# (typing it into the console.) Many of the levels will accept many different
# passwords. Your goal is to find a single password that works for each binary.
#
# If you enter an incorrect password, the program will print "Try again." If you
# enter a correct password, the program will print "Good Job."
#
# Each challenge will be accompanied by a file like this one, named
# "scaffoldXX.py". It will offer guidance as well as the skeleton of a possible
# solution. You will have to edit each file. In some cases, you will have to
# edit it significantly. While use of these files is recommended, you can write
# a solution without them, if you find that they are too restrictive.
#
# Places in the scaffoldXX.py that require a simple substitution will be marked
# with three question marks (???). Places that require more code will be marked
# with an ellipsis (...). Comments will document any new concepts, but will be
# omitted for concepts that have already been covered (you will need to use
# previous scaffoldXX.py files as a reference to solve the challenges.) If a
# comment documents a part of the code that needs to be changed, it will be
# marked with an exclamation point at the end, on a separate line (!).

import angr
import sys

def main(argv):
  # Create an Angr project.
  # If you want to be able to point to the binary from the command line, you can
  # use argv[1] as the parameter. Then, you can run the script from the command
  # line as follows:
  # ./scaffold00 [binary]
  # (!)
  path_to_binary = ???
  project = angr.Project(path_to_binary)

  # Tell Angr where to start executing (should it start from the main()
  # function or somewhere else?) For now, use the entry_state function
  # to instruct Angr to start from the main() function.
  initial_state = project.factory.entry_state()

  # Create a path group initialized with the starting state. Path groups remember
  # the set of paths through the executable that the engine has taken so far.
  path_group = project.factory.path_group(initial_state)

  # Explore the binary to attempt to find the backdoor. You will have to find
  # the address you want to find and insert it here. This function will keep
  # executing until it either finds a solution or it has explored every possible
  # path in the executable.
  # (!)
  backdoor_address = ???
  path_group.explore(find=backdoor_address)

  # Check that we have found a solution. The path_group.explore() method will
  # set path_group.found to a list of the paths that it could find that reach
  # the instruction we asked it to search for. Remember, in Python, if a list
  # is empty, it will be evaluated as false. Otherwise, it will be true.
  if path_group.found:
    # The explore method stops after it finds a single path that arrives at the
    # target address.
    good_path = path_group.found[0]

    # Print the string that Angr wrote to stdin to follow good_path. This is
    # our solution.
    print good_path.state.posix.dumps(sys.stdin.fileno())
  else:
    # If Angr could not find a path that reaches backdoor_address, throw an
    # error. Perhaps you mistyped the backdoor_address?
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
