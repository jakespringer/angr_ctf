# The binary asks for a 16 character password to which is applies a complex
# function and then compares with a reference string with the function
# check_equals_[reference string]. (Decompile the binary and take a look at it!)
# The source code for this function is provided here. However, the reference
# string in your version will be different than AABBCCDDEEFFGGHH:
#
# char* password = "AABBCCDDEEFFGGHH";
# int check_equals_AABBCCDDEEFFGGHH(char* to_check, size_t length) {
#   uint32_t num_correct = 0;
#   for (int i=0; i<length; ++i) {
#     if (to_check[i] == password[i]) {
#       num_correct += 1;
#     }
#   }
#   return num_correct == length;
# }
#
# This function checks if to_check == "AABBCCDDEEFFGGHH". Verify that yourself.
# While you, as a human, can easily determine this, the computer cannot. Instead
# the computer would need to branch every time the if statement in the loop was
# called (16 times), resulting in 2^16 = 65,536 branches, which will take too
# long of a time to evaluate for our needs.
# In this puzzle, your goal will be to stop the program before this function is
# called and manually constrain the to_check variable to be equal to the
# password you identify by decompiling the binary. Since, you, as a human, know
# that if the strings are equal, the program will print "Good Job.", you can
# be assured that if the program can solve for an input that makes them equal,
# the input will be the correct password.

import angr
import claripy
import simuvex
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  start_address = ???
  initial_state = project.factory.blank_state(addr=start_address)

  password0 = claripy.BVS('password', ???)

  password0_address = ???
  initial_state.memory.store(password0_address, password0)

  path_group = project.factory.path_group(initial_state)

  # Angr will not be able to reach the point at which the binary prints out
  # 'Good Job.'. We cannot use that as the target anymore.
  # (!)
  address_to_check_constraint = ???
  path_group.explore(find=address_to_check_constraint)

  if path_group.found:
    good_path = path_group.found[0]

    # Recall that we need to constrain the to_check parameter (see top) of the 
    # check_equals_ function. Determine the address that is being passed as the
    # parameter and load it into a bitvector so that we can constrain it.
    constrained_parameter_address = ???
    constrained_parameter_size_bytes = ???
    constrained_parameter_bitvector = good_path.state.memory.load(
      constrained_parameter_address,
      constrained_parameter_size_bytes
    )

    # Constrain the system to find an input that will make
    # constrained_parameter_bitvector equal the desired value.
    constrained_parameter_desired_value = ??? # :string
    good_path.state.add_constraints(constrained_parameter_bitvector == constrained_parameter_desired_value)

    # Solve for the constrained_parameter_bitvector.
    solution = ???

    print solution
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
