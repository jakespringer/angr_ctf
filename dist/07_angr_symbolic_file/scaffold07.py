# This challenge could, in theory, be solved in multiple ways. However, for the
# sake of learning how to simulate an alternate filesystem, please solve this
# challenge according to structure provided below. As a challenge, once you have
# an initial solution, try solving this in an alternate way.
#
# Problem description and general solution strategy:
# The binary loads the password from a file using the fread function. If the
# password is correct, it prints "Good Job." In order to keep consistency with
# the other challenges, the input from the console is written to a file in the 
# ignore_me function. As the name suggests, ignore it, as it only exists to
# maintain consistency with other challenges.
# We want to:
# 1. Determine the file from which fread reads.
# 2. Use Angr to simulate a filesystem where that file is replaced with our own
#    simulated file.
# 3. Initialize the file with a symbolic value, which will be read with fread
#    and propogated through the program.
# 4. Solve for the symbolic input to determine the password.

# Explain why the memory backing needs to start with 0 (explain memory backing)
# Explain what the content parameter does

import angr
import claripy
import simuvex
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  start_address = ???
  initial_state = project.factory.blank_state(addr=start_address)

  # Specify some information needed to construct a simulated file. For this
  # challenge, the filename is hardcoded, but in theory, it could be symbolic. 
  # Note: to read from the file, the binary calls
  # 'fread(buffer, sizeof(char), 64, file)'.
  # (!)
  filename = ???  # :string
  symbolic_file_size_bytes = ???

  # A file, in Linux, represents a stream of sequential data. This stream may
  # come from a physical file on your hard drive, the network, the output of
  # another program (ex: /dev/urandom), or anything else. In our case, we want
  # to construct a block of memory where we store our symbolic variables for the
  # program to read. The following constructs the symbolic memory that will
  # supply the stream of data to the Linux file. Also, to communicate with 
  # Angr's constraint solving system, we need to associate the memory with the 
  # initial_state.
  symbolic_file_backing_memory = simuvex.SimSymbolicMemory()
  symbolic_file_backing_memory.set_state(initial_state)

  # Construct a bitvector for the password and then store it in the file's
  # backing memory. The store method works exactly the same as the store method
  # you have already used. In fact, it's the exact same method! That means that
  # memory.store(address, bitvector) will write bitvector to the address we
  # specify. In this memory, unlike our program's memory, we want to write to
  # the beginning, as the Linux file will stream data from the beginning of the
  # file. For example, imagine a simple file, 'hello.txt':
  #
  # Hello world, my name is John.
  # ^                       ^
  # ^ address 0             ^ address 24 (count the number of characters)
  # In order to represent this in memory, we would want to write the string to
  # the beginning of the file:
  #
  # hello_txt_backing_memory.store(0, claripy.BVV('Hello world, my name is John.', 30*8))
  #
  # Perhaps, then, we would want to replace John with a
  # symbolic variable. We would call:
  #
  # hello_txt_backing_memory.store(24, claripy.BVS('symbolic_name', 4*8))
  #
  # Then, after the program calls fopen('hello.txt', 'r') and then
  # fread(buffer, sizeof(char), 30, hello_txt_file), the buffer would contain
  # the string from the file, except four symbolic bytes replacing the
  # underscores.
  # (!)
  password = claripy.BVS('password', symbolic_file_size_bytes * 8)
  symbolic_file_backing_memory.store(???, password)

  # Construct the symbolic file. The file_options parameter specifies the Linux
  # file permissions (read, read/write, binary, etc.) The content parameter
  # specifies from where the stream of data should be supplied. If content is
  # an instance of SimSymbolicMemory (we constructed one above), the stream will
  # contain the contents (including any symbolic contents) of the memory,
  # beginning from address zero.
  file_options = 'r'
  password_file = simuvex.SimFile(filename, file_options, content=???, size=symbolic_file_size_bytes)

  # We have already created the file and the memory that stores the data that
  # the file will stream to the program, but we now need to tell Angr where the
  # file should appear to exist on the filesystem. This is a mapping between 
  # strings representing the filenames and the simuvex.SimFiles themselves. For
  # example, if hello_txt_file was a SimFile,
  # symbolic_filesystem = {
  #   'hello.txt' : hello_txt_file
  # }
  # would specify that any fopen('hello.txt', 'r') calls should stream data from
  # hello_txt_file.
  symbolic_filesystem = {
    filename : password_file
  }
  initial_state.posix.fs = symbolic_filesystem

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

    solution = good_path.state.se.any_str(password)

    print solution
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
