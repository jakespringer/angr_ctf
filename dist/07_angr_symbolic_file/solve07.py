import angr
import claripy
import simuvex
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  start_address = 0x80488ef
  initial_state = project.factory.blank_state(addr=start_address)

  # Specify some information needed to construct a symbolic file. For this
  # challenge, the symbolic filename can be hardcoded, but in theory, it could
  # be symbolic. Note: to read from the file, the binary calls
  # 'fscanf(file, "%64s")'.
  # (!)
  filename = 'TKNJAHOR.txt'  # :string
  symbolic_file_size_bytes = 8

  # Construct the symbolic memory from and to which the file will read and
  # write. Also, associate the memory with the initial_state.
  symbolic_file_backing_memory = simuvex.SimSymbolicMemory()
  symbolic_file_backing_memory.set_state(initial_state)

  # Construct a bitvector for the password and then store it in the file's
  # backing memory. The store method works exactly the same as the store method
  # you have already used. In fact, it's the exact same method!
  # Hint: the binary reads the password starting from the beginning of the file.
  # (!)
  password = claripy.BVS('password', symbolic_file_size_bytes * 8)
  symbolic_file_backing_memory.store(0, password)

  # Construct the symbolic file. The file_options parameter specifies the Linux
  # file permissions (read, read/write, binary, etc.) The content parameter
  # specifies the memory from and to which the file should read, write, and
  # execute.
  file_options = 'r'
  password_file = simuvex.SimFile(filename, file_options, content=symbolic_file_backing_memory, size=symbolic_file_size_bytes)

  # Specify the filesystem with which to replace the operating system's
  # filesystem. This is a mapping between strings representing the filenames and
  # the simuvex.SimFiles themselves.
  symbolic_filesystem = {
    filename : password_file
  }

  # Overwrite the filesystem used by the state from the operating system's
  # default to the one constructed above.
  initial_state.posix.fs = symbolic_filesystem

  path_group = project.factory.path_group(initial_state)

  def is_successful(path):
    stdout_output = path.state.posix.dumps(sys.stdout.fileno())
    return 'Good' in stdout_output

  def should_abort(path):
    stdout_output = path.state.posix.dumps(sys.stdout.fileno())
    return 'Try' in stdout_output

  path_group.explore(find=is_successful, avoid=should_abort)

  if path_group.found:
    good_path = path_group.found[0]

    solution = good_path.state.se.any_str(password)

    print solution
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
