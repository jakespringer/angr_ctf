import angr
import claripy
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  start_address = ???
  initial_state = project.factory.blank_state(addr=start_address)

  # The binary is calling scanf("%8s %8s").
  # (!)
  password0 = claripy.BVS('password0', ???)
  ...

  # Instead of telling the binary to write to the address of the memory
  # allocated with malloc, we can simply fake an address to any unused block of
  # memory and overwrite the pointer to the data. This will point the pointer
  # with the address of pointer_to_malloc_memory_address0 to fake_heap_address.
  # Be aware, there is more than one pointer! Analyze the binary to determine
  # global location of each pointer.
  # Note: by default, Angr stores integers in memory with big-endianness. To
  # specify to use the endianness of your architecture, use the parameter
  # endness=project.arch.memory_endness. On x86, this is little-endian.
  # (!)
  fake_heap_address0 = ???
  pointer_to_malloc_memory_address0 = ???
  initial_state.store(pointer_to_malloc_memory_address0, fake_heap_address0, endness=project.arch.memory_endness)
  ...

  # Store our symbolic values at our fake_heap_address. Look at the binary to determine the offsets from the
  # fake_heap_address where scanf writes.
  # (!)
  initial_state.memory.store(fake_heap_address0, password0)
  ...

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

    solution0 = good_path.state.se.any_str(password0)
    ...
    solution = ???

    print solution
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
