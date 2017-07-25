import angr
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)
  initial_state = project.factory.entry_state()
  path_group = project.factory.path_group(initial_state)

  # Explore the binary, but this time, instead of only looking for a path that
  # eventually reaches the backdoor_address, also find a path that does not
  # cross will_not_succeed_address. The binary is pretty large, to save you
  # some time, everything you will need to look at is near the beginning of the
  # address space.
  # (!)
  backdoor_address = 0x80485e9
  will_not_succeed_address = 0x80485ac
  path_group.explore(find=backdoor_address, avoid=will_not_succeed_address)

  if path_group.found:
    good_path = path_group.found[0]
    print good_path.state.posix.dumps(sys.stdin.fileno())
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
