# Angr CTF

This project contains Angr CTFs covering topics from basics to intermediate.

It is recommended to check the presentation (`SymbolicExecution.pptx`) under the docs before getting started with Angr.

## Contents

- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
  * [Bootstrapping Angr CTFs](#bootstrapping-angr-ctfs)
  * [Solving the CTFs](#solving-the-ctfs)
- [Contributing](#contributing)
- [Authors](#authors)
- [License](#license)


## Prerequisites

- Docker

## Getting Started

### Bootstrapping Angr CTFs

To bootstrap the CTF projects:
```sh
./bootstrap.sh
```

It will create the projects per generation in order to distribute the CTFs per person, so that the offsets and passwords of each target binary are unique.

This will generate the workspace for starting to work with Angr:
```
ctfs
├── 00_angr_find
│   ├── bin
│   └── solver.py
├── 01_angr_avoid
│   ├── bin
│   └── solver.py
├── 02_angr_find_condition
│   ├── bin
│   └── solver.py
├── 03_angr_symbolic_registers
│   ├── bin
│   └── solver.py
├── 04_angr_symbolic_stack
│   ├── bin
│   └── solver.py
├── 05_angr_symbolic_memory
│   ├── bin
│   └── solver.py
├── 06_angr_symbolic_dynamic_memory
│   ├── bin
│   └── solver.py
├── 07_angr_symbolic_file
│   ├── bin
│   └── solver.py
├── 08_angr_constraints
│   ├── bin
│   └── solver.py
├── 09_angr_hooks
│   ├── bin
│   └── solver.py
├── 10_angr_simprocedures
│   ├── bin
│   └── solver.py
├── 11_angr_sim_scanf
│   ├── bin
│   └── solver.py
├── 12_angr_veritesting
│   ├── bin
│   └── solver.py
├── 13_angr_static_binary
│   ├── bin
│   └── solver.py
├── 14_angr_shared_library
│   ├── bin
│   ├── libbin.so
│   └── solver.py
├── 15_angr_arbitrary_read
│   ├── bin
│   └── solver.py
├── 16_angr_arbitrary_write
│   ├── bin
│   └── solver.py
└── 17_angr_arbitrary_jump
    ├── bin
    └── solver.py
```

It's very much encouraged to create a separate repository out of the bootstrapped `ctfs` directory, since we don't want to lose work by all means.

Let's get started by mounting the `ctfs` directory from the host-machine into a docker container so that we'll have all the necessary environment to work with Angr:
```sh
docker run -it --rm --mount src="$(pwd)/ctfs",target="/home/angr_ctf/ctfs",type=bind --name angr_ctf angr_ctf
```

Since the directory is mounted inside the container, all changes between the host-machine and the container will immediately reflect each other (`type=bind`).


### Solving the CTFs

The CTFs are ordered by the difficulty level, meaning from `00_angr_find` is the easiest to `17_angr_arbitrary_jump` hardest. This is in order to progress while getting familiar with Angr ecosystem.

In each CTF there is a `solver.py` file and `bin` file for the executable requesting a password to tell you whether you manage to get it right, while other (`14_angr_shared_library`) could also have a `libbin.so` file containing a library the `bin` file using.

The task is to go through each `solver.py` and wherever the `???` characters are present, it requests to fill in the correct answer. In most cases it will be described with a long comment above it to know what to expect, e.g. requesting a specific offset within the binary in order to find the correct password.

## Contributing

Pull-Requests are greatly appreciated should you like to contribute to the project.

Same goes for opening issues; if you have any suggestions, feedback or you found any bugs, please do not hesitate to open an issue.

## Authors

* **Jacob Springer** - *Initial work* - [jakespringer](https://github.com/jakespringer)

See also the list of [contributors](https://github.com/giladreich/angr_ctf/graphs/contributors) who participated in this project.

## License

This project is licensed under the GPL-3.0 License - see the [license](/LICENSE) for more details.
