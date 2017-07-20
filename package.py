#!/usr/bin/env pypy
import os, shutil

def level_generate_module(level_name):
  return __import__(level_name + '.generate')

def package_level(level_name, output_base_directory, num_binaries, user, salt, extra_files):
  seed = user + salt
  generate_module = level_generate_module(level_name)
  output_directory = os.path.join(output_base_directory, level_name)
  binary_file_output_prefix = os.path.join(output_directory, level_name)
  suffix_format_str = '{:0' + str(len(str(num_binaries - 1))) + '}'

  if not os.path.exists(output_directory):
    os.mkdir(output_directory)
  
  for i in xrange(num_binaries):
    suffix = suffix_format_str.format(i)
    binary_file_output = binary_file_output_prefix + suffix
    generate_module.generate.generate([None, seed, binary_file_output])

  for extra_file in extra_files:
    extra_file_abs = os.path.join('.', level_name, extra_file)
    extra_file_target = os.path.join(output_base_directory, level_name, extra_file)
    shutil.copyfile(extra_file_abs, extra_file_target)

def package_all():
  package_level('00_angr_find', 'dist', 8, 'jake', '2017', ['scaffold00.py'])
  package_level('02_angr_avoid', 'dist', 8, 'jake', '2017', ['scaffold02.py'])
  package_level('03_angr_find_condition', 'dist', 8, 'jake', '2017', ['scaffold03.py'])
  package_level('04_angr_symbolic_registers', 'dist', 8, 'jake', '2017', ['scaffold04.py'])
  package_level('05_angr_symbolic_stack', 'dist', 8, 'jake', '2017', ['scaffold05.py'])
  package_level('06_angr_symbolic_memory', 'dist', 8, 'jake', '2017', ['scaffold06.py'])
  package_level('07_angr_symbolic_heap', 'dist', 8, 'jake', '2017', ['scaffold07.py'])
  package_level('08_angr_symbolic_file', 'dist', 8, 'jake', '2017', ['scaffold08.py'])
  package_level('09_angr_constraints', 'dist', 8, 'jake', '2017', ['scaffold09.py'])
  package_level('10_angr_hooks', 'dist', 8, 'jake', '2017', ['scaffold10.py'])
  package_level('11_angr_sim_procedures', 'dist', 8, 'jake', '2017', ['scaffold11.py'])
  package_level('12_angr_locate_vulnerable', 'dist', 8, 'jake', '2017', ['scaffold12.py'])
  package_level('13_angr_unconstrained', 'dist', 8, 'jake', '2017', ['scaffold13.py'])
  package_level('17_angr_veritesting', 'dist', 8, 'jake', '2017', ['scaffold17.py'])
  package_level('18_angr_static_binary', 'dist', 8, 'jake', '2017', ['scaffold18.py'])
  package_level('19_angr_shared_library', 'dist', 8, 'jake', '2017', ['scaffold19.py']) 

if __name__ == '__main__':
  package_all()
