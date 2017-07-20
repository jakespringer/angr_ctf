#!/usr/bin/env pypy
import os

def package_level(level_directory, output_directory, binary_prefix, num_binaries, user, salt):
  seed = user + salt
  generate_filename = os.path.join(level_directory, 'generate.py')
  
