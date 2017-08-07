# This challenge is the exact same as the first challenge, except that it was
# compiled as a static binary. Normally, Angr automatically replaces standard
# library functions with SimProcedures that work much more quickly.
#
# To solve the challenge, manually hook any standard library c functions that
# are used. Then, ensure that you begin the execution at the beginning of the
# main function. Do not use entry_state.
# 
# Here are a few SimProcedures Angr has already written for you. They implement
# standard library functions. You will not need all of them:
# angr.SimProcedures['libc']['malloc']
# angr.SimProcedures['libc']['fopen']
# angr.SimProcedures['libc']['fclose']
# angr.SimProcedures['libc']['fwrite']
# angr.SimProcedures['libc']['getchar']
# angr.SimProcedures['libc']['strncmp']
# angr.SimProcedures['libc']['strcmp']
# angr.SimProcedures['libc']['__isoc99_scanf']
# angr.SimProcedures['libc']['printf']
# angr.SimProcedures['libc']['puts']
# angr.SimProcedures['libc']['exit']
#
# As a reminder, you can hook functions with something similar to:
# project.hook(malloc_address, angr.SimProcedures['libc']['malloc'])
#
# There are many more, see:
# https://github.com/angr/angr/tree/master/angr/procedures/libc
