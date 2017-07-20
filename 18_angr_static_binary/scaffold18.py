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
# simuvex.SimProcedures['libc.so.6']['malloc']
# simuvex.SimProcedures['libc.so.6']['fopen']
# simuvex.SimProcedures['libc.so.6']['fclose']
# simuvex.SimProcedures['libc.so.6']['fwrite']
# simuvex.SimProcedures['libc.so.6']['getchar']
# simuvex.SimProcedures['libc.so.6']['strncmp']
# simuvex.SimProcedures['libc.so.6']['strcmp']
# simuvex.SimProcedures['libc.so.6']['__isoc99_scanf']
# simuvex.SimProcedures['libc.so.6']['printf']
# simuvex.SimProcedures['libc.so.6']['puts']
# simuvex.SimProcedures['libc.so.6']['exit']
# There are many more, see:
# https://github.com/angr/simuvex/tree/master/simuvex/procedures/libc___so___6
