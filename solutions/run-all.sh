#!/bin/bash
echo "Solving all of the levels... This could take a while."
ANGR_OUT_00="$(python3 00_angr_find/solver.py 00_angr_find/bin 2> /dev/null)"
echo -n "."
ANGR_OUT_01="$(python3 01_angr_avoid/solver.py 01_angr_avoid/bin 2> /dev/null)"
echo -n "."
ANGR_OUT_02="$(python3 02_angr_find_condition/solver.py 02_angr_find_condition/bin 2> /dev/null)"
echo -n "."
ANGR_OUT_03="$(python3 03_angr_symbolic_registers/solver.py 03_angr_symbolic_registers/bin 2> /dev/null)"
echo -n "."
ANGR_OUT_04="$(python3 04_angr_symbolic_stack/solver.py 04_angr_symbolic_stack/bin 2> /dev/null)"
echo -n "."
ANGR_OUT_05="$(python3 05_angr_symbolic_memory/solver.py 05_angr_symbolic_memory/bin 2> /dev/null)"
echo -n "."
ANGR_OUT_06="$(python3 06_angr_symbolic_dynamic_memory/solver.py 06_angr_symbolic_dynamic_memory/bin 2> /dev/null)"
echo -n "."
ANGR_OUT_07="$(python3 07_angr_symbolic_file/solver.py 07_angr_symbolic_file/bin 2> /dev/null | tr -d '\0')"
echo -n "."
ANGR_OUT_08="$(python3 08_angr_constraints/solver.py 08_angr_constraints/bin 2> /dev/null)"
echo -n "."
ANGR_OUT_09="$(python3 09_angr_hooks/solver.py 09_angr_hooks/bin 2> /dev/null)"
echo -n "."
ANGR_OUT_10="$(python3 10_angr_simprocedures/solver.py 10_angr_simprocedures/bin 2> /dev/null)"
echo -n "."
ANGR_OUT_11="$(python3 11_angr_sim_scanf/solver.py 11_angr_sim_scanf/bin 2> /dev/null)"
echo -n "."
ANGR_OUT_12="$(python3 12_angr_veritesting/solver.py 12_angr_veritesting/bin 2> /dev/null)"
echo -n "."
ANGR_OUT_13="$(python3 13_angr_static_binary/solver.py 13_angr_static_binary/bin 2> /dev/null)"
echo -n "."
ANGR_OUT_14="$(python3 14_angr_shared_library/solver.py 14_angr_shared_library/lib14_angr_shared_library.so 2> /dev/null)"
echo -n "."
ANGR_OUT_15="$(python3 15_angr_arbitrary_read/solver.py 15_angr_arbitrary_read/bin 2> /dev/null)"
echo -n "."
ANGR_OUT_16="$(python3 16_angr_arbitrary_write/solver.py 16_angr_arbitrary_write/bin 2> /dev/null)"
echo -n "."
ANGR_OUT_17="$(python3 17_angr_arbitrary_jump/solver.py 17_angr_arbitrary_jump/bin 2> /dev/null)"
echo -n "."
echo ""
echo "-- Solutions --"
echo "00: $ANGR_OUT_00"
echo $ANGR_OUT_00 | 00_angr_find/bin
echo "01: $ANGR_OUT_01"
echo $ANGR_OUT_01 | 01_angr_avoid/bin
echo "02: $ANGR_OUT_02"
echo $ANGR_OUT_02 | 02_angr_find_condition/bin
echo "03: $ANGR_OUT_03"
echo $ANGR_OUT_03 | 03_angr_symbolic_registers/bin
echo "04: $ANGR_OUT_04"
echo $ANGR_OUT_04 | 04_angr_symbolic_stack/bin
echo "05: $ANGR_OUT_05"
echo $ANGR_OUT_05 | 05_angr_symbolic_memory/bin
echo "06: $ANGR_OUT_06"
echo $ANGR_OUT_06 | 06_angr_symbolic_dynamic_memory/bin
echo "07: $ANGR_OUT_07"
echo $ANGR_OUT_07 | 07_angr_symbolic_file/bin
echo "08: $ANGR_OUT_08"
echo $ANGR_OUT_08 | 08_angr_constraints/bin
echo "09: $ANGR_OUT_09"
echo $ANGR_OUT_09 | 09_angr_hooks/bin
echo "10: $ANGR_OUT_10"
echo $ANGR_OUT_10 | 10_angr_simprocedures/bin
echo "11: $ANGR_OUT_11"
echo $ANGR_OUT_11 | 11_angr_sim_scanf/bin
echo "12: $ANGR_OUT_12"
echo $ANGR_OUT_12 | 12_angr_veritesting/bin
echo "13: $ANGR_OUT_13"
echo $ANGR_OUT_13 | 13_angr_static_binary/bin
echo "14: $ANGR_OUT_14"
BACKUP_LD_LIBRARY_PATH=$LD_LIBRARY_PATH
export LD_LIBRARY_PATH=./14_angr_shared_library
echo $ANGR_OUT_14 | 14_angr_shared_library/bin
echo "15: $ANGR_OUT_15"
export LD_LIBRARY_PATH=$BACKUP_LD_LIBRARY_PATH
echo $ANGR_OUT_15 | 15_angr_arbitrary_read/bin
echo "16: $ANGR_OUT_16"
echo $ANGR_OUT_16 | 16_angr_arbitrary_write/bin
echo "17: $ANGR_OUT_17"
echo $ANGR_OUT_17 | 17_angr_arbitrary_jump/bin
