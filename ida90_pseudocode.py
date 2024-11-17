#!/usr/bin/env python3
import os
import ida
import idaapi
import argparse
import ida_segment

### List the segments for the loaded binary
def list_segments():
    nb_items = ida_segment.get_segm_qty()
    print("Segments number:",  nb_items)
    for i in range(0, nb_items):
        seg_src = ida_segment.getnseg(i)
        print(str(i+1) + ".")
        print("\tname:", ida_segment.get_segm_name(seg_src))
        print("\tstart_address:", hex(seg_src.start_ea))
        print("\tend_address", hex(seg_src.end_ea))
        print("\tis_data_segment:", ida_segment.get_segm_class(seg_src) == ida_segment.SEG_DATA)
        print("\tbitness:", seg_src.bitness)
        print("\tpermissions:",  seg_src.perm, "\n")

# Parse input arguments
parser=argparse.ArgumentParser(description="Generate C pseudocode")
parser.add_argument("-f", "--file", help="IDA Database for Decompilation", type=str, required=True)

args=parser.parse_args()

# Run auto analysis on the input file
print(f"Opening database {args.file}...")
ida.open_database(args.file, False)

# Ensure the Hex-Rays decompiler is initialized
if not idaapi.init_hexrays_plugin():
    print("Hex-Rays decompiler is not available!")
    ida.close_database(save=False)
    exit()

# Prepare the function addresses
funcaddrs = idaapi.eavec_t()
for func_ea in range(idaapi.get_entry_qty()):
    entry_ea = idaapi.get_entry(func_ea)
    if entry_ea != idaapi.BADADDR:
        funcaddrs.push_back(entry_ea)

# Perform batch decompilation to generate C pseudocode
base_name, _ = os.path.splitext(os.path.basename(args.file))
output_file = f"{base_name}.c"
try:
    print(f"Generating C pseudocode")
    success = idaapi.decompile_many(output_file, funcaddrs, 0)
    if success:
        print(f"Decompilation success.")
    else:
        print(f"Decompilation failed. Check the log for details.")
except Exception as e:
    print(f"An error occurred: {e}")
finally:
    # Cleanup reference object
    del funcaddrs

# List segments
print("Listing segments...")
list_segments()

# Let the idb in a consistent state, explicitly terminate the database
print("Closing database...")
ida.close_database(save=False)