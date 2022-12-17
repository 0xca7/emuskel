"""
See this for a detailed description of python3 unicorn usage:
https://github.com/alexander-hanel/unicorn-engine-notes
thanks so much to alexander hanel for making this available.
"""

from unicorn import *
from unicorn.arm_const import *

from capstone import * 


"""
could use something like this to switch between ARM and Thumb mode
"""
EMULATION_MODES = {
    "Thumb": 0,
    "Arm": 1,
}

# code to be emulated
ARM_CODE   = b"\x37\x00\xa0\xe3\x03\x10\x42\xe0\x01\x00\x00\xef" # mov r0, #0x37; sub r1, r2, r3; svc 1;

# just in here to test thumb code if necessary
THUMB_CODE = b"\x83\xb0" # sub    sp, #0xc

# memory address where emulation starts
ADDRESS         = 0x8000
# stack addr and size
STACK_ADDRESS   = 0xffff0000
STACK_SIZE      = 0x1000


"""
get register information and dump it to stdout
"""
def dump_registers(uc):
    r0 = uc.reg_read(UC_ARM_REG_R0)
    r1 = uc.reg_read(UC_ARM_REG_R0)
    r2 = uc.reg_read(UC_ARM_REG_R0)
    r3 = uc.reg_read(UC_ARM_REG_R0)
    print("----------------------------------")
    print("| r0: 0x{:x} 0xr1: {:x}".format(r0, r1))
    print("| r2: 0x{:x} 0xr3: {:x}".format(r2, r3))
    print("| ...")


"""
trace instructions with this
"""
def hook_code(uc, address, size, user_data):

    print("[0x%x]> instruction size = 0x%x" %(address, size))

    code = uc.mem_read(address, size)

    # replace CS_MODE_ARM by CS_MODE_THUMB
    cs = Cs(CS_ARCH_ARM, CS_MODE_ARM)

    for i in cs.disasm(code, address):
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        dump_registers(uc)


"""
hook a specific instruction
"""
def hook_intr(uc, intno, user_data):
    print("[intr]> hit interrupt hook")


"""
the main emulation functionality
"""
def main(EMULATION_MODE=EMULATION_MODES["Arm"]):

    print("> starting emulation")

    try:

        # replace UC_MODE_ARM by UC_MODE_THUMB
        mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

        # map 1MB memory for this emulation
        mu.mem_map(ADDRESS, 1 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, ARM_CODE)

        # setup a stack
        mu.mem_map(STACK_ADDRESS, STACK_SIZE)
        # stack pointer
        mu.reg_write(UC_ARM_REG_R13, STACK_ADDRESS+STACK_SIZE-4)
        # link register
        mu.reg_write(UC_ARM_REG_R14, STACK_ADDRESS+STACK_SIZE-4)

        # tracing one instruction at ADDRESS with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code, 
            begin=ADDRESS, end=ADDRESS + len(ARM_CODE))

        # add a hook for interrupts, syscalls
        mu.hook_add(UC_HOOK_INTR, hook_intr, begin=ADDRESS, end=ADDRESS+len(ARM_CODE))

        mu.emu_start(ADDRESS, ADDRESS + len(ARM_CODE))

        print("Emulation done. Below is the CPU context")

    except UcError as e:
        print("ERROR: %s" % e)


if __name__ == '__main__':
    main()