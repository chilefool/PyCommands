#!/usr/bin/env python
"""
Immunity Debugger PyCommand that opens a file handle under the debugged process

Author: bobby@strayprocess.com

Usage: Place within PyCommands directory and type "!openfh <path_to_file>" in
  the command bar in order to open a file handle for that file.  The new file
  handle will be shown in the message box at the bottom of the window and
  additional details will be written to the Log window (Alt + L). Registers and
  CPU status flags should all be preserved.

Revision History:
  11/15/2009, v1.0 - Initial public release

"""

__VERSION__ = '1.0'

import immlib
from immutils import *

DESC= "Open a file handle under the debugged process"

# find an unused section of memory that we can write code to
def find_memory_addr(imm, size):
    cave = '\x00' * size
    mod = imm.getModule(imm.getDebuggedName())
    pages = imm.getMemoryPagebyOwnerAddress(mod.getBase())
    for page in pages:
        addr = page.search(cave)
        if addr:
            return addr[0]
    return 0

# use CreateFileA to open a file handle for filename
def createfile(imm, filename):
    # get address of CreateFileA
    createfile_addr = imm.getAddress("kernel32.CreateFileA")
    if(createfile_addr <= 0):
        imm.Log("  Error: kernel32.CreateFileA not found", gray=True)
        return "Error: kernel32.CreateFileA not found"
    imm.Log("  kernel32.CreateFileA found at 0x%08x" % createfile_addr, gray=True)
    
    shellcode_size = 0x25
    mem_addr = find_memory_addr(imm, shellcode_size + len(filename))
    if not mem_addr:
        imm.Log("  Error: a suitable code cave was not found :-(", gray=True)
        return "Error: a suitable code cave was not found :-("
    
    filename_offset = mem_addr + shellcode_size
    createfile_offset = createfile_addr - mem_addr - shellcode_size + 6 # 6 = PushFD + Jmp rel32

    # save registers and calculate offset for Jmp back to origin
    old_regs = imm.getRegs()
    origin_offset = sint32(old_regs['EIP'] - filename_offset)
    
    imm.Log("  Writing %d bytes to code cave at 0x%08x" % (shellcode_size + \
        len(filename), mem_addr), gray=True)
    
    # assemble the call to CreateFileA and write to our memory location
    # CreateFileA(
    #   FileName = <filename>
    #   Access = GENERIC_READ|GENERIC_WRITE
    #   ShareMode = 0
    #   Security = NULL
    #   Mode = OPEN_EXISTING
    #   Attributes = NORMAL
    #   TemplateFile = NULL
    #)
    asm = " \
        PushFD                             \n\
        Xor     EAX, EAX                   \n\
        Push    EAX                        \n\
        Push    80                         \n\
        Push    3                          \n\
        Push    EAX                        \n\
        Push    EAX                        \n\
        Push    0xC0000000                 \n\
        Push    0x%08x                     \n\
        Call    0x%08x                     \n\
        PopFD                              \n\
        DB     0xE9                        \n\
        DD     0x%08x                      \n\
    " % (filename_offset, createfile_offset, origin_offset)
    imm.writeMemory(mem_addr, imm.Assemble(asm))
    # write the filename directly after our assembled code
    imm.writeMemory(filename_offset, filename)
    
    # go to injected code and execute
    imm.setReg('EIP', mem_addr)
    imm.stepIn() # Run(addr) doesn't seem to work right sometimes without stepping first????
    imm.Run(old_regs['EIP'])
    
    # save our file handle
    file_handle = imm.getRegs()['EAX']
    
    # restore registers
    for reg in old_regs:
        imm.setReg(reg, old_regs[reg])
    
    return sint32(file_handle)
    
def main(args): 
    imm = immlib.Debugger()
    imm.Log("")
    if not args:
        imm.Log("[ !openfh ]")
        imm.Log("  Usage: !openfh <path_to_file>", gray=True)
        return "Usage: !openfh <path_to_file>"
    imm.Log("[ !openfh -- %s ]" % args[0])
    filename = args[0]+"\0"

    # make sure kernel32.dll is loaded
    mod = imm.getModule("kernel32.dll")
    if not mod:
        imm.Log("  Error: kernel32.dll not found", gray=True)
        return "Error: kernel32.dll not found"   
    
    # attempt to open a file handle
    file_handle = createfile(imm, filename)
    
    if file_handle <= 0:
        imm.Log("  Call to CreateFile failed", gray=True)
        return "Error opening file handle"
    imm.Log("  Opened file handle %xh (%dd)" % (file_handle, file_handle), gray=True)
    return "File handle: %xh (%dd)" % (file_handle, file_handle)
    
    
if __name__=="__main__":
    print "This module is for use within Immunity Debugger only" 
        