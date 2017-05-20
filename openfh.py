#!/usr/bin/env python
"""
PyCommand that opens a file handle under the debugged process

Place within PyCommands directory and type "!openfh <path_to_file>" in
the command bar in order to open a file handle for that file.  The new file
handle will be shown in the message box at the bottom of the window and
additional details will be written to the Log window (Alt + L). Registers
and CPU status flags should all be preserved.
"""
import immlib
import immutils

__VERSION__ = '1.1'
NAME = 'openfh'
DESC = 'Open a file handle under the debugged process'
COPYRIGHT = 'Copyright (c) 2009-2017 Bobby Noell'
LICENSE = 'MIT'

INVALID_HANDLE_VALUE = -1


def find_unused_memory(imm, size):
    """Find `size` bytes of unused executable memory

    :param imm: Debugger instance
    :param size: length of memory to find
    :return: memory address
    :raise: RuntimeError if not found
    """
    cave = '\x00' * size
    mod = imm.getModule(imm.getDebuggedName())
    pages = imm.getMemoryPageByOwnerAddress(mod.getBase())
    for page in pages:
        if immlib.PageFlags[page.getAccess()].find('E') >= 0:
            addr = page.search(cave)
            if addr:
                return addr[-1]
    raise RuntimeError('A suitable code cave was not found :-(')


def createfile(imm, filename):
    """Use kernel32.CreateFileA to open a file handle for `filename`

    :param imm: Debugger instance
    :param filename: path to file
    :return: file handle
    :raise: RuntimeError on error
    """
    # get address of CreateFileA
    createfile_addr = imm.getAddress('kernel32.CreateFileA')
    if createfile_addr <= 0:
        raise RuntimeError('Unable to find kernel32.CreateFileA')
    imm.log('  kernel32.CreateFileA found at 0x{:08x}'.format(createfile_addr), gray=True)

    # Find an unused section of executable memory that we can write code to
    shellcode_size = 0x26
    filename += '\0'
    cave_size = shellcode_size + len(filename)
    mem_addr = find_unused_memory(imm, cave_size)
    filename_offset = mem_addr + shellcode_size
    createfile_offset = createfile_addr - mem_addr - shellcode_size + 7  # 7 = PopFD+Push imm32+Retn

    # save registers
    old_regs = imm.getRegs()

    imm.log('  Writing {} bytes to code cave at 0x{:08x}'.format(cave_size, mem_addr), gray=True)

    # assemble the call to CreateFileA and write to our memory location
    # CreateFileA(
    #   FileName = <filename>
    #   Access = GENERIC_READ|GENERIC_WRITE
    #   ShareMode = 0
    #   Security = NULL
    #   Mode = OPEN_EXISTING
    #   Attributes = NORMAL
    #   TemplateFile = NULL
    # )
    asm = ' \
        PushFD                             \n\
        Xor     EAX, EAX                   \n\
        Push    EAX                        \n\
        Push    80                         \n\
        Push    3                          \n\
        Push    EAX                        \n\
        Push    EAX                        \n\
        Push    0xC0000000                 \n\
        Push    0x{:08x}                   \n\
        Call    0x{:08x}                   \n\
        PopFD                              \n\
        Push    0x{:08x}                   \n\
        Retn                               \n\
    '.format(filename_offset, createfile_offset, old_regs['EIP'])
    imm.writeMemory(mem_addr, imm.assemble(asm))
    # write the filename directly after our assembled code
    imm.writeMemory(filename_offset, filename)

    # manually set EIP to injected code and execute
    imm.log('  Executing call to kernel32.CreateFileA', gray=True)
    imm.setReg('EIP', mem_addr)
    imm.goSilent(True)
    imm.run(old_regs['EIP'])
    imm.goSilent(False)

    # save our file handle
    file_handle = imm.getRegs()['EAX']

    # restore registers
    for reg in old_regs:
        imm.setReg(reg, old_regs[reg])

    # restore memory
    imm.log('  Restoring {} NULL bytes to 0x{:08x}'.format(cave_size, mem_addr), gray=True)
    imm.writeMemory(mem_addr, '\x00' * cave_size)

    return immutils.sint32(file_handle)


def main(args):
    """PyCommand that opens a file handle under the debugged process

    :param args: arguments passed to the PyCommand
    :return: status string
    """
    imm = immlib.Debugger()
    imm.log('')
    if not args:
        imm.log('[ !openfh ]')
        return 'Usage: !openfh <path_to_file>'
    imm.log('[ !openfh -- {} ]'.format(args[0]))

    try:
        file_handle = createfile(imm, args[0])
    except RuntimeError as exception:
        return 'Error: {}'.format(exception.message)

    if file_handle == INVALID_HANDLE_VALUE:
        return 'Error opening file handle'

    return 'File handle opened for {}: {:x}h ({}d)'.format(args[0], file_handle, file_handle)

if __name__ == '__main__':
    print 'This module is for use within Immunity Debugger only'
