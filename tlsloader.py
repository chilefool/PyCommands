#!/usr/bin/env python
"""
PyCommand that opens an EXE and sets breakpoints on all TLS callback functions

Place within PyCommands directory and type "!tlsloader <path_to_file>" in
the command bar in order to load the PE file, set breakpoints on all TLS
callback functions, and stop execution at the first TLS callback function.
Additional details will be written to the Log window (Alt + L).

Usage of this PyCommand on Windows XP requires you to configure the debugger to
make its first pause at the system breakpoint (which not the default setting).
To make this change, go to "Options" -> "Debugging options" -> [Events].  This
should not be necessary on Windows 7.

If the PE file doesn't contain any TLS callback functions, execution will be
paused at the entry point as defined in the debugger settings.

Note: this script does not currently work on DLLs.
"""
import immlib
import pefile

__VERSION__ = '1.1'
NAME = 'tlsloader'
DESC = 'Open an EXE and set breakpoints on all TLS callback functions'
COPYRIGHT = 'Copyright (c) 2010-2017 Bobby Noell'
LICENSE = 'MIT'


def set_breakpoints(imm, callback_functions):
    """Set breakpoints on each callback function

    :param imm: Debugger instance
    :param callback_functions: list of callback addresses
    :return: None
    """
    for idx in range(len(callback_functions)):
        imm.setBreakpoint(callback_functions[idx])
        imm.setComment(callback_functions[idx], 'TLS callback {}'.format(idx))
        imm.setLabel(callback_functions[idx], 'TLS_callback_{}'.format(idx))


def main(args):
    """PyCommand that opens an EXE and sets breakpoints on all TLS callback functions

    :param args: arguments passed to the PyCommand
    :return: status string
    """
    imm = immlib.Debugger()
    imm.log('')
    if not args:
        imm.log('[ !tlsloader ]')
        return 'Usage: !tlsloader <path_to_file>'
    filename = args[0]

    imm.log('')
    imm.log('[ !tlsloader -- {} ]'.format(filename))

    # load with pefile
    try:
        pe = pefile.PE(name=filename)
    except IOError as exception:
        return 'Error: Unable to open {} ({})'.format(filename, exception.message)
    except pefile.PEFormatError:
        return 'Error: Unable to parse {} as a PE file'.format(filename)

    # exit if attempting to load a DLL
    if 0x2000 & pe.FILE_HEADER.Characteristics == 0x2000:
        return 'Error: tlsloader cannot be used on DLL files'

    callback_functions = []
    # make sure that the PE actually has a TLS directory
    if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
        imm.log(
            '  Array of TLS callback functions at 0x{:08x}'.format(pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks),
            gray=True)
        callback_array_rva = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase

        # read the array of TLS callbacks until we hit a NULL ptr (end of array)
        idx = 0
        while pe.get_dword_from_data(pe.get_data(callback_array_rva + 4 * idx, 4), 0):
            callback_functions.append(pe.get_dword_from_data(pe.get_data(callback_array_rva + 4 * idx, 4), 0))
            imm.log('    * TLS callback function {} defined at 0x{:08x}'.format(idx, callback_functions[idx]),
                    gray=True)
            idx += 1
        # if we start with a NULL ptr, then there are no callback functions
        if idx == 0:
            imm.log('    * No TLS callback functions defined', gray=True)

    imm.openProcess(filename)
    if callback_functions:
        if imm.getOsVersion() == 'xp':
            # ensure we get to system breakpoint
            imm.run(callback_functions[0])
        else:
            # should pause at ntdll!RtlUserThreadStart on Win7
            imm.pause()

        set_breakpoints(imm, callback_functions)
        imm.run(callback_functions[0])
        imm.pause()
        return 'Execution paused at first TLS callback function'
    return 'No TLS callback functions found'

if __name__ == '__main__':
    print 'This module is for use within Immunity Debugger only'
