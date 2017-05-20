#!/usr/bin/env python
"""
Immunity Debugger PyCommand that opens a PE file and sets breakpoints on all TLS
  callback functions

Author: bobby@strayprocess.com

Usage: Place within PyCommands directory and type "!tlsloader <path_to_file>" in
  the command bar in order to load the PE file, set breakpoints on all TLS
  callback functions, and stop execution at the first TLS callback function.
  Additional details will be written to the Log window (Alt + L).
  
  Usage of this PyCommand requires you to configure the debugger to make its
  first pause at the system breakpoint (which not the default setting).  To make
  this change, go to "Options" -> "Debugging options" -> [Events].  I don't
  believe that the python API allows me to do this automatically (or at least I
  didn't find it).

  If the PE file doesn't contain any TLS callback functions, execution will be
  paused at the entry point as defined in the PE header.  Note: this script does
  not currently work on DLLs.

Revision History:
  4/22/2010, v1.0 - Initial public release

"""

__VERSION__ = '1.0'

import immlib
import pefile

DESC= "Open a PE file and set breakpoints on all TLS callback functions"

def main(args): 
    imm = immlib.Debugger()
    imm.Log("")
    if not args:
        imm.Log("[ !tlsloader ]")
        imm.Log("  Usage: !tlsloader <path_to_file>", gray=True)
        return "Usage: !tlsloader <path_to_file>"
    filename = args[0]

    # open the PE in Immunity Debugger
    imm.openProcess(filename)

    imm.Log("")
    imm.Log("[ !tlsloader -- %s ]" % filename)

    # load with pefile
    try:
        pe = pefile.PE(name = filename)
    except IOError:
        imm.Log("  Unable to open %s" % filename, gray=True)
        return "Unable to open %s" % filename
    except pefile.PEFormatError:
        imm.Log("  Unable to parse PE file: %s" % arg, gray=True)
        return "Unable to parse PE file: %s" % arg

    # exit if attempting to load a DLL
    if 0x2000 & pe.FILE_HEADER.Characteristics == 0x2000:
        imm.Log("  tlsloader cannot be used on DLL files", gray=True)
        return "tlsloader cannot be used on DLL files"

    # make sure that the PE actually has a TLS directory
    if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
        imm.Log("  Array of TLS callback functions at 0x%08x"
            % pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks, gray=True)

        callback_array_rva = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase 

        # read the array of TLS callbacks until we hit a NULL ptr (end of array)
        idx = 0
        callback_functions = [ ]
        while pe.get_dword_from_data(pe.get_data(callback_array_rva + 4 * idx, 4), 0):
            callback_functions.append(pe.get_dword_from_data(pe.get_data(callback_array_rva + 4 * idx, 4), 0))
            idx += 1

        # if we start with a NULL ptr, then there are no callback functions
        if idx == 0:
            # get the address of the entry point so we can skip to it
            ep = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint
            imm.Log("    * No TLS callback functions supported... executing until 0x%08x (EP)"
                % ep, gray=True)
            imm.Run(ep)
            return "No TLS callback functions supported"            
        else:
            for idx in range(len(callback_functions)):
                imm.Log("    * TLS callback function %i defined at 0x%08x"
                    % (idx, callback_functions[idx]), gray=True)
                imm.setBreakpoint(callback_functions[idx])
                imm.setComment(callback_functions[idx], "TLS callback %i" % idx)
                imm.setLabel(callback_functions[idx], "TLS_callback_%i" % idx)
            imm.Log("  Executing until first breakpoint", gray=True)
            
            # run until we hit a breakpoint (should be our first callback)
            imm.Run()
            return "Execution paused at first TLS callback function"

    else:
        # get the address of the entry point so we can skip to it
        ep = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint
        imm.Log("  No TLS Directory found... executing until 0x%08x (EP)"
            % ep, gray=True)
        imm.Run(ep)
        return "No TLS directory found"
   
if __name__=="__main__":
    print "This module is for use within Immunity Debugger only"     