# PyCommands

PyCommands for Immunity Debugger that were written to get a better understanding of how something worked or to solve a specific problem.  To install, drop into the PyCommands directory where Immunity Debugger is installed.

## openfh

Opens a file handle under the debugged process.  Type `!openfh <path_to_file>` in the command box to run it.

The new file handle will be shown in the message box at the bottom of the window and additional details will be written to the Log window (Alt + L). Registers and CPU status flags should all be preserved.


## tlsloader

Loads a PE file, sets breakpoints on all TLS callback functions, and stops execution at the first TLS callback function. Type `!tlsloader <path_to_file>` in the command box to run it. Additional details will be written to the Log window (Alt + L).

Usage of this PyCommand on Windows XP requires you to configure the debugger to make its first pause at the system breakpoint (which not the default setting). To make this change, go to "Options" -> "Debugging options" -> [Events].  This should not be necessary on Windows 7.

If the PE file doesn't contain any TLS callback functions, execution will be paused at the entry point as defined in the debugger settings.

_Note:_ this script does not currently work on DLLs.