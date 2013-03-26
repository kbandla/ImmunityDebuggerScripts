#!/usr/bin/env python

#-------------------------------------------------------------------------------
# Malware Analysis BreakPoint Manager
#
# jax will set all breakpoints and add a comment to indicate the 
# breakpoint's name
#
# TODO: Implement code for enabling Breakpoints based on Priority
# (Each BreakPoint has a Priority assoicated with it.)
# Copyright (C) 2010-2011 Kiran Bandla <kbandla@in2void.com>
#-------------------------------------------------------------------------------

__VERSION__  = '0.01'
NAME        = 'jax'
DESC        = 'Applies breakpoints on some important addresses.'
COPYRIGHT   = '(C) 2010-2011 Kiran Bandla, <kbandla@in2void.com>'
LICENSE     = 'WTFPL'

import immlib
functions = {}
functions['kernel32.dll']	=   [   ('LoadLibraryA',3),
                                    ('LoadLibraryW',3),
                                    ('IsDebuggerPresent',1),
                                    ('Sleep',1),
                                    ('CreateProcessA',3),
                                    ('CreateProcessW',3),
                                    ('CreateThread',3),
                                    ('CreateRemoteThread',3),
                                    ('ShellExecuteW',1),
                                    ('TerminateProcess',1),
                                    ('ExitProcess',1),
                                    ('CreateThread',1),
                                    ('CreateRemoteThread',1),
                                    ('ReadProcessMemory',1),
                                    ('WriteProcessMemory',1),
                                    ('VirtualAlloc',1),
                                    ('VirtualAllocEx',1),
                                    ('WriteProcessMemory',1),
                                    ('ReadProcessMemory',1),
                                    ('CreateFileW',1),
                                    ('DeleteFileW',1),
                                    ('MoveFileExW',1),
                                    ('ReadFile',1),
                                    ('WriteFile',1),
                                    ('CopyFile',1),
                                    ('CreateMutexW',1),
                                    ('OpenMutexW',1),
                                    ('ReleaseMutex',1),
                                ]

functions['user32.dll']     =   [   ('ExitWindowsEx',1)
                                ]

functions['shell32.dll']    =   [   ('ShellExecuteExW',1),
                                ]

functions['urlmon.dll']		=   [   ('URLDownloadToFileW',1),
                                    ('InternetOpenUrlW',1)
				                ]

functions['wininet.dll']	=   [	('HttpSendRequest',1),
                                    ('HttpSendRequestEx',1)
				                ]

functions['advapi32.dll']   =   [   ('RegOpenKeyW',1),
                                    ('RegCreateKeyW',1),
                                    ('RegDeleteKeyW',1),
                                    ('RegEnumKeyExW',1),
                                    ('RegEnumValueW',1),
                                    ('RegSetValueExW',1),
                                    ('OpenSCManagerW',1),
                                    ('CreateServiceA',1),
                                    ('CreateServiceW',1),
                                    ('OpenServiceW',1),
                                    ('StartServiceW',1),
                                    ('ControlService',1),
                                ]
                                        

def main(args):
    imm = immlib.Debugger()
    target = imm.getDebuggedName()
    modules = imm.getAllModules()
    for name, value in modules.items():
        name = name.lower()
        if functions.has_key(name):
            funcs = functions[name]
            name = name.strip('.dll')
            for func in funcs:
                imm.log('Adding breakpoint at %s::%s..'%(name, func[0]))
                try:
                    # Add a breakpoint, and the function name as the comment
                    imm.setBreakpointOnName('%s.%s'%(name,func[0]))
                    imm.setComment(imm.getAddress('%s.%s'%(name,func[0])), '%s.%s'%(name,func[0]))
                except Exception,e:
                    pass
    #At this point, breakpoints are all set.

    # Enable All_Debug options from hidedebug
    import hidedebug
    hidedebug.main(['All_debug'])

    # Output the SEH Chain and handlers
    if imm.getSehChain():
        imm.log('%8s %8s'%('SEH','Handler'))
        for seh in imm.getSehChain():
            imm.log('%08X %08X'%(seh[0],seh[1]))

    #imm.run()
    return 'Done'
