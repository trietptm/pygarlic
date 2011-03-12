#
#   Garlic.py
#
#   pyGarlic - Dll injection module for python
#   http://code.google.com/p/pygarlic/
#   Nativ.Assaf+pyGarlic@gmail.com
#   Copyright (C) 2011  Assaf Nativ
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>
#

import win32con
import struct
from ctypes import *

def ErrorIfZero(handle):
    if handle == 0:
        raise WinError()
    else:
        return handle
TRUE = c_char( 	chr( int( True  ) ) )
FALSE = c_char( chr( int( False ) ) )
void_NULL = c_void_p( win32con.NULL )
pchar_NULL = c_char_p( win32con.NULL )

GetCurrentProcess = windll.kernel32.GetCurrentProcess
GetCurrentProcess.argtypes = []
GetCurrentProcess.restype = ErrorIfZero

CloseHandle = windll.kernel32.CloseHandle
CloseHandle.argtypes = [ c_int ]
CloseHandle.restype = ErrorIfZero

OpenProcessToken = windll.advapi32.OpenProcessToken
OpenProcessToken.argtypes = [
    c_int,      # HANDLE ProcessHandle
    c_uint,     # DWORD DesiredAccess
    c_void_p ]  # PHANDLE TokenHandle
OpenProcessToken.restype = ErrorIfZero

AdjustTokenPrivileges = windll.advapi32.AdjustTokenPrivileges
AdjustTokenPrivileges.argtypes = [
    c_int,      # HANDLE TokenHandle
    c_int,      # BOOL DisableAllPrivileges
    c_void_p,   # PTOKEN_PRIVILEGES NewState
    c_uint,     # DWORD BufferLength
    c_void_p,   # PTOKEN_PRIVILEGES PreviousState
    c_void_p ]  # PDWORD ReturnLength
AdjustTokenPrivileges.restype = ErrorIfZero

LookupPrivilegeValue = windll.advapi32.LookupPrivilegeValueA
LookupPrivilegeValue.argtypes = [
    c_char_p,   # LPCTSTR lpSystemName
    c_char_p,   # LPCTSTR lpName
    c_void_p ]  # PLUID lpLuid
LookupPrivilegeValue.restype = ErrorIfZero

# CreateRemoteThread
CreateRemoteThread = windll.kernel32.CreateRemoteThread
CreateRemoteThread.argtypes = [
        c_uint,         # HANDLE hProcess
        c_void_p,       # LPSECURITY_ATTRIBUTES lpThreadAttributes
        c_uint,         # SIZE_T dwStackSize
        c_void_p,       # LPTHREAD_START_ROUTINE lpStartAddress
        c_void_p,       # LPVOID lpParameter
        c_uint,         # DWORD dwCreationFlags
        c_void_p ]      # LPDWORD lpThreadId        
CreateRemoteThread.restype = ErrorIfZero

OpenProcess = windll.kernel32.OpenProcess
OpenProcess.argtypes = [
        c_uint,         # DWORD dwDesiredAccess
        c_uint,         # BOOL bInheritHandle
        c_uint ]        # DWORD dwProcessId
OpenProcess.restype = ErrorIfZero

# LoadLibrary
LoadLibrary = windll.kernel32.LoadLibraryA
LoadLibrary.argtypes = [ c_char_p ]
LoadLibrary.restype = ErrorIfZero

# GetProcAddress
GetProcAddress = windll.kernel32.GetProcAddress
GetProcAddress.argtypes = [
        c_uint,         # HMOUDLE hModule
        c_char_p ]      # LPCSTR lpProcName
GetProcAddress.restype = ErrorIfZero

# VirtualAllocEx
VirtualAllocEx = windll.kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = [
        c_uint,         # HANDLE hProcess
        c_void_p,       # LPVOID lpAddress
        c_uint,         # SIZE_T dwSize
        c_uint,         # DWORD flAllocationType
        c_uint ]        # DWORD flProtect
VirtualAllocEx.restype = ErrorIfZero

# WriteProcessMemory
WriteProcessMemory = windll.kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = [
        c_uint,         # HANDLE hProcess
        c_uint,         # LPVOID lpBaseAddress
        c_char_p,       # LPCVOID lpBuffer
        c_uint,         # SIZE_T nSize
        c_void_p ]      # SIZE_T* lpNumberOfBytesWritten
WriteProcessMemory.restype = ErrorIfZero

CreateProcess = windll.kernel32.CreateProcessA
CreateProcess.argtypes = [
        c_char_p,       # LPCTSTR lpApplicationName
        c_void_p,       # LPTSTR lpCommandLine
        c_void_p,       # LPSECURITY_ATTRIBUTES lpProcessAttributes
        c_void_p,       # LPSECURITY_ATTRIBUTES lpThreadAttributes
        c_char,         # BOOL bInheritHandles
        c_uint,         # DWORD dwCreationFlags
        c_void_p,       # LPVOID lpEnvironment
        c_char_p,       # LPCTSTR lpCurrentDirectory
        c_void_p,       # LPSTARTUPINFO lpStartupInfo
        c_void_p ]      # LPPROCESS_INFORMATION lpProcessInformation
CreateProcess.restype = ErrorIfZero

ResumeThread = windll.kernel32.ResumeThread
ResumeThread.argtypes = [c_uint]
ResumeThread.restype = c_uint


class LUID( Structure ):
    _fields_ = [
            ('LowPart',         c_uint),
            ('HighPart',        c_uint)]

class TOKEN_PRIVILEGES( Structure ):
    _fields_ = [
            ('PrivilegeCount',  c_uint),
            ('Luid',            LUID),
            ('Attributes',      c_uint) ]

class STARTUPINFO( Structure ):
	_fields_ = [
		('cb',			c_uint),
		('lpReserved',		c_char_p),
		('lpDesktop',		c_char_p),
		('lpTitle',		c_char_p),
		('dwX',			c_uint),
		('dwY',			c_uint),
		('dwXSize',		c_uint),
		('dwYSize',		c_uint),
		('dwXCountChars',	c_uint),
		('dwYCountChars',	c_uint),
		('dwFillAttribute',	c_uint),
		('dwFlags',		c_uint),
		('wShowWindow',		c_ushort),
		('cbReserved2',		c_ushort),
		('lpReserved2', 	c_void_p),
		('hStdInput',		c_int),
		('hStdOutput',		c_int),
		('hStdError',		c_int) ]

class PROCESS_INFORMATION( Structure ):
	_fields_ = [
		('hProcess',	c_int),
		('hThread',	c_int),
		('dwProcessId',	c_uint),
		('dwThreadId',	c_uint) ]

class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [("BaseAddress", c_void_p),
                ("AllocationBase", c_void_p),
                ("AllocationProtect", c_uint),
                ("RegionSize", c_longlong),
                ("State", c_uint),
                ("Protect", c_uint),
                ("Type", c_uint),]

class SECURITY_ATTRIBUTES(Structure):
    _fields_ = [("Length", c_uint),
                ("SecDescriptor", c_void_p),
                ("InheritHandle", c_uint)]
    
REMOTE_BUFFER_SIZE = 0x200

def printIfVerbos(text, isVerbos):
    if isVerbos:
        print(text)

def injectDll( process_id, dllName, LoadLibraryA_address=-1, isVerbos=False ):
    if len(dllName) > 0x100:
        print("Dll name to long")
        return

    access_token = c_int(0)
    privileges = TOKEN_PRIVILEGES()

    OpenProcessToken( GetCurrentProcess(), win32con.TOKEN_QUERY | win32con.TOKEN_ADJUST_PRIVILEGES, byref(access_token) )
    access_token = access_token.value
    LookupPrivilegeValue( None, "SeDebugPrivilege", byref(privileges.Luid) )
    privileges.PrivilegeCount = 1
    privileges.Attributes = 2
    AdjustTokenPrivileges(
            access_token,
            0,
            byref(privileges),
            0,
            None,
            None )
    CloseHandle( access_token )

    printIfVerbos("Opening the target process", isVerbos)
    remoteProcess = \
            OpenProcess(
                        #win32con.PROCESS_CREATE_THREAD | win32con.PROCESS_VM_OPERATION | win32con.PROCESS_VM_WRITE,
                        win32con.PROCESS_ALL_ACCESS,
                        win32con.FALSE,
                        process_id )
    __injectAndExecute(remoteProcess, dllName, LoadLibraryA_address, isVerbos=isVerbos)
    CloseHandle(remoteProcess)
 
def __injectAndExecute( remoteProcess, dllName, LoadLibraryA_address=-1, creationFalgs=0, isVerbos=False ):
    printIfVerbos("Allocating memory inside remote process", isVerbos)
    remote_memory_address = \
        VirtualAllocEx( remoteProcess,
                        None,
                        REMOTE_BUFFER_SIZE,
                        win32con.MEM_COMMIT,
                        win32con.PAGE_EXECUTE_READWRITE )
    printIfVerbos("Memory allocated at 0x%x" % remote_memory_address, isVerbos)
    printIfVerbos("Writting the dll name to remote process", isVerbos)
    bytes_written = c_uint(0)
    WriteProcessMemory(
                    remoteProcess,
                    remote_memory_address,
                    dllName + '\x00',
                    len(dllName) + 1,
                    byref(bytes_written))
    if bytes_written.value != (len(dllName) + 1):
        print("Unable to write to process memory")
        return

    if -1 == LoadLibraryA_address:
        printIfVerbos("Verifing the LoadLibrary proc address", isVerbos)
        kernel32lib = LoadLibrary( "kernel32.dll" )
        LoadLibraryA_address = \
            GetProcAddress( kernel32lib,
                            "LoadLibraryA" )
        printIfVerbos("LoadLibraryA found in 0x%x" % LoadLibraryA_address, isVerbos)
        # We can assume that kernel32 is loaded in the same place in every process
        # because it's the first dll to be loaded in every process

    printIfVerbos('Generating loading code', isVerbos)
    code = '\x68'       # Push
    code += struct.pack('=l', remote_memory_address)
    code += '\xb8'      # mov eax,
    code += struct.pack('=l', LoadLibraryA_address)
    code += '\xff\xd0'  # call eax
    code += '\x3c\xc0'  # xor eax,eax
    code += '\xc3'      # retn
    WriteProcessMemory(
            remoteProcess,
            remote_memory_address + 0x100,
            code,
            len(code),
            byref(bytes_written))
    if bytes_written.value != len(code):
        print('Unable to write code')
        return

    printIfVerbos("Creating remote thread on LoadLibrary", isVerbos)
    remote_thread_id = c_uint(0)
    remote_thread = CreateRemoteThread( \
                        remoteProcess,
                        None,
                        0,
                        remote_memory_address + 0x100,
                        remote_memory_address,
                        creationFalgs,
                        byref(remote_thread_id) )
    printIfVerbos("Thread %d created" % remote_thread_id.value, isVerbos)
    return remote_thread

def createProcessWithDll(
        cmdLine, 
        dll, 
        securityAttributes=None, 
        threadAttributes=None, 
        inheritHandles=0, 
        creationFalgs=win32con.NORMAL_PRIORITY_CLASS, 
        environment=None, 
        currentDirectory=None,
        startupInfo=None,
        processInfo=None,
        isVerbos=False ):

    cmdLine = c_char_p(cmdLine)
    if None == startupInfo:
        startupInfo = STARTUPINFO()
        startupInfo.dwFlags = 0
        startupInfo.wShowWindow = 0x0
        startupInfo.cb = sizeof(STARTUPINFO)
    if None == processInfo:
        processInfo = PROCESS_INFORMATION()
    if None == securityAttributes:
        securityAttributes = SECURITY_ATTRIBUTES()
        securityAttributes.Length = sizeof(SECURITY_ATTRIBUTES)
        securityAttributes.SecDescriptior = None
        securityAttributes.InheritHandle = True
    if None == threadAttributes:
        threadAttributes = SECURITY_ATTRIBUTES()
        threadAttributes.Length = sizeof(SECURITY_ATTRIBUTES)
        threadAttributes.SecDescriptior = None
        threadAttributes.InheritHandle = True
        
    printIfVerbos('Creating process', isVerbos)
    CreateProcess( 
                pchar_NULL,
                cmdLine, 
                byref(securityAttributes),
                byref(threadAttributes),
                TRUE,
                creationFalgs | win32con.CREATE_SUSPENDED,
                environment,
                currentDirectory,
                byref(startupInfo),
                byref(processInfo) )
    printIfVerbos('Process created', isVerbos)
    printIfVerbos('Process handle: %d' % processInfo.hProcess, isVerbos)
    printIfVerbos('Process id: %d' % processInfo.dwProcessId, isVerbos)
    printIfVerbos('Thread handle: %d' % processInfo.hThread, isVerbos)
    printIfVerbos('Thread id: %d' % processInfo.dwThreadId, isVerbos)
    remoteThread = __injectAndExecute( processInfo.hProcess, dll, isVerbos=isVerbos )
    ResumeThread(processInfo.hThread)
    printIfVerbos('Process resumed', isVerbos)
    #ResumeThread(remoteThread)

    return (processInfo.hProcess, processInfo.hThread, processInfo.dwProcessId, processInfo.dwThreadId)



