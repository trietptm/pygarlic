
import win32con
import struct
from ctypes import *

def ErrorIfZero(handle):
    if handle == 0:
        raise WinError()
    else:
        return handle

GetCurrentProcess = windll.kernel32.GetCurrentProcess
GetCurrentProcess.argtypes = []
GetCurrentProcess.restype = ErrorIfZero

CloseHandle = windll.kernel32.CloseHandle
CloseHandle.argtypes = [ c_int ]
CloseHandle.restype = ErrorIfZero

OpenProcessToken = windll.advapi32.OpenProcessToken
OpenProcessToken.argtypes = [
	c_int,		# HANDLE ProcessHandle
	c_uint,		# DWORD DesiredAccess
	c_void_p ]	# PHANDLE TokenHandle
OpenProcessToken.restype = ErrorIfZero

AdjustTokenPrivileges = windll.advapi32.AdjustTokenPrivileges
AdjustTokenPrivileges.argtypes = [
	c_int,		# HANDLE TokenHandle
	c_int,		# BOOL DisableAllPrivileges
	c_void_p,	# PTOKEN_PRIVILEGES NewState
	c_uint,		# DWORD BufferLength
	c_void_p,	# PTOKEN_PRIVILEGES PreviousState
	c_void_p ]	# PDWORD ReturnLength
AdjustTokenPrivileges.restype = ErrorIfZero

LookupPrivilegeValue = windll.advapi32.LookupPrivilegeValueA
LookupPrivilegeValue.argtypes = [
	c_char_p,	# LPCTSTR lpSystemName
	c_char_p,	# LPCTSTR lpName
	c_void_p ]	# PLUID lpLuid
LookupPrivilegeValue.restype = ErrorIfZero

# CreateRemoteThread
CreateRemoteThread = windll.kernel32.CreateRemoteThread
CreateRemoteThread.argtypes = [
		c_uint,			# HANDLE hProcess
		c_void_p,		# LPSECURITY_ATTRIBUTES lpThreadAttributes
		c_uint,			# SIZE_T dwStackSize
		c_void_p,		# LPTHREAD_START_ROUTINE lpStartAddress
		c_void_p,		# LPVOID lpParameter
		c_uint,			# DWORD dwCreationFlags
		c_void_p ]		# LPDWORD lpThreadId		
CreateRemoteThread.restype = ErrorIfZero

OpenProcess = windll.kernel32.OpenProcess
OpenProcess.argtypes = [
		c_uint,			# DWORD dwDesiredAccess
		c_uint,			# BOOL bInheritHandle
		c_uint ]		# DWORD dwProcessId
OpenProcess.restype = ErrorIfZero

# LoadLibrary
LoadLibrary = windll.kernel32.LoadLibraryA
LoadLibrary.argtypes = [ c_char_p ]
LoadLibrary.restype = ErrorIfZero

# GetProcAddress
GetProcAddress = windll.kernel32.GetProcAddress
GetProcAddress.argtypes = [
		c_uint,			# HMOUDLE hModule
		c_char_p ]		# LPCSTR lpProcName
GetProcAddress.restype = ErrorIfZero

# VirtualAllocEx
VirtualAllocEx = windll.kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = [
		c_uint,			# HANDLE hProcess
		c_void_p,		# LPVOID lpAddress
		c_uint,			# SIZE_T dwSize
		c_uint,			# DWORD flAllocationType
		c_uint ]		# DWORD flProtect
VirtualAllocEx.restype = ErrorIfZero

# WriteProcessMemory
WriteProcessMemory = windll.kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = [
		c_uint,			# HANDLE hProcess
		c_uint,			# LPVOID lpBaseAddress
		c_char_p,		# LPCVOID lpBuffer
		c_uint,			# SIZE_T nSize
		c_void_p ]		# SIZE_T* lpNumberOfBytesWritten
WriteProcessMemory.restype = ErrorIfZero

class LUID( Structure ):
	_fields_ = [
			('LowPart',			c_uint),
			('HighPart',		c_uint)]

class TOKEN_PRIVILEGES( Structure ):
	_fields_ = [
			('PrivilegeCount',	c_uint),
			('Luid',			LUID),
			('Attributes',		c_uint) ]

REMOTE_BUFFER_SIZE = 0x200

def inject_dll( process_id, dll_name , LoadLibraryA_address = -1 ):
	if len(dll_name) > 0x100:
		print "Dll name to long"
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

	print "Opening the target process"
	remote_process = \
			OpenProcess(
						#win32con.PROCESS_CREATE_THREAD | win32con.PROCESS_VM_OPERATION | win32con.PROCESS_VM_WRITE,
						win32con.PROCESS_ALL_ACCESS,
						win32con.FALSE,
						process_id )
	print "Allocating memory inside remote process"
	remote_memory_address = \
		VirtualAllocEx(	remote_process,
						None,
						REMOTE_BUFFER_SIZE,
						win32con.MEM_COMMIT,
						win32con.PAGE_EXECUTE_READWRITE )
	print "Memory allocated at 0x%x" % remote_memory_address
	print "Writting the dll name to remote process"
	bytes_written = c_uint(0)
	WriteProcessMemory(
					remote_process,
					remote_memory_address,
					dll_name + '\x00',
					len(dll_name) + 1,
					byref(bytes_written))
	if bytes_written.value != (len(dll_name) + 1):
		print "Unable to write to process memory"
		return

	if -1 == LoadLibraryA_address:
		print "Verifing the LoadLibrary proc address"
		kernel32lib = LoadLibrary( "kernel32.dll" )
		LoadLibraryA_address = \
			GetProcAddress( kernel32lib,
							"LoadLibraryA" )
		print "LoadLibraryA found in", hex(LoadLibraryA_address)
		# We can assume that kernel32 is loaded in the same place in every process
		# because it's the first dll to be loaded in every process

	print 'Generating loading code'
	code = '\x68'		# Push
	code += struct.pack('=l', remote_memory_address)
	code += '\xb8'		# mov eax,
	code += struct.pack('=l', LoadLibraryA_address)
	code += '\xff\xd0'	# call eax
	code += '\x3c\xc0'	# xor eax,eax
	code += '\xc3'		# retn
	WriteProcessMemory(
			remote_process,
			remote_memory_address + 0x100,
			code,
			len(code),
			byref(bytes_written))
	if bytes_written.value != len(code):
		print 'Unable to write code'
		return

	print "Creating remote thread on LoadLibrary"
	remote_thread_id = c_uint(0)
	remote_thread = CreateRemoteThread( \
						remote_process,
						None,
						0,
						remote_memory_address + 0x100,
						remote_memory_address,
						0,
						byref(remote_thread_id) )
	print "Thread %d created" % remote_thread_id.value


