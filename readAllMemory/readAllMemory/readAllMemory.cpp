
#include <windows.h>
#include <stdio.h>

BOOL WINAPI DllMain(
              HINSTANCE hinstDLL,
              DWORD fdwReason,
              LPVOID lpvReserved )
{
    BYTE *  pos = NULL;
    BYTE *  end_pos = NULL;
    ULONG   buffer_len = 0;
    BYTE    read_tester;
    HANDLE  dump_file = 0;
    DWORD   bytes_written = 0;
    CHAR    file_name[1024] = {0};

    pos = NULL;
    while( pos < (BYTE *)0x80000000 ) {
        if( 0 == IsBadReadPtr(pos, 1) ) {
            end_pos = pos + 0x1000;
            while( end_pos < (BYTE *)0x80000000 ) {
                if( 0 != IsBadReadPtr(end_pos, 1) ) {
                    break;
                }
                end_pos += 0x1000;
            }
            buffer_len = end_pos - pos;
            sprintf( file_name, "c:\\temp\\mem_%08x.dump", pos );
            dump_file = CreateFileA( file_name, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL );
            WriteFile( dump_file, pos, buffer_len, &bytes_written, NULL );
            CloseHandle(dump_file);
            pos = end_pos;
        }
        pos += 0x1000;
    }

    return FALSE;
}