#include <Windows.h>

// Real pipe name is stomped in by cna
 static const char pipename[] = "\\\\.\\pipe\\INPUT_PIPE_NAME_NO_CHANGE_PLS\0\0\0\0";

WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
);

WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(
    HANDLE hObject
);

WINBASEAPI BOOL WINAPI KERNEL32$WriteFile(
    HANDLE hFile,
    LPCVOID lpBuffer,
    DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
);

WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);

#define CreateFileA     KERNEL32$CreateFileA
#define CloseHandle     KERNEL32$CloseHandle
#define WriteFile       KERNEL32$WriteFile
#define GetLastError    KERNEL32$GetLastError

 void WriteToNamedPipe(char* buffer, DWORD buffer_size) {

     HANDLE hPipe = CreateFileA(
         pipename,  // pipe name
         GENERIC_WRITE,                                // write access
         0,                                            // no sharing
         NULL,                                         // default security attributes
         OPEN_EXISTING,                                // opens existing pipe
         0,                                            // default attributes
         NULL);                                        // no template file

     if (hPipe == INVALID_HANDLE_VALUE) {
         BeaconPrintf(CALLBACK_ERROR, "Failed to connect to pipe. Error: %lu\n", GetLastError());
         return;
     }

     DWORD bytesWritten = 0;
     BOOL success = WriteFile(
         hPipe,            // handle to pipe
         buffer,           // buffer to write
         buffer_size,      // size of buffer
         &bytesWritten,    // number of bytes written
         NULL);            // not overlapped I/O

     if (!success || bytesWritten != buffer_size) {
         BeaconPrintf(CALLBACK_ERROR, "Failed to write to pipe. Error: %lu\n", GetLastError());
     }

     CloseHandle(hPipe);
 }

 void go(char* args, int len) {
     char* data;
     int dataLen;
     datap parser;

     // Get the contents of the named pipe
     BeaconDataParse(&parser, args, len);
     data = BeaconDataExtract(&parser, &dataLen);

     // Send the data to the named pipe
     WriteToNamedPipe(data, dataLen);

     BeaconPrintf(CALLBACK_OUTPUT, "Sent command: %s", data);
 }
