#include "errno.h"
#include "stddef.h"
#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"
#include "strsafe.h"
#include <fcntl.h>
#include <math.h>
#include <process.h>
#include <string>
#include <tchar.h>
#include <windows.h>

#ifdef __cplusplus
#define FUZZ_EXPORT extern "C" __declspec(dllexport)
#else
#define FUZZ_EXPORT __declspec(dllexport)
#endif

// Used for shared memory segment size
#define MAP_SIZE (1 << 16)
#define DATA_SIZE (1 << 20)

#define LEN_FLD_SIZE 4

// Shared memory and pipe designators
#define SHM_ID_VAR "__LIBFUZZER_SHM_ID"
#define PIPE_HANDLE_ST_WR_ID "__LIBFUZZER_STATUS_PIPE_ID"
#define PIPE_HANDLE_CTL_RD_ID "__LIBFUZZER_CONTROL_PIPE_ID"

// Use extra_counters for coverage
#pragma section(".data$__libfuzzer_extra_counters")
__declspec(allocate(".data$__libfuzzer_extra_counters")) uint8_t __libfuzzer_extra_counters[64 * 1024];

static const char *target_path_name = "--target_path";
static const char *target_arg_name = "--target_arg";

static const char *target_path;
static const char *target_arg;
static const char *target_for_process;

static HANDLE hMemFile;
static PVOID pBuf;

// Handles for pipes
HANDLE hst_Rd = NULL;
HANDLE hst_Wr = NULL;
HANDLE hctl_Rd = NULL;
HANDLE hctl_Wr = NULL;

static void die(const char *msg)
{
    printf("%s\n", msg);
    exit(1);
}

static void die_sys(const char *msg)
{
    printf("%s: %s\n", msg, strerror(errno));
    exit(1);
}

static void close_shm()
{
    UnmapViewOfFile(pBuf);
    CloseHandle(hMemFile);
}

// Read the flag value from the single command line parameter. For example,
// read_flag_value("--target_path=binary", "--target-path") will return "binary".
static const char *read_flag_value(const char *param, const char *name)
{
    size_t len = strlen(name);

    if (strstr(param, name) == param && param[len] == '=' && param[len + 1])
    {
        return &param[len + 1];
    }

    return NULL;
}

// Read target_path (the path to .NET executable) and target_arg (optional command
// line argument that can be passed to .NET executable) from the command line parameters.
static void parse_flags(int argc, char **argv)
{
    for (int i = 0; i < argc; ++i)
    {
        char *param = argv[i];

        if (!target_path)
        {
            target_path = read_flag_value(param, target_path_name);
        }

        if (!target_arg)
        {
            target_arg = read_flag_value(param, target_arg_name);
        }
    }
}

// Start the .NET child process and initialize two pipes and one shared
// memory segment for the communication between the parent and the child.
FUZZ_EXPORT int __cdecl LLVMFuzzerInitialize(int *argc, char ***argv)
{

    int32_t status = 0;
    DWORD dwRead = 0;
    DWORD dwWrite = 0;
    BOOL rSuccess = FALSE;
    BOOL bSuccess = FALSE;

    // security attributes for pipes to have inheritable handles
    SECURITY_ATTRIBUTES saAttr;
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    parse_flags(*argc, *argv);

    if (!target_path)
    {
        die("You must specify the target path by using the --target_path command line flag.");
    }

    // Create pipes to read status and write size to managed code (`Fuzzer.Libfuzzer.Run`)
    if (!CreatePipe(&hst_Rd, &hst_Wr, &saAttr, 0))
    {
        die_sys("CreatePipe() failed");
    }
    if (!CreatePipe(&hctl_Rd, &hctl_Wr, &saAttr, 0))
    {
        die_sys("CreatePipe() failed");
    }

    TCHAR sharedMemName[] = TEXT("LIBFUZZER_DOTNET_SHMEM");
    hMemFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, MAP_SIZE + DATA_SIZE, sharedMemName);
    if (hMemFile == NULL)
    {
        die_sys("CreateFileMapping() failed");
    }

    atexit(close_shm);
    pBuf = MapViewOfFile(hMemFile, FILE_MAP_ALL_ACCESS, 0, 0, MAP_SIZE + DATA_SIZE);
    if (pBuf == NULL)
    {
        CloseHandle(hMemFile);
        die_sys("MapViewOfFile() failed");
    }

    // Create environment variables for pipes and shared memory to be read by sharpfuzz
    TCHAR ctl_rd_Id[10] = {0};
    TCHAR st_wr_Id[10] = {0};
    if (FAILED(StringCchPrintfA(ctl_rd_Id, sizeof(ctl_rd_Id) - 1, "%d", (UINT_PTR)hctl_Rd)))
    {
        die_sys("StringCchPrintfA() failed");
    }
    if (FAILED(StringCchPrintfA(st_wr_Id, sizeof(st_wr_Id) - 1, "%d", (UINT_PTR)hst_Wr)))
    {
        die_sys("StringCchPrintfA() failed");
    }

    if (!SetEnvironmentVariable(SHM_ID_VAR, sharedMemName))
    {
        die_sys("SetEnvironmentVariable() failed setting shared memory ID");
    }
    if (!SetEnvironmentVariable(PIPE_HANDLE_CTL_RD_ID, ctl_rd_Id))
    {
        die_sys("SetEnvironmentVariable() failed setting control pipe ID");
    }
    if (!SetEnvironmentVariable(PIPE_HANDLE_ST_WR_ID, st_wr_Id))
    {
        die_sys("SetEnvironmentVariable() failed setting status pipe ID");
    }
    if (target_arg)
    {
        char *temp_target = new char[strlen(target_path) + 1 + strlen(target_arg) + 1];
        strcpy(temp_target, target_path);
        temp_target[strlen(target_path)] = ' ';
        strcpy(temp_target + strlen(target_path) + 1, target_arg);
        target_for_process = temp_target;
    }
    else
    {
        target_for_process = target_path;
    }
    PROCESS_INFORMATION pi;
    STARTUPINFO si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcess(NULL, (LPSTR)target_for_process, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
    {
        die_sys("CreateProcess() failed");
    }

    // read status for intialization
    if (!ReadFile(hst_Rd, &status, LEN_FLD_SIZE, &dwRead, NULL))
    {
        die_sys("ReadFile() failed");
    }

    if (dwRead != LEN_FLD_SIZE)
    {
        printf("Short read");
        exit(1);
    }

    return 0;
}

// Fuzz with `data` by writing it to the shared memory segment, sending
// the size of the data to the .NET process (which will then run
// its own fuzzing function on the shared memory data), and receiving
// the status of the executed operation.
FUZZ_EXPORT int __cdecl LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > DATA_SIZE)
    {
        die("Size of the input data must not exceed 1 MiB.");
    }

    ZeroMemory((PVOID)pBuf, MAP_SIZE);
    CopyMemory((PVOID)((PUCHAR)pBuf + MAP_SIZE), data, size);

    DWORD dwRead;
    DWORD dwWrite;
    BOOL writeSuccess = FALSE;
    BOOL readSuccess = FALSE;

    // write size, read status
    if (!WriteFile(hctl_Wr, &size, LEN_FLD_SIZE, &dwWrite, NULL))
    {
        die_sys("WriteFile() failed");
    }

    if (dwWrite != LEN_FLD_SIZE)
    {
        printf("Short write");
        exit(1);
    }

    int32_t status;

    if (!ReadFile(hst_Rd, &status, LEN_FLD_SIZE, &dwRead, NULL))
    {
        die_sys("ReadFile() failed");
    }

    if (dwRead != LEN_FLD_SIZE)
    {
        printf("Short read");
        exit(1);
    }
    CopyMemory(__libfuzzer_extra_counters, (PVOID)pBuf, MAP_SIZE);

    if (status)
    {
        abort();
    }

    return 0;
}
