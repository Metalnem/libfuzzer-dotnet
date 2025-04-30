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
#include <rpcdce.h>

#pragma comment(lib, "rpcrt4.lib")

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
HANDLE hctl_Wr = NULL;

// Information about the child process
PROCESS_INFORMATION child_pi = {};

static void die(const char *msg)
{
    printf("%s\n", msg);
    exit(1);
}

static void die_lasterror(const char *msg)
{
    LPSTR buffer = NULL;
    DWORD lasterror = GetLastError();
    DWORD chars = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        lasterror,
        0, // default language
        (LPSTR)&buffer, // this looks wrong but FORMAT_MESSAGE_ALLOCATE_BUFFER changes the interpretation of this parameter
        0,
        NULL);

    if (chars == 0) {
        printf("%s [%#lx]\n", msg, lasterror);
    } else {
        printf("%s [%#lx]: %s\n", msg, lasterror, buffer);
    }

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

    HANDLE hst_Wr = NULL;
    HANDLE hctl_Rd = NULL;

    // Create pipes to read status and write size to managed code (`Fuzzer.Libfuzzer.Run`)
    if (!CreatePipe(&hst_Rd, &hst_Wr, &saAttr, 0))
    {
        die_lasterror("CreatePipe() failed");
    }

    if (!CreatePipe(&hctl_Rd, &hctl_Wr, &saAttr, 0))
    {
        die_lasterror("CreatePipe() failed");
    }

    UUID uuid;
    if (RPC_S_OK != UuidCreate(&uuid))
    {
        die("Could not create an UUID");
    }
    TCHAR *sharedMemName;
    if (RPC_S_OK != UuidToStringA(&uuid, (unsigned char **)&sharedMemName))
    {
        die("Could not convert UUID to a string\n");
    }

    hMemFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, MAP_SIZE + DATA_SIZE, sharedMemName);
    if (hMemFile == NULL)
    {
        die_lasterror("CreateFileMapping() failed");
    }

    atexit(close_shm);
    pBuf = MapViewOfFile(hMemFile, FILE_MAP_ALL_ACCESS, 0, 0, MAP_SIZE + DATA_SIZE);
    if (pBuf == NULL)
    {
        die_lasterror("MapViewOfFile() failed");
    }

    // Create environment variables for pipes and shared memory to be read by sharpfuzz
    TCHAR ctl_rd_Id[10] = {0};
    TCHAR st_wr_Id[10] = {0};
    if (FAILED(StringCchPrintfA(ctl_rd_Id, sizeof(ctl_rd_Id) - 1, "%d", (UINT_PTR)hctl_Rd)))
    {
        die("StringCchPrintfA() failed");
    }
    if (FAILED(StringCchPrintfA(st_wr_Id, sizeof(st_wr_Id) - 1, "%d", (UINT_PTR)hst_Wr)))
    {
        die("StringCchPrintfA() failed");
    }

    if (!SetEnvironmentVariable(SHM_ID_VAR, sharedMemName))
    {
        die_lasterror("SetEnvironmentVariable() failed setting shared memory ID");
    }
    if (!SetEnvironmentVariable(PIPE_HANDLE_CTL_RD_ID, ctl_rd_Id))
    {
        die_lasterror("SetEnvironmentVariable() failed setting control pipe ID");
    }
    if (!SetEnvironmentVariable(PIPE_HANDLE_ST_WR_ID, st_wr_Id))
    {
        die_lasterror("SetEnvironmentVariable() failed setting status pipe ID");
    }

    // Create a job object to manage the fuzzer process tree.
    //
    // We will configure it to do the following:
    // - Automatically add new processes to the job on calls to `CreateProcess()`
    // - Kill all job processes when the last job handle is closed
    //
    // Since this process will hold the only job handle, the target child process
    // will be terminated even on abnormal exit of the parent harness.

    // Disable child inheritance of the job handle. This ensures that the current process
    // holds the _only_ handle, so on exit, all job processes will be killed.
    BOOL inherit_job_handle = FALSE;

    SECURITY_ATTRIBUTES job_attrs = {
        sizeof(SECURITY_ATTRIBUTES),
        NULL,
        inherit_job_handle,
    };
    HANDLE job = CreateJobObjectA(&job_attrs, NULL);

    // Terminate other (child) processes when all job handles are closed.
    JOBOBJECT_BASIC_LIMIT_INFORMATION li = {0};
    li.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

    // Setting `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` requires the use of an enclosing
    // `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` struct.
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION eli = {0};
    eli.BasicLimitInformation = li;

    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &eli, sizeof(eli)))
    {
        die_lasterror("failed to set `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`");
    }

    // Assign the current process to the job. Later calls to `CreateProcess()` will automatically
    // assign the created child processes to the job object.
    if (!AssignProcessToJobObject(job, GetCurrentProcess()))
    {
        die_lasterror("failed to assign `libfuzzer-dotnet` process to job");
    }

    if (target_arg)
    {
        size_t target_path_len = strlen(target_path);
        size_t target_arg_len = strlen(target_arg);

        char *temp_target = new char[target_path_len + 1 + target_arg_len + 1];
        strcpy_s(temp_target, target_path_len + 1, target_path);
        temp_target[target_path_len] = ' ';
        strcpy_s(temp_target + target_path_len + 1, target_arg_len + 1, target_arg);
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
        die_lasterror("CreateProcess() failed");
    }

    // read status for intialization
    if (!ReadFile(hst_Rd, &status, LEN_FLD_SIZE, &dwRead, NULL))
    {
        die_lasterror("ReadFile() failed");
    }

    if (dwRead != LEN_FLD_SIZE)
    {
        printf("Short read");
        exit(1);
    }

    // now we're initialized and the process is running
    child_pi = pi;

    // Close our handles to the pipes we passed to the child process.
    //
    // Otherwise, if the child process exits without writing status
    // we will still be blocked on pipe read and never exit.
    //
    // This happens e.g. if the child process throws an exception which
    // cannot be handled by catch clauses (e.g. AccessViolationException),
    // or dies for some other reason.
    CloseHandle(hctl_Rd);
    CloseHandle(hst_Wr);

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
        die_lasterror("WriteFile() failed");
    }

    if (dwWrite != LEN_FLD_SIZE)
    {
        printf("Short write");
        exit(1);
    }

    int32_t status;

    if (!ReadFile(hst_Rd, &status, LEN_FLD_SIZE, &dwRead, NULL))
    {
        if (GetLastError() == ERROR_BROKEN_PIPE)
        {
            DWORD exitCode = 0;
            if (GetExitCodeProcess(child_pi.hProcess, &exitCode))
            {
                printf("SharpFuzz process exited with code %#lx, aborting\n", exitCode);
            }

            abort(); // child process presumably crashed
        }
        else
        {
            die_lasterror("ReadFile() failed");
        }
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
