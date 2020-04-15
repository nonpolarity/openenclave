// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#if defined(_WIN32)
#include <windows.h>
#else
#include <dirent.h>
#endif
#include <openenclave/host.h>
#include <openenclave/internal/syscall/host.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "fs_u.h"

#define SKIP_RETURN_CODE 2

#if defined(_WIN32)
BOOL IsDots(const wchar_t* str) {
    if(wcscmp(str, L".") && wcscmp(str, L".."))
    {
        return FALSE;
    }

    return TRUE;
}

int rmdir(const wchar_t* sPath)
{
    HANDLE hFind;  // file handle
    WIN32_FIND_DATAW FindFileData;

    wchar_t DirPath[MAX_PATH];
    wchar_t FileName[MAX_PATH];

    wcscpy(DirPath, sPath);
    wcscat(DirPath, L"\\*");    // searching all files
    wcscpy(FileName, sPath);
    wcscat(FileName, L"\\");

    hFind = FindFirstFileW(DirPath, &FindFileData); // find the first file
    if (hFind == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }
    wcscpy(DirPath, FileName);

    bool bSearch = true;
    while (bSearch)
    { // until we finds an entry
        if (FindNextFileW(hFind, &FindFileData))
        {
            if (IsDots(FindFileData.cFileName))
            {
                continue;
            }
            wcscat(FileName, FindFileData.cFileName);
            if ((FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            {
                // we have found a directory, recurse
                if (!RemoveDirectoryW(FileName))
                {
                    FindClose(hFind);
                    return FALSE; // directory couldn't be deleted
                }
                RemoveDirectoryW(FileName); // remove the empty directory
                wcscpy(FileName,DirPath);
            }
            else {
                if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_READONLY)
                {
//                    chmod(FileName, _S_IWRITE); // change read-only file mode
                }
                if (!DeleteFileW(FileName))
                {  // delete the file
                    FindClose(hFind);
                    return FALSE;
                }
                wcscpy(FileName,DirPath);
            }
        }
        else {
            if(GetLastError() == ERROR_NO_MORE_FILES) // no more files there
            bSearch = false;
            else {
                // some error occured, close the handle and return FALSE
                FindClose(hFind);
                return FALSE;
            }

        }

    }

    FindClose(hFind);  // closing file handle

    return !RemoveDirectoryW(sPath); // remove the empty directory
}

int wmain(int argc, wchar_t* argv[])
{
    oe_result_t r;
    oe_enclave_t* enclave = NULL;
    const uint32_t flags = oe_get_create_flags();
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;

    if (argc != 4)
    {
        fprintf(stderr, "Usage: %ls ENCLAVE_PATH SRC_DIR BIN_DIR\n", argv[0]);
        return 1;
    }


    if ((flags & OE_ENCLAVE_FLAG_SIMULATE))
    {
        printf("=== Skipped unsupported test in simulation mode (sealKey)\n");
        return SKIP_RETURN_CODE;
    }

    /* create_enclave takes an ANSI path instead of a Unicode path, so we have
     * to try to convert here */
    char enclave_path[MAX_PATH];
    if (WideCharToMultiByte(
            CP_ACP,
            0,
            argv[1],
            -1,
            enclave_path,
            sizeof(enclave_path),
            NULL,
            NULL) == 0)
    {
        fprintf(stderr, "Invalid enclave path\n");
        return 1;
    }
    char* src_dir = oe_win_path_to_posix((PCWSTR)argv[2]);
    char* tmp_dir = oe_win_path_to_posix((PCWSTR)argv[3]);

    // Windows does not support umask.
    // Please set up the right permission to the parent directory.

    if(rmdir(argv[1]))
    {
        fprintf(stdout, "Remove dir failed!\n");
    }

    r = oe_create_fs_enclave(enclave_path, type, flags, NULL, 0, &enclave);
    OE_TEST(r == OE_OK);

    r = test_fs(enclave, src_dir, tmp_dir);
    OE_TEST(r == OE_OK);

    r = oe_terminate_enclave(enclave);
    OE_TEST(r == OE_OK);

    printf("=== passed all tests (hostfs)\n");

    return 0;
}
#else
int rmdir(const char* path)
{
    char abs_path[PATH_MAX];
    int result = -1;
    struct dirent* entry = NULL;
    DIR* dir = NULL;
    if (!(dir = opendir(path)))
    {
        goto done;
    }

    while ((entry = readdir(dir)))
    {
        DIR* sub_dir = NULL;
        FILE* file = NULL;
        memset(abs_path, 0, PATH_MAX);
        // Here ".." is also excluded.
        if (*(entry->d_name) != '.')
        {
            sprintf(abs_path, "%s/%s", path, entry->d_name);
            if ((sub_dir = opendir(abs_path)))
            {
                closedir(sub_dir);
                rmdir(abs_path);
            }
            else if ((file = fopen(abs_path, "r")))
            {
                fclose(file);
                remove(abs_path);
            }
        }
    }

    result = remove(path);

done:
    return result;
}

int main(int argc, const char* argv[])
{
    oe_result_t r;
    oe_enclave_t* enclave = NULL;
    const uint32_t flags = oe_get_create_flags();
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;

    if (argc != 4)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH SRC_DIR BIN_DIR\n", argv[0]);
        return 1;
    }

    if ((flags & OE_ENCLAVE_FLAG_SIMULATE))
    {
        printf("=== Skipped unsupported test in simulation mode (sealKey)\n");
        return SKIP_RETURN_CODE;
    }

    const char* enclave_path = argv[1];
    char* src_dir = (char*)argv[2];
    char* tmp_dir = (char*)argv[3];

    umask(0022);

    rmdir(tmp_dir);

    r = oe_create_fs_enclave(enclave_path, type, flags, NULL, 0, &enclave);
    OE_TEST(r == OE_OK);

    r = test_fs(enclave, src_dir, tmp_dir);
    OE_TEST(r == OE_OK);

    rmdir(tmp_dir);

    r = test_fs_linux(enclave, src_dir, tmp_dir);
    OE_TEST(r == OE_OK);

    r = oe_terminate_enclave(enclave);
    OE_TEST(r == OE_OK);

    printf("=== passed all tests (hostfs)\n");

    return 0;
}
#endif
