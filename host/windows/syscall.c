// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/*
**==============================================================================
**
** windows/syscall.c:
**
**     This file implements SYSCALL OCALLs for Windows. Most of these are stubs
**     which are still under development.
**
**==============================================================================
*/
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <direct.h>
#include <io.h>
#include <stdint.h>
#include <sys/stat.h>

// clang-format off

#include <winsock2.h>
#include <windows.h>
#include <Ws2def.h>
#include <VersionHelpers.h>
// clang-format on

#include <openenclave/corelibc/errno.h>
#include <openenclave/internal/atomic.h>
#include <openenclave/internal/syscall/fcntl.h>
#include <openenclave/internal/syscall/dirent.h>
#include <openenclave/internal/syscall/unistd.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/corelibc/limits.h>
#include "../hostthread.h"
#include "../../common/oe_host_socket.h"
#include "syscall_u.h"

/*
**==============================================================================
**
** WINDOWS ERROR CONVERSION
**
**==============================================================================
*/

struct tab_entry
{
    int key;
    int val;
};

static struct tab_entry winerr2errno[] = {
    {ERROR_ACCESS_DENIED, OE_EACCES},
    {ERROR_ACTIVE_CONNECTIONS, OE_EAGAIN},
    {ERROR_ALREADY_EXISTS, OE_EEXIST},
    {ERROR_BAD_DEVICE, OE_ENODEV},
    {ERROR_BAD_EXE_FORMAT, OE_ENOEXEC},
    {ERROR_BAD_NETPATH, OE_ENOENT},
    {ERROR_BAD_NET_NAME, OE_ENOENT},
    {ERROR_BAD_NET_RESP, OE_ENOSYS},
    {ERROR_BAD_PATHNAME, OE_ENOENT},
    {ERROR_BAD_PIPE, OE_EINVAL},
    {ERROR_BAD_UNIT, OE_ENODEV},
    {ERROR_BAD_USERNAME, OE_EINVAL},
    {ERROR_BEGINNING_OF_MEDIA, OE_EIO},
    {ERROR_BROKEN_PIPE, OE_EPIPE},
    {ERROR_BUSY, OE_EBUSY},
    {ERROR_BUS_RESET, OE_EIO},
    {ERROR_CALL_NOT_IMPLEMENTED, OE_ENOSYS},
    {ERROR_CANCELLED, OE_EINTR},
    {ERROR_CANNOT_MAKE, OE_EPERM},
    {ERROR_CHILD_NOT_COMPLETE, OE_EBUSY},
    {ERROR_COMMITMENT_LIMIT, OE_EAGAIN},
    {ERROR_CONNECTION_REFUSED, OE_ECONNREFUSED},
    {ERROR_CRC, OE_EIO},
    {ERROR_DEVICE_DOOR_OPEN, OE_EIO},
    {ERROR_DEVICE_IN_USE, OE_EAGAIN},
    {ERROR_DEVICE_REQUIRES_CLEANING, OE_EIO},
    {ERROR_DEV_NOT_EXIST, OE_ENOENT},
    {ERROR_DIRECTORY, OE_ENOTDIR},
    {ERROR_DIR_NOT_EMPTY, OE_ENOTEMPTY},
    {ERROR_DISK_CORRUPT, OE_EIO},
    {ERROR_DISK_FULL, OE_ENOSPC},
    {ERROR_DS_GENERIC_ERROR, OE_EIO},
    {ERROR_DUP_NAME, OE_ENOTUNIQ},
    {ERROR_EAS_DIDNT_FIT, OE_ENOSPC},
    {ERROR_EAS_NOT_SUPPORTED, OE_ENOTSUP},
    {ERROR_EA_LIST_INCONSISTENT, OE_EINVAL},
    {ERROR_EA_TABLE_FULL, OE_ENOSPC},
    {ERROR_END_OF_MEDIA, OE_ENOSPC},
    {ERROR_EOM_OVERFLOW, OE_EIO},
    {ERROR_EXE_MACHINE_TYPE_MISMATCH, OE_ENOEXEC},
    {ERROR_EXE_MARKED_INVALID, OE_ENOEXEC},
    {ERROR_FILEMARK_DETECTED, OE_EIO},
    {ERROR_FILENAME_EXCED_RANGE, OE_ENAMETOOLONG},
    {ERROR_FILE_CORRUPT, OE_EEXIST},
    {ERROR_FILE_EXISTS, OE_EEXIST},
    {ERROR_FILE_INVALID, OE_ENXIO},
    {ERROR_FILE_NOT_FOUND, OE_ENOENT},
    {ERROR_HANDLE_DISK_FULL, OE_ENOSPC},
    {ERROR_HANDLE_EOF, OE_ENODATA},
    {ERROR_INVALID_ADDRESS, OE_EINVAL},
    {ERROR_INVALID_AT_INTERRUPT_TIME, OE_EINTR},
    {ERROR_INVALID_BLOCK_LENGTH, OE_EIO},
    {ERROR_INVALID_DATA, OE_EINVAL},
    {ERROR_INVALID_DRIVE, OE_ENODEV},
    {ERROR_INVALID_EA_NAME, OE_EINVAL},
    {ERROR_INVALID_EXE_SIGNATURE, OE_ENOEXEC},
    {ERROR_INVALID_FUNCTION, OE_EBADRQC},
    {ERROR_INVALID_HANDLE, OE_EBADF},
    {ERROR_INVALID_NAME, OE_ENOENT},
    {ERROR_INVALID_PARAMETER, OE_EINVAL},
    {ERROR_INVALID_SIGNAL_NUMBER, OE_EINVAL},
    {ERROR_IOPL_NOT_ENABLED, OE_ENOEXEC},
    {ERROR_IO_DEVICE, OE_EIO},
    {ERROR_IO_INCOMPLETE, OE_EAGAIN},
    {ERROR_IO_PENDING, OE_EAGAIN},
    {ERROR_LOCK_VIOLATION, OE_EBUSY},
    {ERROR_MAX_THRDS_REACHED, OE_EAGAIN},
    {ERROR_META_EXPANSION_TOO_LONG, OE_EINVAL},
    {ERROR_MOD_NOT_FOUND, OE_ENOENT},
    {ERROR_MORE_DATA, OE_EMSGSIZE},
    {ERROR_NEGATIVE_SEEK, OE_EINVAL},
    {ERROR_NETNAME_DELETED, OE_ENOENT},
    {ERROR_NOACCESS, OE_EFAULT},
    {ERROR_NONE_MAPPED, OE_EINVAL},
    {ERROR_NONPAGED_SYSTEM_RESOURCES, OE_EAGAIN},
    {ERROR_NOT_CONNECTED, OE_ENOLINK},
    {ERROR_NOT_ENOUGH_MEMORY, OE_ENOMEM},
    {ERROR_NOT_ENOUGH_QUOTA, OE_EIO},
    {ERROR_NOT_OWNER, OE_EPERM},
    {ERROR_NOT_READY, OE_ENOMEDIUM},
    {ERROR_NOT_SAME_DEVICE, OE_EXDEV},
    {ERROR_NOT_SUPPORTED, OE_ENOSYS},
    {ERROR_NO_DATA, OE_EPIPE},
    {ERROR_NO_DATA_DETECTED, OE_EIO},
    {ERROR_NO_MEDIA_IN_DRIVE, OE_ENOMEDIUM},
    {ERROR_NO_MORE_FILES, OE_ENFILE},
    {ERROR_NO_MORE_ITEMS, OE_ENFILE},
    {ERROR_NO_MORE_SEARCH_HANDLES, OE_ENFILE},
    {ERROR_NO_PROC_SLOTS, OE_EAGAIN},
    {ERROR_NO_SIGNAL_SENT, OE_EIO},
    {ERROR_NO_SYSTEM_RESOURCES, OE_EFBIG},
    {ERROR_NO_TOKEN, OE_EINVAL},
    {ERROR_OPEN_FAILED, OE_EIO},
    {ERROR_OPEN_FILES, OE_EAGAIN},
    {ERROR_OUTOFMEMORY, OE_ENOMEM},
    {ERROR_PAGED_SYSTEM_RESOURCES, OE_EAGAIN},
    {ERROR_PAGEFILE_QUOTA, OE_EAGAIN},
    {ERROR_PATH_NOT_FOUND, OE_ENOENT},
    {ERROR_PIPE_BUSY, OE_EBUSY},
    {ERROR_PIPE_CONNECTED, OE_EBUSY},
    {ERROR_PIPE_LISTENING, OE_ECOMM},
    {ERROR_PIPE_NOT_CONNECTED, OE_ECOMM},
    {ERROR_POSSIBLE_DEADLOCK, OE_EDEADLOCK},
    {ERROR_PRIVILEGE_NOT_HELD, OE_EPERM},
    {ERROR_PROCESS_ABORTED, OE_EFAULT},
    {ERROR_PROC_NOT_FOUND, OE_ESRCH},
    {ERROR_REM_NOT_LIST, OE_ENONET},
    {ERROR_SECTOR_NOT_FOUND, OE_EINVAL},
    {ERROR_SEEK, OE_EINVAL},
    {ERROR_SERVICE_REQUEST_TIMEOUT, OE_EBUSY},
    {ERROR_SETMARK_DETECTED, OE_EIO},
    {ERROR_SHARING_BUFFER_EXCEEDED, OE_ENOLCK},
    {ERROR_SHARING_VIOLATION, OE_EBUSY},
    {ERROR_SIGNAL_PENDING, OE_EBUSY},
    {ERROR_SIGNAL_REFUSED, OE_EIO},
    {ERROR_SXS_CANT_GEN_ACTCTX, OE_ELIBBAD},
    {ERROR_THREAD_1_INACTIVE, OE_EINVAL},
    {ERROR_TIMEOUT, OE_EBUSY},
    {ERROR_TOO_MANY_LINKS, OE_EMLINK},
    {ERROR_TOO_MANY_OPEN_FILES, OE_EMFILE},
    {ERROR_UNEXP_NET_ERR, OE_EIO},
    {ERROR_WAIT_NO_CHILDREN, OE_ECHILD},
    {ERROR_WORKING_SET_QUOTA, OE_EAGAIN},
    {ERROR_WRITE_PROTECT, OE_EROFS},
    {0, 0}};

static struct tab_entry winsock2errno[] = {
    {WSAEINTR, OE_EINTR},
    {WSAEBADF, OE_EBADF},
    {WSAEACCES, OE_EACCES},
    {WSAEFAULT, OE_EFAULT},
    {WSAEINVAL, OE_EINVAL},
    {WSAEMFILE, OE_EMFILE},
    {WSAEWOULDBLOCK, OE_EWOULDBLOCK},
    {WSAEINPROGRESS, OE_EINPROGRESS},
    {WSAEALREADY, OE_EALREADY},
    {WSAENOTSOCK, OE_ENOTSOCK},
    {WSAEDESTADDRREQ, OE_EDESTADDRREQ},
    {WSAEMSGSIZE, OE_EMSGSIZE},
    {WSAEPROTOTYPE, OE_EPROTOTYPE},
    {WSAENOPROTOOPT, OE_ENOPROTOOPT},
    {WSAEPROTONOSUPPORT, OE_EPROTONOSUPPORT},
    {WSAESOCKTNOSUPPORT, OE_ESOCKTNOSUPPORT},
    {WSAEOPNOTSUPP, OE_EOPNOTSUPP},
    {WSAEPFNOSUPPORT, OE_EPFNOSUPPORT},
    {WSAEAFNOSUPPORT, OE_EAFNOSUPPORT},
    {WSAEADDRINUSE, OE_EADDRINUSE},
    {WSAEADDRNOTAVAIL, OE_EADDRNOTAVAIL},
    {WSAENETDOWN, OE_ENETDOWN},
    {WSAENETUNREACH, OE_ENETUNREACH},
    {WSAENETRESET, OE_ENETRESET},
    {WSAECONNABORTED, OE_ECONNABORTED},
    {WSAECONNRESET, OE_ECONNRESET},
    {WSAENOBUFS, OE_ENOBUFS},
    {WSAEISCONN, OE_EISCONN},
    {WSAENOTCONN, OE_ENOTCONN},
    {WSAESHUTDOWN, OE_ESHUTDOWN},
    {WSAETOOMANYREFS, OE_ETOOMANYREFS},
    {WSAETIMEDOUT, OE_ETIMEDOUT},
    {WSAECONNREFUSED, OE_ECONNREFUSED},
    {WSAELOOP, OE_ELOOP},
    {WSAENAMETOOLONG, OE_ENAMETOOLONG},
    {WSAEHOSTDOWN, OE_EHOSTDOWN},
    {WSAEHOSTUNREACH, OE_EHOSTUNREACH},
    {WSAENOTEMPTY, OE_ENOTEMPTY},
    {WSAEUSERS, OE_EUSERS},
    {WSAEDQUOT, OE_EDQUOT},
    {WSAESTALE, OE_ESTALE},
    {WSAEREMOTE, OE_EREMOTE},
    {WSAEDISCON, OE_ESHUTDOWN},
    {WSAEPROCLIM, OE_EPROCLIM},
    {WSASYSNOTREADY, OE_EBUSY},
    {WSAVERNOTSUPPORTED, OE_ENOTSUP},
    {WSANOTINITIALISED, OE_ENXIO},
    {0, 0}};

/**
 * Musl libc has redefined pretty much every define in socket.h so that
 * constants passed as parameters are different if the enclave uses musl
 * and the host uses a socket implementation that uses the original BSD
 * defines (winsock, glibc, BSD libc). The following tables are 1-to-1 mappings
 * from musl defines to bsd defines
 */

// Only SOL_SOCKET is different. All other socket level
// defines are the same.
static struct tab_entry musl2bsd_socket_level[] = {{1, SOL_SOCKET}, {0, 0}};

static struct tab_entry musl2bsd_socket_option[] = {{1, SO_DEBUG},
                                                    {2, SO_REUSEADDR},
                                                    {3, SO_TYPE},
                                                    {4, SO_ERROR},
                                                    {5, SO_DONTROUTE},
                                                    {6, SO_BROADCAST},
                                                    {7, SO_SNDBUF},
                                                    {8, SO_RCVBUF},
                                                    {9, SO_KEEPALIVE},
                                                    {10, SO_OOBINLINE},
                                                    {13, SO_LINGER},
                                                    {18, SO_RCVLOWAT},
                                                    {19, SO_SNDLOWAT}};

static struct tab_entry wsa2eai[] = {{WSATRY_AGAIN, OE_EAI_AGAIN},
                                     {WSAEINVAL, OE_EAI_BADFLAGS},
                                     {WSAEAFNOSUPPORT, OE_EAI_FAMILY},
                                     {WSA_NOT_ENOUGH_MEMORY, OE_EAI_MEMORY},
                                     {WSAHOST_NOT_FOUND, OE_EAI_NONAME},
                                     {WSATYPE_NOT_FOUND, OE_EAI_SERVICE},
                                     {WSAESOCKTNOSUPPORT, OE_EAI_SOCKTYPE},
                                     {0, 0}};

static int _do_lookup(int key, int fallback, struct tab_entry* table)
{
    struct tab_entry* pent = table;
    do
    {
        if (pent->key == key)
        {
            return pent->val;
        }

        pent++;
    } while (pent->val != 0);

    return fallback;
}

static int _winerr_to_errno(int winerr)
{
    return _do_lookup(winerr, OE_EINVAL, winerr2errno);
}

static int _winsockerr_to_errno(DWORD winsockerr)
{
    return _do_lookup(winsockerr, OE_EINVAL, winsock2errno);
}

static int _wsaerr_to_eai(DWORD winsockerr)
{
    return _do_lookup(winsockerr, OE_EINVAL, wsa2eai);
}

static int _musl_to_bsd(int musl_define, struct tab_entry* table)
{
    return _do_lookup(musl_define, OE_EINVAL, table);
}

/*
**==============================================================================
**
** PANIC -- remove this when no longer needed.
**
**==============================================================================
*/

__declspec(noreturn) static void _panic(
    const char* file,
    unsigned int line,
    const char* function)
{
    fprintf(stderr, "%s(%u): %s(): panic\n", file, line, function);
    abort();
}

#define PANIC _panic(__FILE__, __LINE__, __FUNCTION__)

/*
**==============================================================================
**
** File and directory I/O:
**
**==============================================================================
*/

// Allocates char* string which follows the expected rules for
// enclaves. Paths in the format
// <driveletter>:\<item>\<item> -> /<driveletter>/<item>/item>
// <driveletter>:/<item>/<item> -> /<driveletter>/<item>/item>
// paths without drive letter are detected and the drive added
// /<item>/<item> -> /<current driveletter>/<item>/item>
// relative paths are translated to absolute with drive letter
// returns null if the string is illegal
//
// The string  must be freed
//
// we don't handle paths which start with the "\\?\" thing. We never
// use the 8 bit version of the win32 apis. That said, we get paths in 8 bit
// characters from the enclave because there is no "wopen" in linux
//
// We always convert in the ocall function.
//
void normalize_path(char *path, size_t origlen, char slash)
{
    if (!path)
    {
        _set_errno(OE_EINVAL);
        return;
    }

    for (char *c = path; *c != '\0'; c++)
    {
        if (*c == '\\' || *c == '/')
        {
            *c = slash;
        }
    }

    // Corner case, or base case.
    // ".", "./" should return with "."
    if ((origlen >= 2 && path[0] == '.' && path[1] == '\0') ||
        (origlen >= 3 && path[0] == '.' && path[1] == slash && path[2] == '/0'))
    {
        path[1] = '\0';
        return;
    }

    char *p; /* points to the beginning of the path not yet processed; this is
                either a path component or a path separator character */
    char *q; /* points to the end of the path component p points to */
    char *w; /* points to the end of the already normalized path; w <= p is
                maintained */
    size_t len; /* length of current component (which p points to) */

    p = path;
    w = p;
    while (*p != '\0') {
        if (*p == slash) {
            if ((w == path && *path == slash) || (w > path && w[-1] != slash))
                *w++ = slash;
            p++;
            continue;
        }

        q = strchr(p, slash);
        if (q == NULL)
            q = p + strnlen_s(p, OE_PATH_MAX);
        len = q - p;
        if (len < 0)
        {
            _set_errno(OE_EINVAL);
        }

        if (len == 1 && *p == '.') {
            /* remove current component */
        } else if (len == 2 && memcmp(p, "..", 2) == 0) {
            if (w == path || (w == path+3 && memcmp(path, "../", 3) == 0)) {
                /* keep ".." at beginning of relative path ("../x" => "../x") */
                memmove(w, p, len);
                w += len;
            } else if (w == path+1 && *path == slash) {
                /* remove ".." at beginning of absolute path ("/../x" => "/x") */
            } else {
                /* remove both current component ".." and preceding one */
                if (w > path && w[-1] == slash)
                    w--;
                while (w > path && w[-1] != slash)
                    w--;
            }
        } else {
            /* normal component ==> add it */
            memmove(w, p, len);
            w += len;
        }

        p = q;
    }

    /* remove trailing slashes, but keep the one at the start of the path */
    while (w > path+1 && w[-1] == slash) {
        w--;
    }

    *w = '\0';
}

char* oe_win_path_to_posix(const char* path)
{
    size_t required_size = 0;
    size_t current_dir_len = 0;
    char* current_dir = NULL;
    char* enclave_path = NULL;

    if (!path || strnlen_s(path, MAX_PATH) == 0 || strnlen_s(path, MAX_PATH) == MAX_PATH)
    {
        _set_errno(OE_EINVAL);
        goto done;
    }

    if (strcmp(path, "nul") == 0)
    {
        enclave_path = calloc(strlen("/dev/null"), sizeof(char));
        sprintf(enclave_path, "%s", "/dev/null");
        enclave_path[strlen("/dev/null") - 1] = '\0';

        goto done;
    }

    // absolute path with drive letter.
    // we do not handle device type paths ("CON:) or double-letter paths in case
    // of really large numbers of disks (>26). If you have those, mount on
    // windows
    //

    int origin_len =  strnlen_s(path, MAX_PATH);
    if (origin_len >= 2 && isalpha(path[0]) && path[1] == ':')
    {
        // Abosolute path, just replace c: to /c
        required_size = origin_len + 1;

        enclave_path = (char*)calloc(required_size, sizeof(char));
        if (!enclave_path)
        {
            _set_errno(OE_ENOMEM);
            goto done;
        }
        oe_memcpy_s(enclave_path, sizeof(char) * required_size, path, origin_len);
    }
    else
    {
        // Relative path, ./tmp or /tmp.
        // /tmp means D:\tmp if pwd is under D:\.
        //  \tmp is the same case.
        // Anyway we need pwd.
        current_dir = _getcwd(NULL, 0);
        current_dir_len = strnlen_s(current_dir, MAX_PATH);

        if (current_dir_len < 2 || !isalpha(current_dir[0]) || current_dir[1] != ':')
        {
            //_getcwd result is wrong
            _set_errno(OE_EINVAL);
            goto done;
        }

        if (path[0] == '\\' || path[0] == '/')
        {
            // Only need the drive name.
            current_dir_len = 2;
        }

        required_size = current_dir_len + origin_len + 1;

        enclave_path = (char*)calloc(required_size, sizeof(char));
        if (!enclave_path)
        {
            _set_errno(OE_ENOMEM);
            goto done;
        }

        oe_memcpy_s(enclave_path, sizeof(char) * required_size, current_dir, sizeof(char) * current_dir_len);
        oe_memcpy_s(enclave_path + sizeof(char) * current_dir_len, sizeof(char) * (required_size - current_dir_len), path, sizeof(char) * origin_len);
    }

    // Clean up

    // There are at least 2 chars are copied to enclave_path as disk:
    // Check the length here and replace disk: at the first 2 position as /disk.
    if (required_size >= 3 && isalpha(enclave_path[0]) && enclave_path[1] == ':')
    {
        enclave_path[1] = enclave_path[0];
        enclave_path[0] = '/';
    }
    else
    {
        _set_errno(OE_EINVAL);
        goto done;
    }

    enclave_path[required_size - 1] = '\0';
    normalize_path(enclave_path, required_size, '/');

done:
    if (current_dir)
    {
        free(current_dir);
    }
    return enclave_path;
}

// Allocates WCHAR* string which follows the expected rules for
// enclaves comminication with the host file system API. Paths in the format
// /<driveletter>/<item>/<item>  become <driveletter>:/<item>/<item>
//
// The resulting string, especially with a relative path, will probably contain
// mixed slashes. We beleive Windows handles this.
//
// Adds the string "post" to the resulting string end
//
// The string  must be freed
WCHAR* oe_syscall_path_to_win(const char* path, const char* post)
{
    WCHAR* wpath = NULL;
    char* current_dir = NULL;

    if (!path || strnlen_s(path, OE_PATH_MAX) == 0 || strnlen_s(path, OE_PATH_MAX) == OE_PATH_MAX)
    {
        _set_errno(OE_EINVAL);
        goto done;
    }

    if (strcmp(path, "/dev/null") == 0)
    {
        // Just return "nul". On windows nul is the equivolent of /dev/null
        // on Linux.
        wpath = (WCHAR*)(calloc(strlen("nul"), sizeof(WCHAR)));
        if (!wpath)
        {
            _set_errno(OE_ENOMEM);
            goto done;
        }
        wpath[0] = 'n';
        wpath[1] = 'u';
        wpath[2] = 'l';
        wpath[3] = '\0';

        goto done;
    }

    size_t required_size = 0;
    size_t current_dir_len = 0;
    int pathlen = -1;
    size_t postlen = 0;

    pathlen = MultiByteToWideChar(CP_UTF8, 0, path, -1, NULL, 0);
    // positive length is expected return.
    if (pathlen <= 0)
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

    if (post)
    {
        postlen = MultiByteToWideChar(CP_UTF8, 0, post, -1, NULL, 0);
        // positive length is expected return.
        if (postlen <= 0)
        {
            _set_errno(_winerr_to_errno(GetLastError()));
            goto done;
        }
    }

    if (path[0] == '/')
    {
        // /c/dir/file
        if ((pathlen >=3 && path[0] == '/' && isalpha(path[1]) && path[2] == '/') ||
                // /c only
                (pathlen == 2 && path[0] =='/' && isalpha(path[1]) && path[2] == '\0'))
        {
            required_size = pathlen + postlen + 1;
            wpath = (WCHAR*)(calloc(required_size, sizeof(WCHAR)));
            if (!wpath)
            {
                _set_errno(OE_ENOMEM);
                goto done;
            }

            if(!MultiByteToWideChar(
                CP_UTF8, 0, path, -1, wpath, (int)pathlen))
            {
                _set_errno(_winerr_to_errno(GetLastError()));
                free(wpath);
                goto done;
            }
            if (postlen)
            {
                if (!MultiByteToWideChar(
                    CP_UTF8, 0, post, -1, wpath + pathlen - 1, (int)postlen))
                {
                    _set_errno(_winerr_to_errno(GetLastError()));
                    free(wpath);
                    goto done;
                }
            }

            wpath[0] = wpath[1];
            wpath[1] = ':';
        }
        else
        {
            // Absolute path needs drive letter
            required_size = pathlen + postlen + 3;
            wpath = (WCHAR*)(calloc(required_size, sizeof(WCHAR)));
            if (!wpath)
            {
                _set_errno(OE_ENOMEM);
                goto done;
            }

            if(!MultiByteToWideChar(
                CP_UTF8, 0, path, -1, wpath + 2, (int)pathlen))
            {
                _set_errno(_winerr_to_errno(GetLastError()));
                free(wpath);
                goto done;
            }
            if (postlen)
            {
                if(!MultiByteToWideChar(
                    CP_UTF8, 0, post, -1, wpath + pathlen - 1, (int)postlen))
                {
                    _set_errno(_winerr_to_errno(GetLastError()));
                    free(wpath);
                    goto done;
                }
            }

            // getdrive returns 1 for A:
            int drive = _getdrive();
            if (drive <= 0)
            {
                _set_errno(_winerr_to_errno(GetLastError()));
                goto done;
            }

            wpath[0] = drive + 'a' - 1;
            wpath[1] = ':';
        }
    }
    else
    {
        // Relative path
        WCHAR* current_dir = _wgetcwd(NULL, 0);
        if (!current_dir)
        {
            _set_errno(OE_ENOMEM);
            goto done;
        }
        size_t current_dir_len = wcslen(current_dir);

        required_size = pathlen + current_dir_len + postlen + 1;
        wpath = (WCHAR*)(calloc(required_size, sizeof(WCHAR)));
        if (!wpath)
        {
            _set_errno(OE_ENOMEM);
            goto done;
        }

        oe_memcpy_s(wpath, required_size * sizeof(WCHAR), current_dir, current_dir_len * sizeof(WCHAR));
        wpath[current_dir_len++] = '\\';
        if(!MultiByteToWideChar(
            CP_UTF8, 0, path, -1, wpath + current_dir_len, pathlen))
        {
            _set_errno(_winerr_to_errno(GetLastError()));
            free(wpath);
            wpath = NULL;
            goto done;
        }
        if (postlen)
        {
            if(!MultiByteToWideChar(CP_UTF8, 0, path, -1,
                wpath + current_dir_len + pathlen - 1, (int)postlen))
            {
                _set_errno(_winerr_to_errno(GetLastError()));
                free(wpath);
                wpath = NULL;
                goto done;
            }
        }
    }

    for (int i = 0; i < required_size; i++)
    {
        if (wpath[i] == '/')
        {
            wpath[i] = '\\';
        }
    }

    wpath[required_size - 1] = '\0';

done:
    if (current_dir)
    {
        free(current_dir);
    }
    return wpath;
}

//
// windows is much poorer in file bits than unix, but they reencoded the
// corresponding bits, so we have to translate
static unsigned win_stat_to_stat(unsigned winstat)
{
    unsigned ret_stat = 0;

    if (winstat & _S_IFDIR)
    {
        ret_stat |= OE_S_IFDIR;
    }
    if (winstat & _S_IFCHR)
    {
        ret_stat |= OE_S_IFCHR;
    }
    if (winstat & _S_IFIFO)
    {
        ret_stat |= OE_S_IFIFO;
    }
    if (winstat & _S_IFREG)
    {
        ret_stat |= OE_S_IFREG;
    }
    if (winstat & _S_IREAD)
    {
        ret_stat |= OE_S_IRUSR;
    }
    if (winstat & _S_IWRITE)
    {
        ret_stat |= OE_S_IWUSR;
    }
    if (winstat & _S_IEXEC)
    {
        ret_stat |= OE_S_IXUSR;
    }

    return ret_stat;
}

/* Mask to extract open() access mode flags: O_RDONLY, O_WRONLY, O_RDWR. */
#define OPEN_ACCESS_MODE_MASK 0x00000003

oe_host_fd_t oe_syscall_open_ocall(
    const char* pathname,
    int flags,
    oe_mode_t mode)
{
    oe_host_fd_t ret = -1;
    WCHAR* wpathname = NULL;

    if (strcmp(pathname, "/dev/stdin") == 0)
    {
        if ((flags & OPEN_ACCESS_MODE_MASK) != OE_O_RDONLY)
        {
            _set_errno(OE_EINVAL);
            goto done;
        }

        ret = (oe_host_fd_t)GetStdHandle(STD_INPUT_HANDLE);
        goto done;
    }
    else if (strcmp(pathname, "/dev/stdout") == 0)
    {
        if ((flags & OPEN_ACCESS_MODE_MASK) != OE_O_WRONLY)
        {
            _set_errno(OE_EINVAL);
            goto done;
        }

        ret = (oe_host_fd_t)GetStdHandle(STD_OUTPUT_HANDLE);
        goto done;
    }
    else if (strcmp(pathname, "/dev/stderr") == 0)
    {
        if ((flags & OPEN_ACCESS_MODE_MASK) != OE_O_WRONLY)
        {
            _set_errno(OE_EINVAL);
            goto done;
        }

        ret = (oe_host_fd_t)GetStdHandle(STD_ERROR_HANDLE);
        goto done;
    }
    else
    {
        DWORD desired_access = 0;
        DWORD share_mode = 0;
        DWORD create_dispos = OPEN_EXISTING;
        DWORD file_flags = (FILE_ATTRIBUTE_NORMAL | FILE_FLAG_POSIX_SEMANTICS);
        wpathname = oe_syscall_path_to_win(pathname, NULL);

        if ((flags & OE_O_DIRECTORY) != 0)
        {
            file_flags |=
                FILE_FLAG_BACKUP_SEMANTICS; // This will make a directory. Not
                                            // obvious but there it is
        }

        switch (flags & (OE_O_CREAT | OE_O_EXCL | OE_O_TRUNC))
        {
            case OE_O_CREAT:
            {
                // Create a new file or open an existing file.
                create_dispos = OPEN_ALWAYS;
                break;
            }
            case OE_O_CREAT | OE_O_EXCL:
            case OE_O_CREAT | OE_O_EXCL | OE_O_TRUNC:
            {
                // Create a new file, but fail if it already exists.
                // Ignore `O_TRUNC` with `O_CREAT | O_EXCL`
                create_dispos = CREATE_NEW;
                break;
            }
            case OE_O_CREAT | OE_O_TRUNC:
            {
                // Truncate file if it already exists.
                create_dispos = CREATE_ALWAYS;
                break;
            }
            case OE_O_TRUNC:
            case OE_O_TRUNC | OE_O_EXCL:
            {
                // Truncate file if it exists, otherwise fail. Ignore O_EXCL
                // flag.
                create_dispos = TRUNCATE_EXISTING;
                break;
            }
            case OE_O_EXCL:
            default:
            {
                // Open file if it exists, otherwise fail. Ignore O_EXCL flag.
                create_dispos = OPEN_EXISTING;
                break;
            }
        }

        // in linux land, we can always share files for read and write unless
        // they have been opened exclusive
        share_mode = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
        const int ACCESS_FLAGS = 0x3; // Covers rdonly, wronly rdwr
        switch (flags & ACCESS_FLAGS)
        {
            case OE_O_RDONLY:
            {
                desired_access = GENERIC_READ;
                break;
            }
            case OE_O_WRONLY:
            {
                desired_access =
                    (flags & OE_O_APPEND) ? FILE_APPEND_DATA : GENERIC_WRITE;
                break;
            }
            case OE_O_RDWR:
            {
                desired_access =
                    GENERIC_READ |
                    ((flags & OE_O_APPEND) ? FILE_APPEND_DATA : GENERIC_WRITE);
                break;
            }
            default:
                ret = -1;
                _set_errno(OE_EINVAL);
                goto done;
                break;
        }

        if (mode & OE_S_IRUSR)
            desired_access |= GENERIC_READ;
        if (mode & OE_S_IWUSR)
            desired_access |= GENERIC_WRITE;

        HANDLE h = CreateFileW(
            wpathname,
            desired_access,
            share_mode,
            NULL,
            create_dispos,
            file_flags,
            NULL);
        if (h == INVALID_HANDLE_VALUE)
        {
            _set_errno(_winerr_to_errno(GetLastError()));
            goto done;
        }

        ret = (oe_host_fd_t)h;

        // Windows doesn't do mode in the same way as linux. We can set user
        // read/write and thats about it. There are elaborate ACLs and the such
        // for code which is purpose written, but the only part of file mode
        // expressed in windows is the read-only bit, and only for the owner.
        if (flags & OE_O_CREAT)
        {
            int wmode = ((mode & OE_S_IRUSR) ? _S_IREAD : 0) |
                        ((mode & OE_S_IWUSR) ? _S_IWRITE : 0);

            int retx = _wchmod(wpathname, wmode);
            if (retx < 0)
            {
                _set_errno(_winerr_to_errno(GetLastError()));
                goto done;
            }
        }
    }

done:
    if (wpathname)
    {
        free(wpathname);
    }
    return ret;
}

ssize_t oe_syscall_read_ocall(oe_host_fd_t fd, void* buf, size_t count)
{
    ssize_t ret = -1;
    DWORD bytes_returned = 0;

    HANDLE handle = (HANDLE)fd;

    // Convert fd 0, 1, 2 as needed
    switch (fd)
    {
        case 0:
            handle = GetStdHandle(STD_INPUT_HANDLE);
            break;

        case 1:
        case 2:
            _set_errno(OE_EBADF);
            goto done;

        default:
            break;
    }

    if (!ReadFile(handle, buf, (DWORD)count, &bytes_returned, NULL))
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

    ret = (ssize_t)bytes_returned;

done:
    return ret;
}

ssize_t oe_syscall_write_ocall(oe_host_fd_t fd, const void* buf, size_t count)
{
    ssize_t ret = -1;
    DWORD bytes_written = 0;

    HANDLE handle = (HANDLE)fd;

    // Convert fd 0, 1, 2 as needed
    switch (fd)
    {
        case 0:
            // Error. You cant write to stdin
            _set_errno(OE_EBADF);
            goto done;

        case 1:
            handle = GetStdHandle(STD_OUTPUT_HANDLE);
            break;

        case 2:
            handle = GetStdHandle(STD_ERROR_HANDLE);
            break;

        default:
            break;
    }

    if (!WriteFile(handle, buf, (DWORD)count, &bytes_written, NULL))
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

    ret = (ssize_t)bytes_written;

done:
    return ret;
}

ssize_t oe_syscall_readv_ocall(
    oe_host_fd_t fd,
    void* iov_buf,
    int iovcnt,
    size_t iov_buf_size)
{
    struct oe_iovec* iov = (struct oe_iovec*)iov_buf;
    ssize_t ret = -1;
    ssize_t size_read;

    errno = 0;

    if ((!iov && iovcnt) || iovcnt < 0 || iovcnt > OE_IOV_MAX)
    {
        errno = EINVAL;
        goto done;
    }

    /* Handle zero data case. */
    if (!iov || iovcnt == 0)
    {
        ret = 0;
        goto done;
    }

    {
        void* buf;
        size_t count;

        buf = &iov[iovcnt];
        count = iov_buf_size - ((size_t)iovcnt * sizeof(struct oe_iovec));

        size_read = oe_syscall_read_ocall(fd, buf, count);
    }

    ret = size_read;

done:
    return ret;
}

ssize_t oe_syscall_writev_ocall(
    oe_host_fd_t fd,
    const void* iov_buf,
    int iovcnt,
    size_t iov_buf_size)
{
    ssize_t ret = -1;
    ssize_t size_written;
    struct oe_iovec* iov = (struct oe_iovec*)iov_buf;

    errno = 0;

    if ((!iov && iovcnt) || iovcnt < 0 || iovcnt > OE_IOV_MAX)
    {
        errno = EINVAL;
        goto done;
    }

    /* Handle zero data case. */
    if (!iov || iovcnt == 0)
    {
        ret = 0;
        goto done;
    }

    {
        const void* buf;
        size_t count;

        buf = &iov[iovcnt];
        count = iov_buf_size - ((size_t)iovcnt * sizeof(struct oe_iovec));

        size_written = oe_syscall_write_ocall(fd, buf, count);
    }

    ret = size_written;

done:
    return ret;
}

oe_off_t oe_syscall_lseek_ocall(oe_host_fd_t fd, oe_off_t offset, int whence)
{
    ssize_t ret = -1;
    DWORD sfp_rtn = 0;
    LARGE_INTEGER new_offset = {0};

    new_offset.QuadPart = offset;
    if (!SetFilePointerEx(
            (HANDLE)fd, new_offset, (PLARGE_INTEGER)&new_offset, whence))
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

    ret = (oe_off_t)new_offset.QuadPart;

done:
    return ret;
}

int oe_syscall_close_ocall(oe_host_fd_t fd)
{
    int ret = -1;
    HANDLE handle = (HANDLE)fd;

    // Convert fd 0, 1, 2 as needed
    switch (fd)
    {
        case 0:
            handle = GetStdHandle(STD_INPUT_HANDLE);
            break;

        case 1:
            handle = GetStdHandle(STD_OUTPUT_HANDLE);
            break;

        case 2:
            handle = GetStdHandle(STD_ERROR_HANDLE);
            break;

        default:
            break;
    }

    if (handle < 0)
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

    ret = !CloseHandle(handle);
    if (ret)
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

done:
    return ret;
}

static oe_host_fd_t _dup_socket(oe_host_fd_t);

oe_host_fd_t oe_syscall_dup_ocall(oe_host_fd_t fd)
{
    oe_host_fd_t ret = -1;
    // suppose fd is a handle.
    HANDLE oldhandle = (HANDLE)fd;

    // If fd is a stdin/out/err, convert it to the corresponding HANDLE.
    switch (fd)
    {
        case 0:
            oldhandle = GetStdHandle(STD_INPUT_HANDLE);
            break;

        case 1:
            oldhandle = GetStdHandle(STD_OUTPUT_HANDLE);
            break;

        case 2:
            oldhandle = GetStdHandle(STD_ERROR_HANDLE);
            break;

        default:
            break;
    }

    // Now try to dup it as a handle first.
    if (oldhandle >= 0 && DuplicateHandle(
            GetCurrentProcess(),
            oldhandle,
            GetCurrentProcess(),
            (HANDLE*)&ret,
            0,
            FALSE,
            DUPLICATE_SAME_ACCESS))
    {
        _set_errno(0);
        goto done;
    }

    _set_errno(_winerr_to_errno(GetLastError()));

    // if fd is not a HANDLE, then try to dup it as a socket.
    ret = _dup_socket(fd);
    if (ret == -1)
        _set_errno(OE_EINVAL);
    else
        _set_errno(0);

done:
    return ret;
}

struct WIN_DIR_DATA
{
    HANDLE hFind;
    WIN32_FIND_DATAW FindFileData;
    int dir_offs;
    WCHAR* pdirpath;
};

uint64_t oe_syscall_opendir_ocall(const char* pathname)
{
    struct WIN_DIR_DATA* pdir = NULL;

    pdir = (struct WIN_DIR_DATA*)calloc(1, sizeof(struct WIN_DIR_DATA));
    if (!pdir)
    {
        goto done;
    }

    WCHAR* wpathname = oe_syscall_path_to_win(pathname, "/*");
    pdir->hFind = FindFirstFileW(wpathname, &pdir->FindFileData);
    if (pdir->hFind == INVALID_HANDLE_VALUE)
    {
        free(wpathname);
        free(pdir);
        pdir = NULL;
        goto done;
    }

    pdir->dir_offs = 0;
    pdir->pdirpath = wpathname;

done:
    return (uint64_t)pdir;
}

int oe_syscall_readdir_ocall(uint64_t dirp, struct oe_dirent* entry)
{
    int ret = -1;

    struct WIN_DIR_DATA* pdir = (struct WIN_DIR_DATA*)dirp;
    int nlen = -1;

    _set_errno(0);

    if (!dirp || !entry)
    {
        _set_errno(OE_EINVAL);
        ret = -1;
        goto done;
    }

    // Find file next doesn't return '.' because it shows up in opendir and we
    // lose it but we know it is there, so we can just return it
    if (pdir->dir_offs == 0)
    {
        entry->d_off = pdir->dir_offs++;
        entry->d_type = OE_DT_DIR;
        entry->d_reclen = sizeof(struct oe_dirent);
        entry->d_name[0] = '.';
        entry->d_name[1] = '\0';
        ret = 0;
        goto done;
    }

    if (!FindNextFileW(pdir->hFind, &pdir->FindFileData))
    {
        DWORD winerr = GetLastError();

        if (winerr == ERROR_NO_MORE_FILES)
        {
            /* Return 1 to indicate there no more entries. */
            ret = 1;
        }
        else
        {
            _set_errno(_winerr_to_errno(winerr));
            ret = -1;
        }
        goto done;
    }

    nlen = WideCharToMultiByte(
        CP_UTF8, 0, pdir->FindFileData.cFileName, -1, NULL, 0, NULL, NULL);
    (void)WideCharToMultiByte(
        CP_UTF8,
        0,
        pdir->FindFileData.cFileName,
        nlen,
        entry->d_name,
        sizeof(entry->d_name),
        NULL,
        NULL);

    if(nlen == 0)
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

    entry->d_type = 0;
    if (pdir->FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
    {
        entry->d_type = OE_DT_DIR;
    }
    else if (pdir->FindFileData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
    {
        entry->d_type = OE_DT_LNK;
    }
    else
    {
        entry->d_type = OE_DT_REG;
    }

    entry->d_off = pdir->dir_offs++;
    entry->d_reclen = sizeof(struct oe_dirent);

    ret = 0;

done:
    return ret;
}

void oe_syscall_rewinddir_ocall(uint64_t dirp)
{
    DWORD err = 0;
    struct WIN_DIR_DATA* pdir = (struct WIN_DIR_DATA*)dirp;
    WCHAR* wpathname = pdir->pdirpath;
    // Undo abosolute path forcing again. We do this over because we need to
    // preserve the allocation address for free.
    if (wcslen(wpathname) >= 3 && wpathname[0] == '/' && wpathname[2] == ':')
    {
        wpathname++;
    }

    if(!FindClose(pdir->hFind))
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

    memset(&pdir->FindFileData, 0, (size_t)sizeof(pdir->FindFileData));

    pdir->hFind = FindFirstFileW(wpathname, &pdir->FindFileData);
    if (pdir->hFind == INVALID_HANDLE_VALUE)
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }
    pdir->dir_offs = 0;

done:
    return;
}

int oe_syscall_closedir_ocall(uint64_t dirp)
{
    int ret = -1;
    struct WIN_DIR_DATA* pdir = (struct WIN_DIR_DATA*)dirp;

    if (!dirp)
    {
        goto done;
    }
    if (!FindClose(pdir->hFind))
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

    free(pdir->pdirpath);
    pdir->pdirpath = NULL;
    free(pdir);
    ret = 0;

done:
    return ret;
}

int oe_syscall_stat_ocall(const char* pathname, struct oe_stat* buf)
{
    int ret = -1;
    WCHAR* wpathname = oe_syscall_path_to_win(pathname, NULL);
    struct _stat64 winstat = {0};

    ret = _wstat64(wpathname, &winstat);
    if (ret < 0)
    {
        // How do we get to  wstat's error

        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

#undef st_atime
#undef st_mtime
#undef st_ctime

    buf->st_dev = winstat.st_dev;
    buf->st_ino = winstat.st_ino;
    buf->st_mode = win_stat_to_stat(winstat.st_mode);
    buf->st_nlink = winstat.st_nlink;
    buf->st_uid = winstat.st_uid;
    buf->st_gid = winstat.st_gid;
    buf->st_rdev = winstat.st_rdev;
    buf->st_size = winstat.st_size;
    buf->st_atim.tv_sec = winstat.st_atime;
    buf->st_mtim.tv_sec = winstat.st_mtime;
    buf->st_ctim.tv_sec = winstat.st_ctime;

done:

    if (wpathname)
    {
        free(wpathname);
    }

    return ret;
}

int oe_syscall_access_ocall(const char* pathname, int mode)
{
    int ret = -1;
    WCHAR* wpathname = oe_syscall_path_to_win(pathname, NULL);

    int winmode = mode & ~1; // X_OK is a noop but makes access unhappy
    ret = _waccess(wpathname, winmode);
    if (ret < 0)
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

done:
    if (wpathname)
    {
        free(wpathname);
    }
    return ret;
}

int oe_syscall_link_ocall(const char* oldpath, const char* newpath)
{
    int ret = -1;
    WCHAR* oldwpath = oe_syscall_path_to_win(oldpath, NULL);
    WCHAR* newwpath = oe_syscall_path_to_win(newpath, NULL);

    if (!CreateHardLinkW(newwpath, oldwpath, NULL))
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }
    ret = 0;

done:
    if (oldwpath)
    {
        free(oldwpath);
    }

    if (newwpath)
    {
        free(newwpath);
    }
    return ret;
}

int oe_syscall_unlink_ocall(const char* pathname)
{
    int ret = -1;
    WCHAR* wpathname = oe_syscall_path_to_win(pathname, NULL);

    ret = _wunlink(wpathname);
    if (ret < 0)
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

done:
    if (wpathname)
    {
        free(wpathname);
    }
    return ret;
}

int oe_syscall_rename_ocall(const char* oldpath, const char* newpath)
{
    int ret = -1;
    WCHAR* oldwpath = oe_syscall_path_to_win(oldpath, NULL);
    WCHAR* newwpath = oe_syscall_path_to_win(newpath, NULL);

    ret = _wrename(oldwpath, newwpath);
    if (ret < 0)
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

done:
    if (oldwpath)
    {
        free(oldwpath);
    }

    if (newwpath)
    {
        free(newwpath);
    }
    return ret;
}

int oe_syscall_truncate_ocall(const char* pathname, oe_off_t length)
{
    int ret = -1;
    DWORD sfp_rtn = 0;
    LARGE_INTEGER new_offset = {0};
    WCHAR* wpathname = oe_syscall_path_to_win(pathname, NULL);

    HANDLE h = CreateFileW(
        wpathname,
        GENERIC_WRITE,
        FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (h == INVALID_HANDLE_VALUE)
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

    new_offset.QuadPart = length;
    if (!SetFilePointerEx(
            h, new_offset, (PLARGE_INTEGER)&new_offset, FILE_BEGIN))
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

    if (!SetEndOfFile(h))
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

    ret = !CloseHandle(h);
    if (ret)
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

done:
    if (wpathname)
    {
        free(wpathname);
    }
    return ret;
}

int oe_syscall_mkdir_ocall(const char* pathname, oe_mode_t mode)
{
    int ret = -1;
    WCHAR* wpathname = oe_syscall_path_to_win(pathname, NULL);

    ret = _wmkdir(wpathname);
    if (ret < 0)
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

done:
    if (wpathname)
    {
        free(wpathname);
    }
    return ret;
}

int oe_syscall_rmdir_ocall(const char* pathname)
{
    int ret = -1;
    WCHAR* wpathname = oe_syscall_path_to_win(pathname, NULL);

    ret = _wrmdir(wpathname);
    if (ret < 0)
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

done:
    if (wpathname)
    {
        free(wpathname);
    }
    return ret;
}

/*
**==============================================================================
**
** Socket I/O:
**
**==============================================================================
*/

#define OE_SOCKET_FD_MAGIC 0x29b4a345c7564b57
typedef struct win_socket_fd
{
    uint64_t magic;
    SOCKET socket;
} oe_socket_fd_t;

static oe_socket_fd_t _invalid_socket = {OE_SOCKET_FD_MAGIC, INVALID_SOCKET};

oe_host_fd_t _make_socket_fd(SOCKET sock)
{
    oe_host_fd_t fd = (oe_host_fd_t)&_invalid_socket;
    if (sock != INVALID_SOCKET)
    {
        oe_socket_fd_t* socket_fd =
            (oe_socket_fd_t*)malloc(sizeof(oe_socket_fd_t));
        if (socket_fd)
        {
            socket_fd->magic = OE_SOCKET_FD_MAGIC;
            socket_fd->socket = sock;
            fd = (oe_host_fd_t)socket_fd;
        }
    }
    return fd;
}

SOCKET _get_socket(oe_host_fd_t fd)
{
    oe_socket_fd_t* socket_fd = (oe_socket_fd_t*)fd;
    if (socket_fd && socket_fd->magic == OE_SOCKET_FD_MAGIC)
        return socket_fd->socket;
    return INVALID_SOCKET;
}

static oe_host_fd_t _dup_socket(oe_host_fd_t oldfd)
{
    oe_socket_fd_t* old_socket_fd = (oe_socket_fd_t*)oldfd;
    if (old_socket_fd && old_socket_fd->magic == OE_SOCKET_FD_MAGIC)
    {
        // Duplicate socket
        WSAPROTOCOL_INFO protocolInfo;
        int ret = WSADuplicateSocket(
            old_socket_fd->socket, GetCurrentProcessId(), &protocolInfo);
        if (ret == SOCKET_ERROR)
        {
            _set_errno(_winsockerr_to_errno(WSAGetLastError()));
        }

        SOCKET sock = WSASocket(
            protocolInfo.iAddressFamily,
            protocolInfo.iSocketType,
            protocolInfo.iProtocol,
            &protocolInfo,
            0,
            0);
        if (sock == INVALID_SOCKET)
        {
            _set_errno(_winsockerr_to_errno(WSAGetLastError()));
        }

        return _make_socket_fd(sock);
    }

    return -1;
}

static int _wsa_startup()
{
    static int64_t wsa_init_done = FALSE;
    WSADATA wsaData;
    int ret = 0;

    if (oe_atomic_compare_and_swap(
            (volatile int64_t*)&wsa_init_done, (int64_t)0, (int64_t)1))
    {
        ret = WSAStartup(2, &wsaData);
        if (ret != 0)
            goto done;
    }

done:
    return ret;
}

oe_host_fd_t oe_syscall_socket_ocall(int domain, int type, int protocol)
{
    SOCKET sock = INVALID_SOCKET;

    if (_wsa_startup() != 0)
    {
        _set_errno(OE_EINVAL);
        goto done;
    }

    sock = socket(domain, type, protocol);
    if (sock == INVALID_SOCKET)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
    }

done:
    return _make_socket_fd(sock);
}

int oe_syscall_socketpair_ocall(
    int domain,
    int type,
    int protocol,
    oe_host_fd_t sv_out[2])
{
    OE_UNUSED(domain);
    OE_UNUSED(type);
    OE_UNUSED(protocol);
    OE_UNUSED(sv_out);

    PANIC;
}

int oe_syscall_connect_ocall(
    oe_host_fd_t sockfd,
    const struct oe_sockaddr* addr,
    oe_socklen_t addrlen)
{
    int ret = connect(
        _get_socket(sockfd), (const struct sockaddr*)addr, (int)addrlen);
    if (ret != 0)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
    }

    return ret;
}

oe_host_fd_t oe_syscall_accept_ocall(
    oe_host_fd_t sockfd,
    struct oe_sockaddr* addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out)
{
    int addrlen = (int)addrlen_in;
    SOCKET conn_socket = accept(
        _get_socket(sockfd),
        (struct sockaddr*)addr,
        addrlen_out ? &addrlen : NULL);
    if (conn_socket == INVALID_SOCKET)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
        goto done;
    }

    if (addrlen_out)
        *addrlen_out = addrlen;

done:
    return _make_socket_fd(conn_socket);
}

int oe_syscall_bind_ocall(
    oe_host_fd_t sockfd,
    const struct oe_sockaddr* addr,
    oe_socklen_t addrlen)
{
    int ret = bind(_get_socket(sockfd), (const struct sockaddr*)addr, addrlen);
    if (ret != 0)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
    }

    return ret;
}

int oe_syscall_listen_ocall(oe_host_fd_t sockfd, int backlog)
{
    int ret = listen(_get_socket(sockfd), backlog);
    if (ret != 0)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
    }

    return ret;
}

ssize_t oe_syscall_recvmsg_ocall(
    oe_host_fd_t sockfd,
    void* msg_name,
    oe_socklen_t msg_namelen,
    oe_socklen_t* msg_namelen_out,
    void* msg_iov_buf,
    size_t msg_iovlen,
    size_t msg_iov_buf_size,
    void* msg_control,
    size_t msg_controllen,
    size_t* msg_controllen_out,
    int flags)
{
    OE_UNUSED(sockfd);
    OE_UNUSED(msg_name);
    OE_UNUSED(msg_namelen);
    OE_UNUSED(msg_namelen_out);
    OE_UNUSED(msg_iov_buf);
    OE_UNUSED(msg_iovlen);
    OE_UNUSED(msg_iov_buf_size);
    OE_UNUSED(msg_control);
    OE_UNUSED(msg_controllen);
    OE_UNUSED(msg_controllen_out);
    OE_UNUSED(flags);

    PANIC;
}

ssize_t oe_syscall_sendmsg_ocall(
    oe_host_fd_t sockfd,
    const void* msg_name,
    oe_socklen_t msg_namelen,
    void* msg_iov_buf,
    size_t msg_iovlen,
    size_t msg_iov_buf_size,
    const void* msg_control,
    size_t msg_controllen,
    int flags)
{
    OE_UNUSED(sockfd);
    OE_UNUSED(msg_name);
    OE_UNUSED(msg_namelen);
    OE_UNUSED(msg_iov_buf);
    OE_UNUSED(msg_iovlen);
    OE_UNUSED(msg_iov_buf_size);
    OE_UNUSED(msg_control);
    OE_UNUSED(msg_controllen);
    OE_UNUSED(flags);

    PANIC;
}

ssize_t oe_syscall_recv_ocall(
    oe_host_fd_t sockfd,
    void* buf,
    size_t len,
    int flags)
{
    ssize_t ret;
    _set_errno(0);

    ret = recv(_get_socket(sockfd), (char*)buf, (int)len, flags);
    if (ret == SOCKET_ERROR)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
    }

    return ret;
}

ssize_t oe_syscall_recvfrom_ocall(
    oe_host_fd_t sockfd,
    void* buf,
    size_t len,
    int flags,
    struct oe_sockaddr* src_addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out)
{
    ssize_t ret;
    _set_errno(0);

    ret = recvfrom(
        _get_socket(sockfd),
        (char*)buf,
        (int)len,
        flags,
        (struct sockaddr*)src_addr,
        (int*)&addrlen_in);
    if (ret == SOCKET_ERROR)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
    }
    else
    {
        if (addrlen_out)
            *addrlen_out = addrlen_in;
    }

    return ret;
}

ssize_t oe_syscall_send_ocall(
    oe_host_fd_t sockfd,
    const void* buf,
    size_t len,
    int flags)
{
    ssize_t ret;
    _set_errno(0);

    ret = send(_get_socket(sockfd), buf, len, flags);
    if (ret == SOCKET_ERROR)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
    }

    return ret;
}

ssize_t oe_syscall_sendto_ocall(
    oe_host_fd_t sockfd,
    const void* buf,
    size_t len,
    int flags,
    const struct oe_sockaddr* src_addr,
    oe_socklen_t addrlen)
{
    ssize_t ret;
    _set_errno(0);

    ret = sendto(
        _get_socket(sockfd),
        buf,
        len,
        flags,
        (struct sockaddr*)src_addr,
        addrlen);
    if (ret == SOCKET_ERROR)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
    }

    return ret;
}

ssize_t oe_syscall_recvv_ocall(
    oe_host_fd_t fd,
    void* iov_buf,
    int iovcnt,
    size_t iov_buf_size)
{
    OE_UNUSED(fd);
    OE_UNUSED(iov_buf);
    OE_UNUSED(iovcnt);
    OE_UNUSED(iov_buf_size);

    PANIC;
}

ssize_t oe_syscall_sendv_ocall(
    oe_host_fd_t fd,
    const void* iov_buf,
    int iovcnt,
    size_t iov_buf_size)
{
    OE_UNUSED(fd);
    OE_UNUSED(iov_buf);
    OE_UNUSED(iovcnt);
    OE_UNUSED(iov_buf_size);

    PANIC;
}

int oe_syscall_shutdown_ocall(oe_host_fd_t sockfd, int how)
{
    int ret = shutdown(_get_socket(sockfd), how);
    if (ret != 0)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
    }

    return ret;
}

int oe_syscall_close_socket_ocall(oe_host_fd_t sockfd)
{
    SOCKET sock = _get_socket(sockfd);
    int r = -1;
    if (sock != INVALID_SOCKET)
    {
        r = closesocket(sock);
        if (r != 0)
        {
            _set_errno(_winsockerr_to_errno(WSAGetLastError()));
        }

        free((oe_socket_fd_t*)sockfd);
    }
    return r;
}

#define F_GETFL 3

int oe_syscall_fcntl_ocall(
    oe_host_fd_t fd,
    int cmd,
    uint64_t arg,
    uint64_t argsize,
    void* argout)
{
    if (fd < 0)
    {
        return -1;
    }

    SOCKET sock;

    if ((sock = _get_socket(fd)) != INVALID_SOCKET)
    {
        switch (cmd)
        {
            case F_GETFL:
                // TODO: There is no way to get file access modes on winsock
                // sockets. Currently this only exists to because mbedtls uses
                // this syscall to check if the socket is blocking. If we want
                // this syscall to actually work properly for other cases, this
                // should be revisited.
                return 0;
            default:
                PANIC;
        }
    }
    else
    {
        // File operations are not supported
        PANIC;
    }
}

#define TIOCGWINSZ 0x5413
#define TIOCSWINSZ 0x5414

int oe_syscall_ioctl_ocall(
    oe_host_fd_t fd,
    uint64_t request,
    uint64_t arg,
    uint64_t argsize,
    void* argout)
{
    OE_UNUSED(fd);
    OE_UNUSED(arg);
    OE_UNUSED(argsize);
    OE_UNUSED(argout);

    errno = 0;

    // We don't support any ioctls right now as we will have to translate the
    // codes from the enclave to be the equivelent for windows. But... no such
    // codes are currently being used So we panic to highlight the problem line
    // of code. In this way, we can see what ioctls are needed

    switch (request)
    {
        case TIOCGWINSZ:
        case TIOCSWINSZ:
            _set_errno(OE_ENOTTY);
            break;
        default:
            _set_errno(OE_EINVAL);
            break;
    }

    return -1;
}

int oe_syscall_setsockopt_ocall(
    oe_host_fd_t sockfd,
    int level,
    int optname,
    const void* optval,
    oe_socklen_t optlen)
{
    level = _musl_to_bsd(level, musl2bsd_socket_level);
    optname = _musl_to_bsd(optname, musl2bsd_socket_option);

    int ret = setsockopt(_get_socket(sockfd), level, optname, optval, optlen);
    if (ret != 0)
    {
        int err = _winsockerr_to_errno(WSAGetLastError());
        _set_errno(err);
    }

    return ret;
}

int oe_syscall_getsockopt_ocall(
    oe_host_fd_t sockfd,
    int level,
    int optname,
    void* optval,
    oe_socklen_t optlen_in,
    oe_socklen_t* optlen_out)
{
    level = _musl_to_bsd(level, musl2bsd_socket_level);
    optname = _musl_to_bsd(optname, musl2bsd_socket_option);

    int ret =
        getsockopt(_get_socket(sockfd), level, optname, optval, &optlen_in);
    if (ret != 0)
    {
        int err = _winsockerr_to_errno(WSAGetLastError());
        _set_errno(err);
    }
    else
    {
        if (optlen_out)
            *optlen_out = optlen_in;
    }

    return ret;
}

int oe_syscall_getsockname_ocall(
    oe_host_fd_t sockfd,
    struct oe_sockaddr* addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out)
{
    OE_UNUSED(sockfd);
    OE_UNUSED(addr);
    OE_UNUSED(addrlen_in);
    OE_UNUSED(addrlen_out);

    PANIC;
}

int oe_syscall_getpeername_ocall(
    oe_host_fd_t sockfd,
    struct oe_sockaddr* addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out)
{
    OE_UNUSED(sockfd);
    OE_UNUSED(addr);
    OE_UNUSED(addrlen_in);
    OE_UNUSED(addrlen_out);

    PANIC;
}

int oe_syscall_shutdown_sockets_device_ocall(oe_host_fd_t sockfd)
{
    OE_UNUSED(sockfd);

    PANIC;
}

/*
**==============================================================================
**
** Signals:
**
**==============================================================================
*/

int oe_syscall_kill_ocall(int pid, int signum)
{
    OE_UNUSED(pid);
    OE_UNUSED(signum);

    PANIC;
}

/*
**==============================================================================
**
** Resolver:
**
**==============================================================================
*/

int oe_syscall_getaddrinfo_open_ocall(
    const char* node,
    const char* service,
    const struct oe_addrinfo* hints,
    uint64_t* handle_out)
{
    int ret = OE_EAI_FAIL;
    getaddrinfo_handle_t* handle = NULL;

    if (_wsa_startup() != 0)
    {
        _set_errno(OE_EINVAL);
        goto done;
    }

    _set_errno(0);

    if (handle_out)
    {
        *handle_out = 0;
    }
    else
    {
        ret = OE_EAI_SYSTEM;
        _set_errno(OE_EINVAL);
        goto done;
    }

    if (!(handle = calloc(1, sizeof(getaddrinfo_handle_t))))
    {
        ret = OE_EAI_MEMORY;
        _set_errno(OE_ENOMEM);
        goto done;
    }

    ret =
        getaddrinfo(node, service, (const struct addrinfo*)hints, &handle->res);
    if (ret == 0)
    {
        handle->magic = GETADDRINFO_HANDLE_MAGIC;
        handle->next = handle->res;
        *handle_out = (uint64_t)handle;
        handle = NULL;
    }
    else
    {
        ret = _wsaerr_to_eai(ret);
    }

done:

    if (handle)
        free(handle);

    return ret;
}

int oe_syscall_getaddrinfo_read_ocall(
    uint64_t handle_,
    int* ai_flags,
    int* ai_family,
    int* ai_socktype,
    int* ai_protocol,
    oe_socklen_t ai_addrlen_in,
    oe_socklen_t* ai_addrlen,
    struct oe_sockaddr* ai_addr,
    size_t ai_canonnamelen_in,
    size_t* ai_canonnamelen,
    char* ai_canonname)
{
    int err_no = 0;
    int ret = _getaddrinfo_read(
        handle_,
        ai_flags,
        ai_family,
        ai_socktype,
        ai_protocol,
        ai_addrlen_in,
        ai_addrlen,
        ai_addr,
        ai_canonnamelen_in,
        ai_canonnamelen,
        ai_canonname,
        &err_no);
    _set_errno(err_no);

    return ret;
}

int oe_syscall_getaddrinfo_close_ocall(uint64_t handle_)
{
    int ret = -1;
    getaddrinfo_handle_t* handle = _cast_getaddrinfo_handle((void*)handle_);

    _set_errno(0);

    if (!handle)
    {
        _set_errno(OE_EINVAL);
        goto done;
    }

    freeaddrinfo(handle->res);
    free(handle);

    ret = 0;

done:
    return ret;
}

int oe_syscall_getnameinfo_ocall(
    const struct oe_sockaddr* sa,
    oe_socklen_t salen,
    char* host,
    oe_socklen_t hostlen,
    char* serv,
    oe_socklen_t servlen,
    int flags)
{
    OE_UNUSED(sa);
    OE_UNUSED(salen);
    OE_UNUSED(host);
    OE_UNUSED(hostlen);
    OE_UNUSED(serv);
    OE_UNUSED(servlen);
    OE_UNUSED(flags);

    PANIC;
}

/*
**==============================================================================
**
** Polling:
**
**==============================================================================
*/

oe_host_fd_t oe_syscall_epoll_create1_ocall(int flags)
{
    OE_UNUSED(flags);

    PANIC;
}

int oe_syscall_epoll_wait_ocall(
    int64_t epfd,
    struct oe_epoll_event* events,
    unsigned int maxevents,
    int timeout)
{
    OE_UNUSED(epfd);
    OE_UNUSED(events);
    OE_UNUSED(maxevents);
    OE_UNUSED(timeout);

    PANIC;
}

int oe_syscall_epoll_wake_ocall(void)
{
    PANIC;
}

int oe_syscall_epoll_ctl_ocall(
    int64_t epfd,
    int op,
    int64_t fd,
    struct oe_epoll_event* event)
{
    OE_UNUSED(epfd);
    OE_UNUSED(op);
    OE_UNUSED(fd);
    OE_UNUSED(event);

    PANIC;
}

int oe_syscall_epoll_close_ocall(oe_host_fd_t epfd)
{
    OE_UNUSED(epfd);

    PANIC;
}

/*
**==============================================================================
**
** poll()
**
**==============================================================================
*/

int oe_syscall_poll_ocall(
    struct oe_host_pollfd* host_fds,
    oe_nfds_t nfds,
    int timeout)
{
    OE_UNUSED(host_fds);
    OE_UNUSED(nfds);
    OE_UNUSED(timeout);

    PANIC;
}

/*
**==============================================================================
**
** uid, gid, pid, and groups:
**
**==============================================================================
*/

int oe_syscall_getpid_ocall(void)
{
    PANIC;
}

int oe_syscall_getppid_ocall(void)
{
    PANIC;
}

int oe_syscall_getpgrp_ocall(void)
{
    PANIC;
}

unsigned int oe_syscall_getuid_ocall(void)
{
    PANIC;
}

unsigned int oe_syscall_geteuid_ocall(void)
{
    PANIC;
}

unsigned int oe_syscall_getgid_ocall(void)
{
    PANIC;
}

unsigned int oe_syscall_getegid_ocall(void)
{
    PANIC;
}

int oe_syscall_getpgid_ocall(int pid)
{
    OE_UNUSED(pid);

    PANIC;
}

int oe_syscall_getgroups_ocall(size_t size, unsigned int* list)
{
    OE_UNUSED(size);
    OE_UNUSED(list);

    PANIC;
}

/*
**==============================================================================
**
** uname():
**
**==============================================================================
*/

int oe_syscall_uname_ocall(struct oe_utsname* buf)
{
    int ret = -1;

    if (!buf)
    {
        _set_errno(OE_EINVAL);
        goto done;
    }

    // Get domain name
    DWORD size = sizeof(buf->domainname);
    if (!GetComputerNameEx(ComputerNameDnsDomain, buf->domainname, &size))
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

    // Get hostname
    size = sizeof(buf->nodename);
    if (!GetComputerNameEx(ComputerNameDnsHostname, buf->nodename, &size))
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

    // Based on
    // https://docs.microsoft.com/en-us/windows/win32/sysinfo/getting-the-system-version
    // OE SDK is supported only on WindowsServer and Win10
    if (IsWindowsServer())
    {
        sprintf(buf->sysname, "WindowsServer");
        sprintf(buf->version, "2016OrAbove");
    }
    else if (IsWindows10OrGreater())
    {
        sprintf(buf->sysname, "Windows10OrGreater");
        sprintf(buf->version, "10OrAbove");
    }

    ret = 0;

done:
    return ret;
}
