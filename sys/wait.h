/*
MIT License

Copyright (c) 2025 win32ports(Form Github user Macintosh-Maisensei)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#ifndef __SYS_WAIT_H__
#define __SYS_WAIT_H__

#ifdef _WIN32

#ifdef __cplusplus
extern "C" {
#endif

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define WIN32_LEAN_AND_MEAN
#include <tlhelp32.h>
#include <windows.h>

#if !defined(pid_t)
typedef int pid_t;
#endif

#if !defined(id_t)
typedef unsigned id_t;
#endif

#if !defined(uid_t)
typedef unsigned uid_t;
#endif

#ifndef __siginfo_t_defined
#define __siginfo_t_defined
typedef struct {
  int si_signo;
  int si_code;
  int si_errno;
  pid_t si_pid;
  uid_t si_uid;
  void *si_addr;
  int si_status;
  long si_band;
} siginfo_t;
#endif

struct timeval {
  long tv_sec;
  long tv_usec;
};

struct rusage {
  struct timeval ru_utime;
  struct timeval ru_stime;
};

#ifndef WNOHANG
#define WNOHANG 1
#endif

#ifndef WUNTRACED
#define WUNTRACED 2
#endif

#ifndef WCONTINUED
#define WCONTINUED 8
#endif

#define __WEXITSTATUS(status) (((status) & 0xFF00) >> 8)
#define __WTERMSIG(status) ((status) & 0x7F)
#define __WSTOPSIG(status) __WEXITSTATUS(status)

#define WEXITSTATUS(status) __WEXITSTATUS(status)
#define WTERMSIG(status) __WTERMSIG(status)
#define WSTOPSIG(status) __WSTOPSIG(status)

#define __WIFEXITED(status) (__WTERMSIG(status) == 0)
#define __WIFSIGNALED(status) (((signed char)(__WTERMSIG(status) + 1) >> 1) > 0)
#define __WIFSTOPPED(status) (((status) & 0xFF) == 0x7F)

#define WIFEXITED(status) __WIFEXITED(status)
#define WIFSIGNALED(status) __WIFSIGNALED(status)
#define WIFSTOPPED(status) __WIFSTOPPED(status)

static int __match_any_child(PROCESSENTRY32 *pe, DWORD current_pid) {
  return pe->th32ParentProcessID == current_pid;
}

static int __match_pid(PROCESSENTRY32 *pe, DWORD target_pid) {
  return pe->th32ProcessID == target_pid;
}

static int __match_current_group(PROCESSENTRY32 *pe, DWORD current_pid) {
  HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnapshot == INVALID_HANDLE_VALUE)
    return 0;

  PROCESSENTRY32 current_pe;
  current_pe.dwSize = sizeof(PROCESSENTRY32);
  DWORD parent_pid = 0;

  if (Process32First(hSnapshot, &current_pe)) {
    do {
      if (current_pe.th32ProcessID == current_pid) {
        parent_pid = current_pe.th32ParentProcessID;
        break;
      }
    } while (Process32Next(hSnapshot, &current_pe));
  }
  CloseHandle(hSnapshot);
  return pe->th32ParentProcessID == parent_pid;
}

static int __match_target_group(PROCESSENTRY32 *pe, DWORD target_pgid) {
  return pe->th32ParentProcessID == target_pgid;
}

static int __waitpid_internal(pid_t pid, int *status, int options,
                              siginfo_t *infop, struct rusage *rusage) {
  HANDLE hProcess = INVALID_HANDLE_VALUE;
  HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

  if (hSnapshot == INVALID_HANDLE_VALUE) {
    errno = ECHILD;
    return -1;
  }

  PROCESSENTRY32 pe;
  pe.dwSize = sizeof(PROCESSENTRY32);
  int found = 0;
  DWORD target_pid = 0;
  DWORD current_pid = GetCurrentProcessId();

  int (*match_func)(PROCESSENTRY32 *, DWORD) = NULL;
  DWORD match_param = 0;

  if (pid == -1) {
    match_func = __match_any_child;
    match_param = current_pid;
  } else if (pid > 0) {
    match_func = __match_pid;
    match_param = (DWORD)pid;
  } else if (pid == 0) {
    match_func = __match_current_group;
    match_param = current_pid;
  } else if (pid < -1) {
    match_func = __match_target_group;
    match_param = (DWORD)(-pid);
  }

  if (Process32First(hSnapshot, &pe)) {
    do {
      if (match_func(&pe, match_param)) {
        hProcess = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION, FALSE,
                               pe.th32ProcessID);
        if (hProcess != NULL && hProcess != INVALID_HANDLE_VALUE) {
          target_pid = pe.th32ProcessID;
          found = 1;
          break;
        }
      }
    } while (Process32Next(hSnapshot, &pe));
  }

  CloseHandle(hSnapshot);

  if (!found) {
    if (hProcess != NULL && hProcess != INVALID_HANDLE_VALUE) {
      CloseHandle(hProcess);
    }
    errno = ECHILD;
    return -1;
  }

  DWORD wait_result =
      WaitForSingleObject(hProcess, (options & WNOHANG) ? 0 : INFINITE);

  int result_status = 0;
  if (wait_result == WAIT_OBJECT_0) {
    DWORD exit_code;
    if (GetExitCodeProcess(hProcess, &exit_code)) {
      result_status = (exit_code & 0xFF) << 8;
    }
  } else if (wait_result == WAIT_TIMEOUT && (options & WNOHANG)) {
    CloseHandle(hProcess);
    return 0;
  } else {
    CloseHandle(hProcess);
    errno = ECHILD;
    return -1;
  }

  if (status)
    *status = result_status;

  if (infop) {
    memset(infop, 0, sizeof(siginfo_t));
    infop->si_pid = (pid_t)target_pid;
    infop->si_status = result_status;
  }

  if (rusage) {
    memset(rusage, 0, sizeof(struct rusage));
    FILETIME create, exit, kernel, user;
    if (GetProcessTimes(hProcess, &create, &exit, &kernel, &user)) {
      ULONGLONG user_time =
          ((ULONGLONG)user.dwHighDateTime << 32) | user.dwLowDateTime;
      ULONGLONG kernel_time =
          ((ULONGLONG)kernel.dwHighDateTime << 32) | kernel.dwLowDateTime;

      rusage->ru_utime.tv_sec = (long)(user_time / 10000000);
      rusage->ru_utime.tv_usec = (long)((user_time % 10000000) / 10);

      rusage->ru_stime.tv_sec = (long)(kernel_time / 10000000);
      rusage->ru_stime.tv_usec = (long)((kernel_time % 10000000) / 10);
    }
  }

  CloseHandle(hProcess);
  return (int)target_pid;
}

static int waitpid(pid_t pid, int *status, int options) {
  return __waitpid_internal(pid, status, options, NULL, NULL);
}

static int wait(int *status) { return waitpid(-1, status, 0); }

#ifdef _XOPEN_SOURCE

typedef enum { P_ALL, P_PID, P_PGID } idtype_t;

static int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options) {
  pid_t pid_val = -1;
  switch (idtype) {
  case P_PID:
    pid_val = (pid_t)id;
    break;
  case P_PGID:
    pid_val = -(pid_t)id;
    break;
  case P_ALL:
    pid_val = -1;
    break;
  default:
    errno = EINVAL;
    return -1;
  }
  return __waitpid_internal(pid_val, NULL, options, infop, NULL);
}

static pid_t wait3(int *status, int options, struct rusage *rusage) {
  return waitpid(-1, status, options);
}

static pid_t wait4(pid_t pid, int *status, int options, struct rusage *rusage) {
  return __waitpid_internal(pid, status, options, NULL, rusage);
}

#endif

#ifdef __cplusplus
}
#endif

#endif // _WIN32
#endif // __SYS_WAIT_H__
