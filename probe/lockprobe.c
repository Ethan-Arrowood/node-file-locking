// lockprobe: checks the OS file-locking behavior that a Node.js fs.lock()
// built on flock(2) (Unix) and LockFileEx() (Windows) depends on.
//
// Files are opened the way libuv opens them, and locks are taken the way the
// Node.js prototype takes them, so the results apply to it directly.
//
// Each check prints one line: PASS or FAIL, a name, and details. "INFO" lines
// record behavior that varies by platform and that no check depends on.
// Exit status is the number of failed checks.
//
// Usage: lockprobe [dir]     run all checks, using files in dir (default ".")
//        lockprobe hold FILE (internal) lock FILE, print "held", wait forever

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#endif

static int failures = 0;
static char path[4096];
static const char* self;

static void report(int ok, const char* name, const char* fmt, ...) {
  va_list ap;
  printf("%s  %-50s ", ok ? "PASS" : "FAIL", name);
  va_start(ap, fmt);
  vprintf(fmt, ap);
  va_end(ap);
  printf("\n");
  fflush(stdout);
  if (!ok) failures++;
}

static void info(const char* name, const char* fmt, ...) {
  va_list ap;
  printf("INFO  %-50s ", name);
  va_start(ap, fmt);
  vprintf(fmt, ap);
  va_end(ap);
  printf("\n");
  fflush(stdout);
}

#ifdef _WIN32

// ---------------------------------------------------------------- Windows --

typedef HANDLE file_t;

// The Node.js prototype locks this one byte, far past the end of any file.
#define LOCK_OFFSET_LOW 0xFFFFFFFEu
#define LOCK_OFFSET_HIGH 0x7FFFFFFFu

// Like libuv's fs__open() for 'r+' (or 'a' when append is set).
static file_t open_file(int append) {
  DWORD access = FILE_GENERIC_READ | FILE_GENERIC_WRITE;
  if (append) {
    access &= ~FILE_WRITE_DATA;
    access |= FILE_APPEND_DATA;
  }
  HANDLE h = CreateFileA(path,
                         access,
                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         NULL,
                         OPEN_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
                         NULL);
  if (h == INVALID_HANDLE_VALUE) {
    fprintf(stderr, "CreateFile failed: %lu\n", GetLastError());
    exit(100);
  }
  return h;
}

static void close_file(file_t h) { CloseHandle(h); }

static OVERLAPPED range(DWORD low, DWORD high) {
  OVERLAPPED ov;
  memset(&ov, 0, sizeof(ov));
  ov.Offset = low;
  ov.OffsetHigh = high;
  return ov;
}

// Returns 0 on success, or GetLastError().
static DWORD lock_range(file_t h, int exclusive, int wait, DWORD off_low,
                        DWORD off_high, DWORD len_low, DWORD len_high) {
  OVERLAPPED ov = range(off_low, off_high);
  DWORD flags = (exclusive ? LOCKFILE_EXCLUSIVE_LOCK : 0) |
                (wait ? 0 : LOCKFILE_FAIL_IMMEDIATELY);
  return LockFileEx(h, flags, 0, len_low, len_high, &ov) ? 0 : GetLastError();
}

static DWORD try_lock(file_t h, int exclusive) {
  return lock_range(h, exclusive, 0, LOCK_OFFSET_LOW, LOCK_OFFSET_HIGH, 1, 0);
}

static DWORD unlock(file_t h) {
  OVERLAPPED ov = range(LOCK_OFFSET_LOW, LOCK_OFFSET_HIGH);
  return UnlockFileEx(h, 0, 1, 0, &ov) ? 0 : GetLastError();
}

static int hold(void) {
  file_t h = open_file(0);
  DWORD err = lock_range(h, 1, 1, LOCK_OFFSET_LOW, LOCK_OFFSET_HIGH, 1, 0);
  if (err != 0) return 1;
  printf("held\n");
  fflush(stdout);
  Sleep(INFINITE);
  return 0;
}

static PROCESS_INFORMATION start_holder(void) {
  char cmd[8192];
  snprintf(cmd, sizeof(cmd), "\"%s\" hold \"%s\"", self, path);
  SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
  HANDLE out_read, out_write;
  CreatePipe(&out_read, &out_write, &sa, 0);
  SetHandleInformation(out_read, HANDLE_FLAG_INHERIT, 0);
  STARTUPINFOA si;
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdOutput = out_write;
  si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
  PROCESS_INFORMATION pi;
  if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
    fprintf(stderr, "CreateProcess failed: %lu\n", GetLastError());
    exit(100);
  }
  CloseHandle(out_write);
  char buf[16] = {0};
  DWORD n = 0;
  ReadFile(out_read, buf, sizeof(buf) - 1, &n, NULL);
  CloseHandle(out_read);
  if (strncmp(buf, "held", 4) != 0) {
    fprintf(stderr, "holder did not lock\n");
    exit(100);
  }
  return pi;
}

typedef struct {
  file_t h;
  DWORD result;
} wait_arg;

static DWORD WINAPI wait_thread(LPVOID p) {
  wait_arg* arg = (wait_arg*)p;
  arg->result = lock_range(arg->h, 1, 1, LOCK_OFFSET_LOW, LOCK_OFFSET_HIGH, 1, 0);
  return 0;
}

static void run_platform_checks(void) {
  DWORD err;

  {
    file_t a = open_file(0), b = open_file(0);
    err = try_lock(a, 1);
    report(err == 0, "exclusive lock", "LockFileEx -> %lu", err);
    err = try_lock(b, 1);
    report(err != 0, "second handle in same process conflicts",
           "LockFileEx -> %lu", err);
    report(err == ERROR_LOCK_VIOLATION, "contention error is LOCK_VIOLATION",
           "got %lu, ERROR_LOCK_VIOLATION is %lu", err,
           (DWORD)ERROR_LOCK_VIOLATION);

    // The lock is past the end of the file, so the data stays accessible.
    DWORD n = 0;
    BOOL wrote = WriteFile(b, "data", 4, &n, NULL);
    report(wrote && n == 4, "other handle can write while locked (advisory)",
           "WriteFile -> %d, %lu bytes, error %lu", wrote, n,
           wrote ? 0 : GetLastError());
    char buf[4];
    OVERLAPPED at0 = range(0, 0);
    BOOL read = ReadFile(b, buf, 4, &n, &at0);
    report(read && n == 4, "other handle can read while locked (advisory)",
           "ReadFile -> %d, %lu bytes, error %lu", read, n,
           read ? 0 : GetLastError());

    // Rust's File::lock() and Deno lock the whole range, which covers our
    // byte, so they conflict with us.
    err = lock_range(b, 1, 0, 0, 0, MAXDWORD, MAXDWORD);
    report(err != 0, "whole-range lock (Rust, Deno) conflicts",
           "LockFileEx(0, ~0) -> %lu", err);
    if (err == 0) {
      OVERLAPPED ov = range(0, 0);
      UnlockFileEx(b, 0, MAXDWORD, MAXDWORD, &ov);
    }

    // Python's filelock locks byte 0, which doesn't overlap our byte.
    err = lock_range(b, 1, 0, 0, 0, 1, 0);
    info("byte-0 lock (Python filelock) vs ours",
         "LockFileEx(0, 1) -> %lu (%s)", err,
         err == 0 ? "no conflict" : "conflicts");
    if (err == 0) {
      OVERLAPPED ov = range(0, 0);
      UnlockFileEx(b, 0, 1, 0, &ov);
    }

    err = unlock(a);
    report(err == 0, "unlock", "UnlockFileEx -> %lu", err);
    err = unlock(a);
    report(err == ERROR_NOT_LOCKED, "unlocking twice reports NOT_LOCKED",
           "UnlockFileEx -> %lu", err);
    err = try_lock(b, 1);
    report(err == 0, "lock is free after unlock", "LockFileEx -> %lu", err);
    unlock(b);
    close_file(a);
    close_file(b);
  }

  {
    // Shared locks.
    file_t a = open_file(0), b = open_file(0), c = open_file(0);
    DWORD ea = try_lock(a, 0), eb = try_lock(b, 0), ec = try_lock(c, 1);
    report(ea == 0 && eb == 0, "two shared locks coexist",
           "LockFileEx -> %lu, %lu", ea, eb);
    report(ec != 0, "exclusive conflicts with shared", "LockFileEx -> %lu", ec);
    // The prototype converts by unlocking first, then locking again.
    unlock(a);
    err = try_lock(a, 1);
    report(err != 0, "conversion to exclusive blocked by other shared",
           "LockFileEx -> %lu", err);
    unlock(b);
    err = try_lock(a, 1);
    report(err == 0, "conversion succeeds once others release",
           "LockFileEx -> %lu", err);
    close_file(a);
    close_file(b);
    close_file(c);
  }

  {
    // Locking twice through one handle without unlocking: does it stack,
    // fail, or convert? The prototype always unlocks first, so this is only
    // informative.
    file_t a = open_file(0);
    DWORD first = try_lock(a, 0), second = try_lock(a, 0);
    DWORD u1 = unlock(a), u2 = unlock(a), u3 = unlock(a);
    info("same handle locked shared twice",
         "lock -> %lu, %lu; unlock -> %lu, %lu, %lu", first, second, u1, u2,
         u3);
    close_file(a);
  }

  {
    // The prototype's waiting thread locks through a duplicate handle and
    // then closes it. The lock must stay with the original handle.
    file_t a = open_file(0), b = open_file(0), dup;
    HANDLE proc = GetCurrentProcess();
    DuplicateHandle(proc, a, proc, &dup, 0, FALSE, DUPLICATE_SAME_ACCESS);
    err = try_lock(dup, 1);
    report(err == 0, "lock through duplicate handle", "LockFileEx -> %lu", err);
    close_file(dup);
    err = try_lock(b, 1);
    report(err != 0, "lock survives closing the duplicate",
           "other handle LockFileEx -> %lu", err);
    err = unlock(a);
    report(err == 0, "original handle can release it", "UnlockFileEx -> %lu",
           err);
    err = try_lock(b, 1);
    report(err == 0, "lock is free afterwards", "LockFileEx -> %lu", err);
    close_file(a);
    close_file(b);
  }

  {
    // Closing the handle releases the lock.
    file_t a = open_file(0), b = open_file(0);
    try_lock(a, 1);
    close_file(a);
    err = try_lock(b, 1);
    report(err == 0, "closing the handle releases the lock",
           "LockFileEx -> %lu", err);
    close_file(b);
  }

  {
    // An unrelated open and close of the same file keeps the lock.
    file_t a = open_file(0), b = open_file(0);
    try_lock(a, 1);
    close_file(open_file(0));
    err = try_lock(b, 1);
    report(err != 0, "unrelated open+close keeps the lock",
           "LockFileEx -> %lu", err);
    close_file(a);
    close_file(b);
  }

  {
    // fs.open(path, 'a') gives append-only access.
    file_t a = open_file(1);
    err = try_lock(a, 1);
    info("lock on append-only handle ('a')", "LockFileEx -> %lu", err);
    unlock(a);
    close_file(a);
  }

  {
    // A blocking wait on a handle opened without FILE_FLAG_OVERLAPPED (as
    // libuv opens files) returns once the holder releases.
    file_t a = open_file(0), b = open_file(0);
    try_lock(a, 1);
    wait_arg arg = {b, 12345};
    HANDLE t = CreateThread(NULL, 0, wait_thread, &arg, 0, NULL);
    DWORD still = WaitForSingleObject(t, 200);
    report(still == WAIT_TIMEOUT, "blocking wait blocks while held",
           "WaitForSingleObject -> %lu", still);
    unlock(a);
    DWORD done = WaitForSingleObject(t, 5000);
    report(done == WAIT_OBJECT_0 && arg.result == 0,
           "blocking wait returns after release",
           "wait -> %lu, LockFileEx -> %lu", done, arg.result);
    CloseHandle(t);
    close_file(a);
    close_file(b);
  }

  {
    // Can another thread interrupt a blocked LockFileEx()? If so, a future
    // version can make aborts end the wait at once on Windows.
    file_t a = open_file(0), b = open_file(0);
    try_lock(a, 1);
    wait_arg arg = {b, 12345};
    HANDLE t = CreateThread(NULL, 0, wait_thread, &arg, 0, NULL);
    Sleep(200);
    BOOL cancelled = CancelSynchronousIo(t);
    DWORD cancel_err = cancelled ? 0 : GetLastError();
    DWORD done = WaitForSingleObject(t, 2000);
    info("CancelSynchronousIo on a blocked wait",
         "cancel -> %d (error %lu); thread %s; LockFileEx -> %lu "
         "(ERROR_OPERATION_ABORTED is %lu)",
         cancelled, cancel_err,
         done == WAIT_OBJECT_0 ? "returned" : "still blocked", arg.result,
         (DWORD)ERROR_OPERATION_ABORTED);
    unlock(a);
    WaitForSingleObject(t, 5000);
    CloseHandle(t);
    close_file(a);
    close_file(b);
  }

  {
    // The OS releases a killed process's lock.
    PROCESS_INFORMATION pi = start_holder();
    file_t b = open_file(0);
    err = try_lock(b, 1);
    report(err != 0, "another process's lock conflicts", "LockFileEx -> %lu",
           err);
    TerminateProcess(pi.hProcess, 1);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD start = GetTickCount();
    do {
      err = try_lock(b, 1);
      if (err == 0) break;
      Sleep(10);
    } while (GetTickCount() - start < 10000);
    report(err == 0, "killed process's lock is released",
           "after %lu ms", GetTickCount() - start);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    close_file(b);
  }
}

#else

// ------------------------------------------------------------------- Unix --

typedef int file_t;

// Like libuv's uv_fs_open() for 'r+'.
static file_t open_file(int append) {
  int fd = open(path, (append ? O_WRONLY | O_APPEND : O_RDWR) | O_CREAT |
                          O_CLOEXEC, 0644);
  if (fd == -1) {
    perror("open");
    exit(100);
  }
  return fd;
}

static void close_file(file_t fd) { close(fd); }

// Returns 0 on success, or errno.
static int try_lock(file_t fd, int exclusive) {
  return flock(fd, (exclusive ? LOCK_EX : LOCK_SH) | LOCK_NB) == 0 ? 0 : errno;
}

static int unlock(file_t fd) { return flock(fd, LOCK_UN) == 0 ? 0 : errno; }

static int posix_try_lock(file_t fd) {
  struct flock fl;
  memset(&fl, 0, sizeof(fl));
  fl.l_type = F_WRLCK;
  fl.l_whence = SEEK_SET;
  return fcntl(fd, F_SETLK, &fl) == 0 ? 0 : errno;
}

static int hold(int posix) {
  file_t fd = open_file(0);
  if (posix) {
    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    if (fcntl(fd, F_SETLKW, &fl) != 0) return 1;
  } else if (flock(fd, LOCK_EX) != 0) {
    return 1;
  }
  printf("held\n");
  fflush(stdout);
  for (;;) pause();
}

// Runs fn in a child process, so the check sees this process from outside.
// Returns the child's result.
static int in_child(int (*fn)(void)) {
  pid_t pid = fork();
  if (pid == 0) _exit(fn());
  int status;
  waitpid(pid, &status, 0);
  return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int child_try_flock(void) {
  file_t fd = open_file(0);
  return try_lock(fd, 1) == 0 ? 0 : 1;
}

static int child_try_posix(void) {
  file_t fd = open_file(0);
  return posix_try_lock(fd) == 0 ? 0 : 1;
}

static pid_t start_holder(int posix) {
  int fds[2];
  if (pipe(fds) != 0) exit(100);
  pid_t pid = fork();
  if (pid == 0) {
    dup2(fds[1], 1);
    close(fds[0]);
    execl(self, self, posix ? "hold-posix" : "hold", path, (char*)NULL);
    _exit(127);
  }
  close(fds[1]);
  char buf[16] = {0};
  if (read(fds[0], buf, sizeof(buf) - 1) < 4 || strncmp(buf, "held", 4) != 0) {
    fprintf(stderr, "holder did not lock\n");
    exit(100);
  }
  close(fds[0]);
  return pid;
}

static void run_platform_checks(void) {
  int err;

  {
    file_t a = open_file(0), b = open_file(0);
    err = try_lock(a, 1);
    report(err == 0, "exclusive lock", "flock -> %d", err);
    err = try_lock(b, 1);
    report(err == EWOULDBLOCK, "second open in same process conflicts",
           "flock -> %s", strerror(err));

    ssize_t n = pwrite(b, "data", 4, 0);
    report(n == 4, "other open can write while locked (advisory)",
           "pwrite -> %zd", n);

    close_file(open_file(0));
    err = try_lock(b, 1);
    report(err == EWOULDBLOCK, "unrelated open+close keeps the lock",
           "flock -> %s", strerror(err));

    err = unlock(a);
    report(err == 0, "unlock", "flock(LOCK_UN) -> %d", err);
    err = unlock(a);
    report(err == 0, "unlocking twice succeeds", "flock(LOCK_UN) -> %d", err);
    err = try_lock(b, 1);
    report(err == 0, "lock is free after unlock", "flock -> %d", err);
    close_file(a);
    close_file(b);
  }

  {
    file_t a = open_file(0), b = open_file(0), c = open_file(0);
    int ea = try_lock(a, 0), eb = try_lock(b, 0), ec = try_lock(c, 1);
    report(ea == 0 && eb == 0, "two shared locks coexist", "flock -> %d, %d",
           ea, eb);
    report(ec == EWOULDBLOCK, "exclusive conflicts with shared", "flock -> %s",
           strerror(ec));
    err = try_lock(a, 1);
    report(err == EWOULDBLOCK, "conversion to exclusive blocked by other shared",
           "flock -> %s", strerror(err));
    unlock(b);
    err = try_lock(a, 1);
    report(err == 0, "conversion succeeds once others release", "flock -> %d",
           err);
    close_file(a);
    close_file(b);
    close_file(c);
  }

  {
    // The prototype's waiting thread locks through a duplicate fd and then
    // closes it. The lock must stay with the open file.
    file_t a = open_file(0), b = open_file(0);
    file_t dup = fcntl(a, F_DUPFD_CLOEXEC, 0);
    err = try_lock(dup, 1);
    report(err == 0, "lock through duplicate fd", "flock -> %d", err);
    close_file(dup);
    err = try_lock(b, 1);
    report(err == EWOULDBLOCK, "lock survives closing the duplicate",
           "flock -> %s", strerror(err));
    err = unlock(a);
    report(err == 0, "original fd can release it", "flock(LOCK_UN) -> %d", err);
    close_file(a);
    close_file(b);
  }

  {
    file_t a = open_file(0), b = open_file(0);
    try_lock(a, 1);
    close_file(a);
    err = try_lock(b, 1);
    report(err == 0, "closing the fd releases the lock", "flock -> %d", err);
    close_file(b);
  }

  {
    file_t a = open_file(1);
    err = try_lock(a, 1);
    info("lock on append-only fd ('a')", "flock -> %d", err);
    close_file(a);
  }

  {
    // The fcntl() problem from nodejs/node#122: closing any fd for the file
    // drops the process's lock.
    file_t a = open_file(0), b = open_file(0);
    posix_try_lock(a);
    int second = posix_try_lock(b);
    report(second == 0, "fcntl: second open in same process also 'locks'",
           "fcntl(F_SETLK) -> %d (contrast with flock)", second);
    int before = in_child(child_try_posix);
    close_file(b);
    int after = in_child(child_try_posix);
    report(before != 0 && after == 0,
           "fcntl: closing another fd drops the lock",
           "other process could lock: before close %s, after close %s",
           before == 0 ? "yes" : "no", after == 0 ? "yes" : "no");
    close_file(a);
  }

  {
    // flock() and fcntl() locks are separate on Linux and the same on BSDs
    // and macOS. zsh's `zsystem flock` and SQLite use fcntl().
    pid_t pid = start_holder(1);
    int flock_blocked = in_child(child_try_flock);
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
    info("flock vs another process's fcntl lock",
         "%s", flock_blocked ? "conflicts" : "no conflict");
  }

  {
    pid_t pid = start_holder(0);
    file_t b = open_file(0);
    err = try_lock(b, 1);
    report(err == EWOULDBLOCK, "another process's lock conflicts",
           "flock -> %s", strerror(err));
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
    err = try_lock(b, 1);
    report(err == 0, "killed process's lock is released", "flock -> %d", err);
    close_file(b);
  }
}

#endif

int main(int argc, char** argv) {
  self = argv[0];
#ifdef _WIN32
  static char module[MAX_PATH];
  if (GetModuleFileNameA(NULL, module, MAX_PATH) > 0) self = module;
#endif
  if (argc == 3 && strcmp(argv[1], "hold") == 0) {
    snprintf(path, sizeof(path), "%s", argv[2]);
#ifdef _WIN32
    return hold();
#else
    return hold(0);
#endif
  }
#ifndef _WIN32
  if (argc == 3 && strcmp(argv[1], "hold-posix") == 0) {
    snprintf(path, sizeof(path), "%s", argv[2]);
    return hold(1);
  }
#endif

  const char* dir = argc > 1 ? argv[1] : ".";
  snprintf(path, sizeof(path), "%s/lockprobe.lock", dir);
  remove(path);
  run_platform_checks();
  remove(path);
  printf("\n%d failed\n", failures);
  return failures;
}
