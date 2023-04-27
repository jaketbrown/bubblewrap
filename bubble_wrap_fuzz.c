#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "bwrap.h"
#include "config.h"

typedef struct BwrapOptions {
    int unshare_user_ns;
    int unshare_pid_ns;
    int unshare_ipc_ns;
    int unshare_net_ns;
    int unshare_uts_ns;
    int unshare_cgroup_ns;
    int unshare_mount_ns;
    const char *uid_map;
    const char *gid_map;
    int use_capsicum;
    int use_seccomp;
    const char *chroot_dir;
    const char *chdir_dir;
    const char **setenv_list;
    const char *exec_file;
    const char **argv;
    int stdin_fd;
    int stdout_fd;
    int stderr_fd;
    int log_fd;
} BwrapOptions;


int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  // Declare a BwrapOptions struct
  BwrapOptions opts;

  // Initialize the struct with default values
  memset(&opts, 0, sizeof(opts));
  opts.unshare_user_ns = 1;
  opts.unshare_pid_ns = 1;
  opts.unshare_ipc_ns = 1;
  opts.unshare_net_ns = 1;
  opts.unshare_uts_ns = 1;
  opts.unshare_cgroup_ns = 1;
  opts.unshare_mount_ns = 1;
  opts.uid_map = "0 1000 1\n";
  opts.gid_map = "0 1000 1\n";
  opts.use_capsicum = 0;
  opts.use_seccomp = 0;
  opts.chroot_dir = "/";
  opts.chdir_dir = "/";
  opts.setenv_list = NULL;
  opts.exec_file = NULL;
  opts.argv = NULL;
  opts.stdin_fd = STDIN_FILENO;
  opts.stdout_fd = STDOUT_FILENO;
  opts.stderr_fd = STDERR_FILENO;
  opts.log_fd = STDERR_FILENO;

  // Copy the input data to a buffer
  uint8_t *buf = malloc(Size + 1);
  if (!buf) {
    return 0;
  }
  memcpy(buf, Data, Size);
  buf[Size] = '\0';

  // Set the exec_file field in the options struct to point to the buffer
  opts.exec_file = (char *)buf;

  // Call the bwrap_exec function with the options struct
  bwrap_exec(&opts);

  // Free the buffer
  free(buf);

  return 0;
}

