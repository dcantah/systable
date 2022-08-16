## systable

This is a utility to inspect syscall tables for Linux v5.0 or higher. Useful for writing seccomp filters mainly, or seeing if a syscall is available on a specific version. It fulfills my needs, so maybe it's helpful for someone else.

### Building/Installing
```
// Build
go build ./cmd/systable

// Install
go install github.com/dcantah/systable/cmd/systable@latest
```

### Architecture support
arm, x86 and x64.

### Config
To ease the need to continuously provide --arch and --version if the defaults don't fit your needs, you can edit the config file located at $HOME/.systable/config.json to whatever you prefer. The values in this file are the defaults for any invocation not containing --arch, --version or --format. Any commandline flags provided will override these settings.

### Examples
```shell
// Basic usage. Get the syscall list with all defaults (v6.0, x64, and table based output).
$ systable | head -n 5
Num(rax)   Name                      Arg0(rdi)                                  Arg1(rsi)                              Arg2(rdx)                                       Arg3(r10)                                 Arg4(r8)                                      Arg5(r9)   
0          read                      unsigned int fd                            char *buf                              size_t count                                                                                                                            
1          write                     unsigned int fd                            const char *buf                        size_t count                                                                                                                            
2          open                      const char *filename                       int flags                              umode_t mode                                                                                                                            
3          close                     unsigned int fd

// Specify different kernel tags.
$ systable -v "v5.0" | tail -n 5
330        pkey_alloc               unsigned long flags                 unsigned long init_val                                                                                                                                                        
331        pkey_free                int pkey                                                                                                                                                                                                          
332        statx                    int dfd                             const char *path                      unsigned flags                                  unsigned mask                             struct statx *buffer                          
333        io_pgetevents            aio_context_t ctx_id                long min_nr                           long nr                                         struct io_event *events                   struct __kernel_timespec *timeout             const struct __aio_sigset *sig
334        rseq                     struct rseq *rseq                   uint32_t rseq_len                     int flags                                       uint32_t sig                                                                            

$ systable -v "v6.0" | tail -n 5
446        landlock_restrict_self    int ruleset_fd                             __u32 flags                                                                                                                                                                    
447        memfd_secret              unsigned int flags                                                                                                                                                                                                        
448        process_mrelease          int pidfd                                  unsigned int flags                                                                                                                                                             
449        futex_waitv               struct futex_waitv *waiters                unsigned int nr_futexes                unsigned int flags                              struct __kernel_timespec *timeout         clockid_t clockid                             
450        set_mempolicy_home_node   unsigned long start                        unsigned long len                      unsigned long home_node                         unsigned long flags

// Constrain the output to only a specific set of syscalls.
$ systable read
Num(rax)   Name               Arg0(rdi)          Arg1(rsi)                  Arg2(rdx)               Arg3(r10)                  Arg4(r8)                Arg5(r9)   
0          read               unsigned int fd    char *buf                  size_t count                                                               
17         pread64            unsigned int fd    char *buf                  size_t count            loff_t pos                                         
19         readv              unsigned long fd   const struct iovec *vec    unsigned long vlen                                                         
89         readlink           const char *path   char *buf                  int bufsiz                                                                 
187        readahead          int fd             loff_t offset              size_t count                                                               
267        readlinkat         int dfd            const char *path           char *buf               int bufsiz                                         
295        preadv             unsigned long fd   const struct iovec *vec    unsigned long vlen      unsigned long pos_l        unsigned long pos_h     
310        process_vm_readv   pid_t pid          const struct iovec *lvec   unsigned long liovcnt   const struct iovec *rvec   unsigned long riovcnt   unsigned long flags
327        preadv2            unsigned long fd   const struct iovec *vec    unsigned long vlen      unsigned long pos_l        unsigned long pos_h     rwf_t flags

// Constrain the output to a specific syscall.
$ systable --exact read
Num(rax)   Name   Arg0(rdi)         Arg1(rsi)   Arg2(rdx)      Arg3(r10)   Arg4(r8)   Arg5(r9)   
0          read   unsigned int fd   char *buf   size_t count

$ systable --exact read_not_exist
2024/09/15 04:43:51 no syscalls found

// Get the syscalls in json format (includes manpage URL and easier to parse calling convention data).
$ systable --format json pread | jq .
{
  "calling_convention": {
    "number": "rax",
    "return": "rax",
    "arg0": "rdi",
    "arg1": "rsi",
    "arg2": "rdx",
    "arg3": "r10",
    "arg4": "r8",
    "arg5": "r9"
  },
  "syscalls": [
    {
      "number": 17,
      "name": "pread64",
      "man_page": "https://man7.org/linux/man-pages/man2/pread64.2.html",
      "arguments": [
        "unsigned int fd",
        "char *buf",
        "size_t count",
        "loff_t pos"
      ]
    },
    {
      "number": 295,
      "name": "preadv",
      "man_page": "https://man7.org/linux/man-pages/man2/preadv.2.html",
      "arguments": [
        "unsigned long fd",
        "const struct iovec *vec",
        "unsigned long vlen",
        "unsigned long pos_l",
        "unsigned long pos_h"
      ]
    },
    {
      "number": 327,
      "name": "preadv2",
      "man_page": "https://man7.org/linux/man-pages/man2/preadv2.2.html",
      "arguments": [
        "unsigned long fd",
        "const struct iovec *vec",
        "unsigned long vlen",
        "unsigned long pos_l",
        "unsigned long pos_h",
        "rwf_t flags"
      ]
    }
  ]
}

```

### Notes
This program parses output from the various .tbl files in Linux. These are pulled via http from https://raw.githubusercontent.com/torvalds/linux/, so the program IS prone to stop working if these files are ever moved to a new spot in a coming kernel version. Once a specific kernel version + architecture pair is pulled and parsed, this program saves the original .tbl file in a cache on disk located at $HOME/.systable/cache/. These are safe to remove, it's solely to speed up future uses of the program that specify the same version+arch pair.
