cmd_scripts/kconfig/mconf.o := gcc -Wp,-MD,scripts/kconfig/.mconf.o.d  -Wall -Wstrict-prototypes -O2 -fomit-frame-pointer       -c -o scripts/kconfig/mconf.o scripts/kconfig/mconf.c

deps_scripts/kconfig/mconf.o := \
  scripts/kconfig/mconf.c \
  /usr/include/stdc-predef.h \
  /usr/include/sys/ioctl.h \
  /usr/include/features.h \
  /usr/include/sys/cdefs.h \
  /usr/include/bits/wordsize.h \
  /usr/include/bits/long-double.h \
  /usr/include/gnu/stubs.h \
  /usr/include/gnu/stubs-64.h \
  /usr/include/bits/ioctls.h \
  /usr/include/asm/ioctls.h \
  /usr/include/asm-generic/ioctls.h \
  /usr/include/linux/ioctl.h \
  /usr/include/asm/ioctl.h \
  /usr/include/asm-generic/ioctl.h \
  /usr/include/bits/ioctl-types.h \
  /usr/include/sys/ttydefaults.h \
  /usr/include/sys/wait.h \
  /usr/include/bits/types.h \
  /usr/include/bits/typesizes.h \
  /usr/include/signal.h \
  /usr/include/bits/signum.h \
  /usr/include/bits/signum-generic.h \
  /usr/include/bits/types/sig_atomic_t.h \
  /usr/include/bits/types/sigset_t.h \
  /usr/include/bits/types/__sigset_t.h \
  /usr/include/bits/types/struct_timespec.h \
  /usr/include/bits/types/siginfo_t.h \
  /usr/include/bits/types/__sigval_t.h \
  /usr/include/bits/siginfo-arch.h \
  /usr/include/bits/siginfo-consts.h \
  /usr/include/bits/types/sigevent_t.h \
  /usr/include/bits/sigevent-consts.h \
  /usr/include/bits/sigaction.h \
  /usr/lib/gcc/x86_64-pc-linux-gnu/8.2.1/include/stddef.h \
  /usr/include/bits/types/stack_t.h \
  /usr/include/sys/ucontext.h \
  /usr/include/bits/sigstack.h \
  /usr/include/bits/ss_flags.h \
  /usr/include/bits/pthreadtypes.h \
  /usr/include/bits/thread-shared-types.h \
  /usr/include/bits/pthreadtypes-arch.h \
  /usr/include/bits/sigthread.h \
  /usr/include/bits/waitflags.h \
  /usr/include/bits/waitstatus.h \
  /usr/include/ctype.h \
  /usr/include/endian.h \
  /usr/include/bits/endian.h \
  /usr/include/bits/types/locale_t.h \
  /usr/include/bits/types/__locale_t.h \
  /usr/include/errno.h \
  /usr/include/bits/errno.h \
  /usr/include/linux/errno.h \
  /usr/include/asm/errno.h \
  /usr/include/asm-generic/errno.h \
  /usr/include/asm-generic/errno-base.h \
  /usr/include/fcntl.h \
  /usr/include/bits/fcntl.h \
  /usr/include/bits/fcntl-linux.h \
  /usr/include/bits/stat.h \
  /usr/lib/gcc/x86_64-pc-linux-gnu/8.2.1/include-fixed/limits.h \
  /usr/lib/gcc/x86_64-pc-linux-gnu/8.2.1/include-fixed/syslimits.h \
  /usr/include/limits.h \
  /usr/include/bits/libc-header-start.h \
  /usr/include/bits/posix1_lim.h \
  /usr/include/bits/local_lim.h \
  /usr/include/linux/limits.h \
  /usr/include/bits/posix2_lim.h \
  /usr/include/bits/xopen_lim.h \
  /usr/include/bits/uio_lim.h \
  /usr/lib/gcc/x86_64-pc-linux-gnu/8.2.1/include/stdarg.h \
  /usr/include/stdlib.h \
  /usr/include/bits/floatn.h \
  /usr/include/bits/floatn-common.h \
  /usr/include/sys/types.h \
  /usr/include/bits/types/clock_t.h \
  /usr/include/bits/types/clockid_t.h \
  /usr/include/bits/types/time_t.h \
  /usr/include/bits/types/timer_t.h \
  /usr/include/bits/stdint-intn.h \
  /usr/include/bits/stdlib-bsearch.h \
  /usr/include/bits/stdlib-float.h \
  /usr/include/string.h \
  /usr/include/strings.h \
  /usr/include/termios.h \
  /usr/include/bits/termios.h \
  /usr/include/unistd.h \
  /usr/include/bits/posix_opt.h \
  /usr/include/bits/environments.h \
  /usr/include/bits/confname.h \
  /usr/include/bits/getopt_posix.h \
  /usr/include/bits/getopt_core.h \
  /usr/include/locale.h \
  /usr/include/bits/locale.h \
  scripts/kconfig/lkc.h \
  scripts/kconfig/expr.h \
  /usr/include/stdio.h \
  /usr/include/bits/types/__fpos_t.h \
  /usr/include/bits/types/__mbstate_t.h \
  /usr/include/bits/types/__fpos64_t.h \
  /usr/include/bits/types/__FILE.h \
  /usr/include/bits/types/FILE.h \
  /usr/include/bits/types/struct_FILE.h \
  /usr/include/bits/stdio_lim.h \
  /usr/include/bits/sys_errlist.h \
  /usr/include/bits/stdio.h \
  /usr/lib/gcc/x86_64-pc-linux-gnu/8.2.1/include/stdbool.h \
  /usr/include/libintl.h \
  scripts/kconfig/lkc_proto.h \

scripts/kconfig/mconf.o: $(deps_scripts/kconfig/mconf.o)

$(deps_scripts/kconfig/mconf.o):
