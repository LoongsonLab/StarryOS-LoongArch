extern crate alloc;
use alloc::boxed::Box;
// use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

#[cfg(not(target_arch = "loongarch64"))]
use axhal::arch::write_page_table_root;

use axhal::arch::flush_tlb;
use axhal::KERNEL_PROCESS_ID;
use axlog::info;
use axlog::warn;
use axprocess::link::{create_link, FilePath};
use axprocess::{wait_pid, yield_now_task, PID2PC};

#[cfg(not(target_arch = "loongarch64"))]
use axruntime::KERNEL_PAGE_TABLE;
use axtask::{TaskId, EXITED_TASKS};
use lazy_init::LazyInit;
use spinlock::SpinNoIrq;
use syscall_utils::{init_current_dir, new_file, FileFlags};

/// 初赛测例
#[allow(dead_code)]
const JUNIOR_TESTCASES: &[&str] = &[
    "brk",
    "chdir",
    "clone",
    "close",
    "dup",
    "dup2",
    "execve",
    "exit",
    "fork",
    "fstat",
    "getcwd",
    "getdents",
    "getpid",
    "getppid",
    "gettimeofday",
    "mkdir_",
    "mmap",
    "mount",
    "munmap",
    "open",
    "openat",
    "pipe",
    "read",
    "sleep",
    "times",
    "umount",
    "uname",
    "unlink",
    "wait",
    "waitpid",
    "write",
    "yield",
];

/// libc静态测例
pub const LIBC_STATIC_TESTCASES: &[&str] = &[
        "./runtest.exe -w entry-static.exe argv.exe",
    "./runtest.exe -w entry-static.exe basename.exe",
    "./runtest.exe -w entry-static.exe clocale_mbfuncs.exe",
    "./runtest.exe -w entry-static.exe clock_gettime.exe",
    "./runtest.exe -w entry-static.exe crypt.exe",
    "./runtest.exe -w entry-static.exe dirname.exe",
    "./runtest.exe -w entry-static.exe env.exe",
    "./runtest.exe -w entry-static.exe fdopen.exe",
    "./runtest.exe -w entry-static.exe fnmatch.exe",
    "./runtest.exe -w entry-static.exe fscanf.exe",
    "./runtest.exe -w entry-static.exe fwscanf.exe",
    "./runtest.exe -w entry-static.exe iconv_open.exe",
    "./runtest.exe -w entry-static.exe inet_pton.exe",
    "./runtest.exe -w entry-static.exe mbc.exe",
    "./runtest.exe -w entry-static.exe memstream.exe",
    "./runtest.exe -w entry-static.exe pthread_cancel_points.exe",
    "./runtest.exe -w entry-static.exe pthread_cancel.exe",
    "./runtest.exe -w entry-static.exe pthread_cond.exe",
    "./runtest.exe -w entry-static.exe pthread_tsd.exe",
    "./runtest.exe -w entry-static.exe qsort.exe",
    "./runtest.exe -w entry-static.exe random.exe",
    "./runtest.exe -w entry-static.exe search_hsearch.exe",
    "./runtest.exe -w entry-static.exe search_insque.exe",
    "./runtest.exe -w entry-static.exe search_lsearch.exe",
    "./runtest.exe -w entry-static.exe search_tsearch.exe",
    "./runtest.exe -w entry-static.exe setjmp.exe",
    "./runtest.exe -w entry-static.exe snprintf.exe",
    "./runtest.exe -w entry-static.exe socket.exe",
    "./runtest.exe -w entry-static.exe sscanf.exe",
    "./runtest.exe -w entry-static.exe sscanf_long.exe",
    "./runtest.exe -w entry-static.exe stat.exe",
    "./runtest.exe -w entry-static.exe strftime.exe",
    "./runtest.exe -w entry-static.exe string.exe",
    "./runtest.exe -w entry-static.exe string_memcpy.exe",
    "./runtest.exe -w entry-static.exe string_memmem.exe",
    "./runtest.exe -w entry-static.exe string_memset.exe",
    "./runtest.exe -w entry-static.exe string_strchr.exe",
    "./runtest.exe -w entry-static.exe string_strcspn.exe",
    "./runtest.exe -w entry-static.exe string_strstr.exe",
    "./runtest.exe -w entry-static.exe strptime.exe",
    "./runtest.exe -w entry-static.exe strtod.exe",
    "./runtest.exe -w entry-static.exe strtod_simple.exe",
    "./runtest.exe -w entry-static.exe strtof.exe",
    "./runtest.exe -w entry-static.exe strtol.exe",
    "./runtest.exe -w entry-static.exe strtold.exe",
    "./runtest.exe -w entry-static.exe swprintf.exe",
    "./runtest.exe -w entry-static.exe tgmath.exe",
    "./runtest.exe -w entry-static.exe time.exe",
    "./runtest.exe -w entry-static.exe tls_align.exe",
    "./runtest.exe -w entry-static.exe udiv.exe",
    "./runtest.exe -w entry-static.exe ungetc.exe",
    "./runtest.exe -w entry-static.exe utime.exe",
    "./runtest.exe -w entry-static.exe wcsstr.exe",
    "./runtest.exe -w entry-static.exe wcstol.exe",
    "./runtest.exe -w entry-static.exe pleval.exe",
    "./runtest.exe -w entry-static.exe daemon_failure.exe",
    "./runtest.exe -w entry-static.exe dn_expand_empty.exe",
    "./runtest.exe -w entry-static.exe dn_expand_ptr_0.exe",
    "./runtest.exe -w entry-static.exe fflush_exit.exe",
    "./runtest.exe -w entry-static.exe fgets_eof.exe",
    "./runtest.exe -w entry-static.exe fgetwc_buffering.exe",
    "./runtest.exe -w entry-static.exe fpclassify_invalid_ld80.exe",
    "./runtest.exe -w entry-static.exe ftello_unflushed_append.exe",
    "./runtest.exe -w entry-static.exe getpwnam_r_crash.exe",
    "./runtest.exe -w entry-static.exe getpwnam_r_errno.exe",
    "./runtest.exe -w entry-static.exe iconv_roundtrips.exe",
    "./runtest.exe -w entry-static.exe inet_ntop_v4mapped.exe",
    "./runtest.exe -w entry-static.exe inet_pton_empty_last_field.exe",
    "./runtest.exe -w entry-static.exe iswspace_null.exe",
    "./runtest.exe -w entry-static.exe lrand48_signextend.exe",
    "./runtest.exe -w entry-static.exe lseek_large.exe",
    "./runtest.exe -w entry-static.exe malloc_0.exe",
    "./runtest.exe -w entry-static.exe mbsrtowcs_overflow.exe",
    "./runtest.exe -w entry-static.exe memmem_oob_read.exe",
    "./runtest.exe -w entry-static.exe memmem_oob.exe",
    "./runtest.exe -w entry-static.exe mkdtemp_failure.exe",
    "./runtest.exe -w entry-static.exe mkstemp_failure.exe",
    "./runtest.exe -w entry-static.exe printf_1e9_oob.exe",
    "./runtest.exe -w entry-static.exe printf_fmt_g_round.exe",
    "./runtest.exe -w entry-static.exe printf_fmt_g_zeros.exe",
    "./runtest.exe -w entry-static.exe printf_fmt_n.exe",
    "./runtest.exe -w entry-static.exe pthread_robust_detach.exe",
    "./runtest.exe -w entry-static.exe pthread_cancel_sem_wait.exe",
    "./runtest.exe -w entry-static.exe pthread_cond_smasher.exe",
    "./runtest.exe -w entry-static.exe pthread_condattr_setclock.exe",
    "./runtest.exe -w entry-static.exe pthread_exit_cancel.exe",
    "./runtest.exe -w entry-static.exe pthread_once_deadlock.exe",
    "./runtest.exe -w entry-static.exe pthread_rwlock_ebusy.exe",
    "./runtest.exe -w entry-static.exe putenv_doublefree.exe",
    "./runtest.exe -w entry-static.exe regex_backref_0.exe",
    "./runtest.exe -w entry-static.exe regex_bracket_icase.exe",
    "./runtest.exe -w entry-static.exe regex_ere_backref.exe",
    "./runtest.exe -w entry-static.exe regex_escaped_high_byte.exe",
    "./runtest.exe -w entry-static.exe regex_negated_range.exe",
    "./runtest.exe -w entry-static.exe regexec_nosub.exe",
    "./runtest.exe -w entry-static.exe rewind_clear_error.exe",
    "./runtest.exe -w entry-static.exe rlimit_open_files.exe",
    "./runtest.exe -w entry-static.exe scanf_bytes_consumed.exe",
    "./runtest.exe -w entry-static.exe scanf_match_literal_eof.exe",
    "./runtest.exe -w entry-static.exe scanf_nullbyte_char.exe",
    "./runtest.exe -w entry-static.exe setvbuf_unget.exe",
    "./runtest.exe -w entry-static.exe sigprocmask_internal.exe",
    "./runtest.exe -w entry-static.exe sscanf_eof.exe",
    "./runtest.exe -w entry-static.exe statvfs.exe",
    "./runtest.exe -w entry-static.exe strverscmp.exe",
    "./runtest.exe -w entry-static.exe syscall_sign_extend.exe",
    "./runtest.exe -w entry-static.exe uselocale_0.exe",
    "./runtest.exe -w entry-static.exe wcsncpy_read_overflow.exe",
    "./runtest.exe -w entry-static.exe wcsstr_false_negative.exe",
];

/// 来自 libc 的动态测例
#[allow(dead_code)]
pub const LIBC_DYNAMIC_TESTCASES: &[&str] = &[
    "./runtest.exe -w entry-dynamic.exe argv.exe",
    "./runtest.exe -w entry-dynamic.exe basename.exe",
    "./runtest.exe -w entry-dynamic.exe clocale_mbfuncs.exe",
    "./runtest.exe -w entry-dynamic.exe clock_gettime.exe",
    "./runtest.exe -w entry-dynamic.exe crypt.exe",
    "./runtest.exe -w entry-dynamic.exe dirname.exe",
    "./runtest.exe -w entry-dynamic.exe dlopen.exe", // 单独存在运行时bug，放在runtest里面就是正常的
    "./runtest.exe -w entry-dynamic.exe dlopen",
    "./runtest.exe -w entry-dynamic.exe env.exe",
    "./runtest.exe -w entry-dynamic.exe fdopen.exe",
    "./runtest.exe -w entry-dynamic.exe fnmatch.exe",
    // "./runtest.exe -w entry-dynamic.exe fscanf.exe",
    "./runtest.exe -w entry-dynamic.exe fwscanf.exe",
    "./runtest.exe -w entry-dynamic.exe iconv_open.exe",
    "./runtest.exe -w entry-dynamic.exe inet_pton.exe",
    "./runtest.exe -w entry-dynamic.exe mbc.exe",
    "./runtest.exe -w entry-dynamic.exe memstream.exe",
    "./runtest.exe -w entry-dynamic.exe pthread_cancel_points.exe",
    "./runtest.exe -w entry-dynamic.exe pthread_cancel.exe",
    "./runtest.exe -w entry-dynamic.exe pthread_cond.exe",
    "./runtest.exe -w entry-dynamic.exe pthread_tsd.exe",
    "./runtest.exe -w entry-dynamic.exe qsort.exe",
    "./runtest.exe -w entry-dynamic.exe random.exe",
    "./runtest.exe -w entry-dynamic.exe search_hsearch.exe",
    "./runtest.exe -w entry-dynamic.exe search_insque.exe",
    "./runtest.exe -w entry-dynamic.exe search_lsearch.exe",
    "./runtest.exe -w entry-dynamic.exe search_tsearch.exe",
    "./runtest.exe -w entry-dynamic.exe sem_init.exe",
    "./runtest.exe -w entry-dynamic.exe setjmp.exe",
    "./runtest.exe -w entry-dynamic.exe snprintf.exe",
    "./runtest.exe -w entry-dynamic.exe socket",
    "./runtest.exe -w entry-dynamic.exe sscanf.exe",
    "./runtest.exe -w entry-dynamic.exe sscanf_long.exe",
    "./runtest.exe -w entry-dynamic.exe stat.exe",
    "./runtest.exe -w entry-dynamic.exe strftime.exe",
    "./runtest.exe -w entry-dynamic.exe string.exe",
    "./runtest.exe -w entry-dynamic.exe string_memcpy.exe",
    "./runtest.exe -w entry-dynamic.exe string_memmem.exe",
    "./runtest.exe -w entry-dynamic.exe string_memset.exe",
    "./runtest.exe -w entry-dynamic.exe string_strchr.exe",
    "./runtest.exe -w entry-dynamic.exe string_strcspn.exe",
    "./runtest.exe -w entry-dynamic.exe string_strstr.exe",
    "./runtest.exe -w entry-dynamic.exe strptime.exe",
    "./runtest.exe -w entry-dynamic.exe strtod.exe",
    "./runtest.exe -w entry-dynamic.exe strtod_simple.exe",
    "./runtest.exe -w entry-dynamic.exe strtof.exe",
    "./runtest.exe -w entry-dynamic.exe strtol.exe",
    "./runtest.exe -w entry-dynamic.exe strtold.exe",
    "./runtest.exe -w entry-dynamic.exe swprintf.exe",
    "./runtest.exe -w entry-dynamic.exe tgmath.exe",
    "./runtest.exe -w entry-dynamic.exe time.exe",
    "./runtest.exe -w entry-dynamic.exe tls_init.exe",
    "./runtest.exe -w entry-dynamic.exe tls_local_exec.exe",
    "./runtest.exe -w entry-dynamic.exe udiv.exe",
    "./runtest.exe -w entry-dynamic.exe ungetc.exe",
    "./runtest.exe -w entry-dynamic.exe utime.exe",
    "./runtest.exe -w entry-dynamic.exe wcsstr.exe",
    "./runtest.exe -w entry-dynamic.exe wcstol.exe",
    "./runtest.exe -w entry-dynamic.exe daemon_failure.exe",
    "./runtest.exe -w entry-dynamic.exe dn_expand_empty.exe",
    "./runtest.exe -w entry-dynamic.exe dn_expand_ptr_0.exe",
    "./runtest.exe -w entry-dynamic.exe fflush_exit.exe",
    "./runtest.exe -w entry-dynamic.exe fgets_eof.exe",
    // "./runtest.exe -w entry-dynamic.exe fgetwc_buffering.exe",
    "./runtest.exe -w entry-dynamic.exe fpclassify_invalid_ld80.exe",
    "./runtest.exe -w entry-dynamic.exe ftello_unflushed_append.exe",
    "./runtest.exe -w entry-dynamic.exe getpwnam_r_crash.exe",
    "./runtest.exe -w entry-dynamic.exe getpwnam_r_errno.exe",
    "./runtest.exe -w entry-dynamic.exe iconv_roundtrips.exe",
    "./runtest.exe -w entry-dynamic.exe inet_ntop_v4mapped.exe",
    "./runtest.exe -w entry-dynamic.exe inet_pton_empty_last_field.exe",
    "./runtest.exe -w entry-dynamic.exe iswspace_null.exe",
    "./runtest.exe -w entry-dynamic.exe lrand48_signextend.exe",
    "./runtest.exe -w entry-dynamic.exe lseek_large.exe",
    "./runtest.exe -w entry-dynamic.exe malloc_0.exe",
    "./runtest.exe -w entry-dynamic.exe mbsrtowcs_overflow.exe",
    "./runtest.exe -w entry-dynamic.exe memmem_oob_read.exe",
    "./runtest.exe -w entry-dynamic.exe memmem_oob.exe",
    "./runtest.exe -w entry-dynamic.exe mkdtemp_failure.exe",
    "./runtest.exe -w entry-dynamic.exe mkstemp_failure.exe",
    "./runtest.exe -w entry-dynamic.exe printf_1e9_oob.exe",
    "./runtest.exe -w entry-dynamic.exe printf_fmt_g_round.exe",
    "./runtest.exe -w entry-dynamic.exe printf_fmt_g_zeros.exe",
    "./runtest.exe -w entry-dynamic.exe printf_fmt_n.exe",
    "./runtest.exe -w entry-dynamic.exe pthread_robust_detach.exe",
    "./runtest.exe -w entry-dynamic.exe pthread_cond_smasher.exe",
    "./runtest.exe -w entry-dynamic.exe pthread_condattr_setclock.exe",
    "./runtest.exe -w entry-dynamic.exe pthread_exit_cancel.exe",
    "./runtest.exe -w entry-dynamic.exe pthread_once_deadlock.exe",
    "./runtest.exe -w entry-dynamic.exe pthread_rwlock_ebusy.exe",
    "./runtest.exe -w entry-dynamic.exe putenv_doublefree.exe",
    "./runtest.exe -w entry-dynamic.exe regex_backref_0.exe",
    "./runtest.exe -w entry-dynamic.exe regex_bracket_icase.exe",
    "./runtest.exe -w entry-dynamic.exe regex_ere_backref.exe",
    "./runtest.exe -w entry-dynamic.exe regex_escaped_high_byte.exe",
    "./runtest.exe -w entry-dynamic.exe regex_negated_range.exe",
    "./runtest.exe -w entry-dynamic.exe regexec_nosub.exe",
    "./runtest.exe -w entry-dynamic.exe rewind_clear_error.exe",
    "./runtest.exe -w entry-dynamic.exe rlimit_open_files.exe",
    "./runtest.exe -w entry-dynamic.exe scanf_bytes_consumed.exe",
    "./runtest.exe -w entry-dynamic.exe scanf_match_literal_eof.exe",
    "./runtest.exe -w entry-dynamic.exe scanf_nullbyte_char.exe",
    "./runtest.exe -w entry-dynamic.exe setvbuf_unget.exe",
    "./runtest.exe -w entry-dynamic.exe sigprocmask_internal.exe",
    "./runtest.exe -w entry-dynamic.exe sscanf_eof.exe",
    "./runtest.exe -w entry-dynamic.exe statvfs.exe",
    "./runtest.exe -w entry-dynamic.exe strverscmp.exe",
    "./runtest.exe -w entry-dynamic.exe syscall_sign_extend.exe",
    "./runtest.exe -w entry-dynamic.exe tls_get_new_dtv.exe",
    "./runtest.exe -w entry-dynamic.exe uselocale_0.exe",
    "./runtest.exe -w entry-dynamic.exe wcsncpy_read_overflow.exe",
    "./runtest.exe -w entry-dynamic.exe wcsstr_false_negative.exe",
];

#[allow(dead_code)]
pub const LUA_TESTCASES: &[&str] = &[
    // "lua", // 需标准输入，不好进行自动测试
    "lua date.lua",
    "lua file_io.lua",
    "lua max_min.lua",
    "lua random.lua",
    "lua remove.lua",
    "lua round_num.lua",
    "lua sin30.lua",
    "lua strings.lua",
    "lua sort.lua",
];

#[allow(dead_code)]
pub const OSTRAIN_TESTCASES: &[&str] = &[
    // "fileopen",
    // "fileread",
    // "filewrite",
    // "task_yield",
    "task_single_yield",
    // "getpid",
    // "malloc",
    // "thread_sigsegv",
    // "process_sigsegv",
];

#[allow(dead_code)]
pub const SDCARD_TESTCASES: &[&str] = &[
    // "hello",
    // "main",
    // "libc.so",
    // "busybox echo hello",
    // "busybox sh test_hello.sh",
    "busybox sh",
    // "busybox ls",
    // "sh",
    // "busybox sh lua_testcode.sh",
    // "./riscv64-linux-musl-native/bin/riscv64-linux-musl-gcc ./hello.c -static",
    // "./a.out",
    // "./time-test",
    // "./interrupts-test-1",
    // "./interrupts-test-2",
    // "./copy-file-range-test-1",
    // "./copy-file-range-test-2",
    // "./copy-file-range-test-3",
    // "./copy-file-range-test-4",
    // "busybox echo hello",
    // "busybox sh ./unixbench_testcode.sh",
    // "busybox echo hello",
    // "busybox sh ./iperf_testcode.sh",
    // "busybox echo hello",
    // "busybox sh busybox_testcode.sh",
    // "busybox echo hello",
    // "busybox sh ./iozone_testcode.sh",
    // "busybox echo latency measurements",
    // "lmbench_all lat_syscall -P 1 null",
    // "lmbench_all lat_syscall -P 1 read",
    // "lmbench_all lat_syscall -P 1 write",
    // "busybox mkdir -p /var/tmp",
    // "busybox touch /var/tmp/lmbench",
    // "lmbench_all lat_syscall -P 1 stat /var/tmp/lmbench",
    // "lmbench_all lat_syscall -P 1 fstat /var/tmp/lmbench",
    // "lmbench_all lat_syscall -P 1 open /var/tmp/lmbench",
    // "lmbench_all lat_select -n 100 -P 1 file",
    // "lmbench_all lat_sig -P 1 install",
    // "lmbench_all lat_sig -P 1 catch",
    // "lmbench_all lat_sig -P 1 prot lat_sig",
    // "lmbench_all lat_pipe -P 1",
    // "lmbench_all lat_proc -P 1 fork",
    // "lmbench_all lat_proc -P 1 exec",
    // "busybox cp hello /tmp",
    // "lmbench_all lat_proc -P 1 shell",
    // "lmbench_all lmdd label=\"File /var/tmp/XXX write bandwidth:\" of=/var/tmp/XXX move=1m fsync=1 print=3",
    // "lmbench_all lat_pagefault -P 1 /var/tmp/XXX",
    // "lmbench_all lat_mmap -P 1 512k /var/tmp/XXX",
    // "busybox echo file system latency",
    // "lmbench_all lat_fs /var/tmp",
    // "busybox echo Bandwidth measurements",
    // "lmbench_all bw_pipe -P 1",
    // "lmbench_all bw_file_rd -P 1 512k io_only /var/tmp/XXX",
    // "lmbench_all bw_file_rd -P 1 512k open2close /var/tmp/XXX",
    // "lmbench_all bw_mmap_rd -P 1 512k mmap_only /var/tmp/XXX",
    // "lmbench_all bw_mmap_rd -P 1 512k open2close /var/tmp/XXX",
    // "busybox echo context switch overhead",
    // "lmbench_all lat_ctx -P 1 -s 32 2 4 8 16 24 32 64 96",
    // "busybox sh libctest_testcode.sh",
    // "busybox sh lua_testcode.sh",
    // "libc-bench",
    // "busybox sh ./netperf_testcode.sh",
    // "busybox sh ./cyclictest_testcode.sh",
];

pub const NETPERF_TESTCASES: &[&str] = &[
    "netperf -H 127.0.0.1 -p 12865 -t UDP_STREAM -l 1 -- -s 16k -S 16k -m 1k -M 1k",
    "netperf -H 127.0.0.1 -p 12865 -t TCP_STREAM -l 1 -- -s 16k -S 16k -m 1k -M 1k",
    "netperf -H 127.0.0.1 -p 12865 -t UDP_RR -l 1 -- -s 16k -S 16k -m 1k -M 1k -r 64,64 -R 1",
    "netperf -H 127.0.0.1 -p 12865 -t TCP_RR -l 1 -- -s 16k -S 16k -m 1k -M 1k -r 64,64 -R 1",
    "netperf -H 127.0.0.1 -p 12865 -t TCP_CRR -l 1 -- -s 16k -S 16k -m 1k -M 1k -r 64,64 -R 1",
];

pub const IPERF_TESTCASES: &[&str] = &[
    "iperf3 -c 127.0.0.1 -p 5001 -t 2 -i 0", // basic tcp
    "iperf3 -c 127.0.0.1 -p 5001 -t 2 -i 0 -u -b 100G", // basic udp
    "iperf3 -c 127.0.0.1 -p 5001 -t 2 -i 0 -P 5", // parallel tcp
    "iperf3 -c 127.0.0.1 -p 5001 -t 2 -i 0 -u -P 5 -b 1000G", // parallel udp
    "iperf3 -c 127.0.0.1 -p 5001 -t 2 -i 0 -R", // reverse tcp
    "iperf3 -c 127.0.0.1 -p 5001 -t 2 -i 0 -u -R -b 1000G", // reverse udp
];
/// 运行测试时的状态机，记录测试结果与内容
struct TestResult {
    sum: usize,
    accepted: usize,
    now_testcase: Option<Vec<String>>,
    // 同时记录名称与进程号
    failed_testcases: Vec<Vec<String>>,
}

impl TestResult {
    pub fn new(case_num: usize) -> Self {
        Self {
            sum: case_num,
            accepted: 0,
            now_testcase: None,
            failed_testcases: Vec::new(),
        }
    }
    pub fn load(&mut self, testcase: &Vec<String>) {
        warn!(
            " --------------- load testcase: {:?} --------------- ",
            testcase
        );
        self.now_testcase = Some(testcase.clone());
    }
    /// 调用这个函数的应当是测例最开始的进程，而不是它fork出来的一系列进程
    /// 认为exit_code为负数时代表不正常
    pub fn finish_one_test(&mut self, exit_code: i32) {
        match exit_code {
            0 => {
                warn!(" --------------- test passed --------------- ");
                self.accepted += 1;
                self.now_testcase.take();
            }
            _ => {
                warn!(
                    " --------------- TEST FAILED, exit code = {} --------------- ",
                    exit_code
                );
                self.failed_testcases
                    .push(self.now_testcase.take().unwrap());
            }
        }
    }

    /// 完成了所有测例之后，打印测试结果
    pub fn show_result(&self) {
        info!(
            " --------------- all test ended, passed {} / {} --------------- ",
            self.accepted, self.sum
        );
        info!(" --------------- failed tests: --------------- ");
        for test in &self.failed_testcases {
            info!("{:?}", test);
        }
        info!(" --------------- end --------------- ");
    }
}

static TESTRESULT: LazyInit<SpinNoIrq<TestResult>> = LazyInit::new();

/// 某一个测试用例完成之后调用，记录测试结果
pub fn finish_one_test(exit_code: i32) {
    TESTRESULT.lock().finish_one_test(exit_code);
}

#[allow(dead_code)]
pub fn show_result() {
    TESTRESULT.lock().show_result();
}
#[allow(unused)]
/// 分割命令行参数
fn get_args(command_line: &[u8]) -> Vec<String> {
    let mut args = Vec::new();
    // 需要判断是否存在引号，如busybox_cmd.txt的第一条echo指令便有引号
    // 若有引号时，不能把引号加进去，同时要注意引号内的空格不算是分割的标志
    let mut in_quote = false;
    let mut arg_start = 0; // 一个新的参数的开始位置
    for pos in 0..command_line.len() {
        if command_line[pos] == '\"' as u8 {
            in_quote = !in_quote;
        }
        if command_line[pos] == ' ' as u8 && !in_quote {
            // 代表要进行分割
            // 首先要防止是否有空串
            if arg_start != pos {
                args.push(
                    core::str::from_utf8(&command_line[arg_start..pos])
                        .unwrap()
                        .to_string(),
                );
            }
            arg_start = pos + 1;
        }
    }
    // 最后一个参数
    if arg_start != command_line.len() {
        args.push(
            core::str::from_utf8(&command_line[arg_start..])
                .unwrap()
                .to_string(),
        );
    }
    args
}
/// 在执行系统调用前初始化文件系统
///
/// 包括建立软连接，提前准备好一系列的文件与文件夹
pub fn fs_init(_case: &'static str) {
    // 需要对libc-dynamic进行特殊处理，因为它需要先加载libc.so
    // 建立一个硬链接

    let libc_so  = &"ld-musl-loongarch64-sf.so.1";
    let libc_so1 = &"ld.so.1";
    let libc_so2 = &"ld-musl-loongarch64.so.1"; // 另一种名字的 libc.so，非 libc-test 测例库用

    create_link(
        &(FilePath::new(("/lib/".to_string() + libc_so).as_str()).unwrap()),
        &(FilePath::new("libc.so").unwrap()),
    );

    create_link(
        &(FilePath::new(("/lib64/".to_string() + libc_so1).as_str()).unwrap()),
        &(FilePath::new("libc.so").unwrap()),
    );

    create_link(
        &(FilePath::new(("/lib/".to_string() + libc_so2).as_str()).unwrap()),
        &(FilePath::new("libc.so").unwrap()),
    );

    let tls_so = &"tls_get_new-dtv_dso.so";
    create_link(
        &(FilePath::new(("/lib/".to_string() + tls_so).as_str()).unwrap()),
        &(FilePath::new("tls_get_new-dtv_dso.so").unwrap()),
    );

    // if case == "busybox" {
    create_link(
        &(FilePath::new("/sbin/busybox").unwrap()),
        &(FilePath::new("busybox").unwrap()),
    );
    create_link(
        &(FilePath::new("/usr/sbin/busybox").unwrap()),
        &(FilePath::new("busybox").unwrap()),
    );
    // create_link(
    //     &(FilePath::new("/sbin/ls").unwrap()),
    //     &(FilePath::new("busybox").unwrap()),
    // );
    create_link(
        &(FilePath::new("/usr/sbin/ls").unwrap()),
        &(FilePath::new("busybox").unwrap()),
    );
    create_link(
        &(FilePath::new("/usr/sbin/main").unwrap()),
        &(FilePath::new("main").unwrap()),
    );
    create_link(
        &(FilePath::new("/usr/sbin/hello").unwrap()),
        &(FilePath::new("hello").unwrap()),
    );
    // create_link(
    //     &(FilePath::new("/ls").unwrap()),
    //     &(FilePath::new("/busybox").unwrap()),
    // );
    // create_link(
    //     &(FilePath::new("/sh").unwrap()),
    //     &(FilePath::new("/busybox").unwrap()),
    // );
    create_link(
        &(FilePath::new("/bin/lmbench_all").unwrap()),
        &(FilePath::new("/lmbench_all").unwrap()),
    );
    create_link(
        &(FilePath::new("/bin/iozone").unwrap()),
        &(FilePath::new("/iozone").unwrap()),
    );
    let _ = new_file("/lat_sig", &(FileFlags::CREATE | FileFlags::RDWR));
    // }

    // gcc相关的链接，可以在testcases/gcc/riscv64-linux-musl-native/lib目录下使用ls -al指令查看
    /*
    let src_dir = "riscv64-linux-musl-native/lib";
    create_link(
        &FilePath::new(format!("{}/ld-musl-riscv64.so.1", src_dir).as_str()).unwrap(),
        &FilePath::new("/lib/libc.so").unwrap(),
    );
    create_link(
        &FilePath::new(format!("{}/libatomic.so", src_dir).as_str()).unwrap(),
        &FilePath::new(format!("{}/libatomic.so.1.2.0", src_dir).as_str()).unwrap(),
    );
    create_link(
        &FilePath::new(format!("{}/libatomic.so.1", src_dir).as_str()).unwrap(),
        &FilePath::new(format!("{}/libatomic.so.1.2.0", src_dir).as_str()).unwrap(),
    );
    create_link(
        &FilePath::new(format!("{}/libgfortran.so", src_dir).as_str()).unwrap(),
        &FilePath::new(format!("{}/libgfortran.so.5.0.0", src_dir).as_str()).unwrap(),
    );
    create_link(
        &FilePath::new(format!("{}/libgfortran.so.5", src_dir).as_str()).unwrap(),
        &FilePath::new(format!("{}/libgfortran.so.5.0.0", src_dir).as_str()).unwrap(),
    );
    create_link(
        &FilePath::new(format!("{}/libgomp.so", src_dir).as_str()).unwrap(),
        &FilePath::new(format!("{}/libgomp.so.1.0.0", src_dir).as_str()).unwrap(),
    );
    create_link(
        &FilePath::new(format!("{}/libgomp.so.1", src_dir).as_str()).unwrap(),
        &FilePath::new(format!("{}/libgomp.so.1.0.0", src_dir).as_str()).unwrap(),
    );
    create_link(
        &FilePath::new(format!("{}/libssp.so", src_dir).as_str()).unwrap(),
        &FilePath::new(format!("{}/libssp.so.0.0.0", src_dir).as_str()).unwrap(),
    );
    create_link(
        &FilePath::new(format!("{}/libssp.so.0", src_dir).as_str()).unwrap(),
        &FilePath::new(format!("{}/libssp.so.0.0.0", src_dir).as_str()).unwrap(),
    );
    create_link(
        &FilePath::new(format!("{}/libstdc++.so", src_dir).as_str()).unwrap(),
        &FilePath::new(format!("{}/libstdc++.so.6.0.29", src_dir).as_str()).unwrap(),
    );
    create_link(
        &FilePath::new(format!("{}/libstdc++.so.6", src_dir).as_str()).unwrap(),
        &FilePath::new(format!("{}/libstdc++.so.6.0.29", src_dir).as_str()).unwrap(),
    );
    */
}

pub fn run_testcases(case: &'static str) {
    fs_init(case);
    let (mut test_iter, case_len) = match case {
        "junior" => (Box::new(JUNIOR_TESTCASES.iter()), JUNIOR_TESTCASES.len()),
        "libc-static" => (
            Box::new(LIBC_STATIC_TESTCASES.iter()),
            LIBC_STATIC_TESTCASES.len(),
        ),
        "libc-dynamic" => (
            Box::new(LIBC_DYNAMIC_TESTCASES.iter()),
            LIBC_DYNAMIC_TESTCASES.len(),
        ),
        "lua" => (Box::new(LUA_TESTCASES.iter()), LUA_TESTCASES.len()),
        "netperf" => (Box::new(NETPERF_TESTCASES.iter()), NETPERF_TESTCASES.len()),

        "ipref" => (Box::new(IPERF_TESTCASES.iter()), IPERF_TESTCASES.len()),

        "sdcard" => (Box::new(SDCARD_TESTCASES.iter()), SDCARD_TESTCASES.len()),

        "ostrain" => (Box::new(OSTRAIN_TESTCASES.iter()), OSTRAIN_TESTCASES.len()),
        _ => {
            panic!("unknown test case: {}", case);
        }
    };
    TESTRESULT.init_by(SpinNoIrq::new(TestResult::new(case_len)));
    loop {
        let mut ans = None;
        if let Some(command_line) = test_iter.next() {
            let args = get_args(command_line.as_bytes());
            let testcase = args.clone();
            // let real_testcase = if testcase[0] == "./busybox".to_string()
            //     || testcase[0] == "busybox".to_string()
            //     || testcase[0] == "entry-static.exe".to_string()
            //     || testcase[0] == "entry-dynamic.exe".to_string()
            //     || testcase[0] == "lmbench_all".to_string()
            // {
            //     testcase[1].clone()
            // } else {
            //     testcase[0].clone()
            // };

            let main_task = axprocess::Process::init(args).unwrap();
            let now_process_id = main_task.get_process_id() as isize;
            TESTRESULT.lock().load(&(testcase));
            let mut exit_code = 0;
            ans = loop {
                if wait_pid(now_process_id, &mut exit_code as *mut i32).is_ok() {
                    break Some(exit_code);
                }

                yield_now_task();
            };
        }
        TaskId::clear();
        
        #[cfg(not(target_arch = "loongarch64"))]
        {
            write_page_table_root(KERNEL_PAGE_TABLE.root_paddr());
        };
        
        flush_tlb(None);

        EXITED_TASKS.lock().clear();
        if let Some(exit_code) = ans {
            let kernel_process = Arc::clone(PID2PC.lock().get(&KERNEL_PROCESS_ID).unwrap());
            kernel_process
                .children
                .lock()
                .retain(|x| x.pid() == KERNEL_PROCESS_ID);
            // 去除指针引用，此时process_id对应的进程已经被释放
            // 释放所有非内核进程
            finish_one_test(exit_code);
        } else {
            // 已经测试完所有的测例
            TESTRESULT.lock().show_result();
            break;
        }
        // chdir会改变当前目录，需要重新设置
        init_current_dir();
    }
}
