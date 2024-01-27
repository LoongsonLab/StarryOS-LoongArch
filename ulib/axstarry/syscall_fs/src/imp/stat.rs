//! 获取文件系统状态信息
//!

use axfs::api::{FileIOType, Kstat, Kstatx};
use axlog::{debug, error, info};
use axprocess::{
    current_process,
    link::{deal_with_path, FilePath, AT_FDCWD},
};
use syscall_utils::{get_fs_stat, FsStat, SyscallError, SyscallResult};

use crate::ctype::mount::get_stat_in_fs;

pub fn syscall_fstat(fd: usize, kst: *mut Kstat) -> SyscallResult {
    let process = current_process();
    let fd_table = process.fd_manager.fd_table.lock();

    if fd >= fd_table.len() || fd < 3 {
        debug!("fd {} is out of range", fd);
        return Err(SyscallError::EPERM);
    }
    if fd_table[fd].is_none() {
        debug!("fd {} is none", fd);
        return Err(SyscallError::EPERM);
    }
    let file = fd_table[fd].clone().unwrap();
    if (file.get_type() != FileIOType::FileDesc) &&
       (file.get_type() != FileIOType::DirDesc) {
        debug!("fd {} is not a file or dir", fd);
        return Err(SyscallError::EPERM);
    }

    match file.get_stat() {
        Ok(stat) => {
            unsafe {
                *kst = stat;
            }
            Ok(0)
        }
        Err(e) => {
            debug!("get stat error: {:?}", e);
            Err(SyscallError::EPERM)
        }
    }
}

/// 获取文件状态信息，但是给出的是目录 fd 和相对路径。 79
pub fn syscall_fstatat(dir_fd: usize, path: *const u8, kst: *mut Kstat) -> SyscallResult {
    let file_path = deal_with_path(dir_fd, Some(path), false).unwrap();
    info!("path : {}", file_path.path());
    match get_stat_in_fs(&file_path) {
        Ok(stat) => unsafe {
            *kst = stat;
            Ok(0)
        },
        Err(error_no) => {
            debug!("get stat error: {:?}", error_no);
            Err(error_no)
        }
    }
}

/// 43
/// 获取文件系统的信息
pub fn syscall_statfs(path: *const u8, stat: *mut FsStat) -> SyscallResult {
    let file_path = deal_with_path(AT_FDCWD, Some(path), false).unwrap();
    if file_path.equal_to(&FilePath::new("/").unwrap()) {
        // 目前只支持访问根目录文件系统的信息
        unsafe {
            *stat = get_fs_stat();
        }

        Ok(0)
    } else {
        error!("Only support fs_stat for root");
        Err(SyscallError::EINVAL)
    }
}

pub fn dev_convert(dev: u64) -> (u32, u32) {
    let major = ((dev >> 32) & 0xfffff000) | ((dev >> 8) & 0x00000fff);
    let minor = ((dev >> 12) & 0xffffff00) | ((dev >> 0) & 0x000000ff);
    (major as u32, minor as u32)
}

/// 291
/// 获取文件状态信息
/// fd, path, flag, 0x7ff, &stx
pub fn syscall_statx(fd: usize, path: *const u8, _flags: usize, _statx_type: usize, stat: *mut Kstatx) -> SyscallResult {
    if fd == AT_FDCWD {
        let file_path = deal_with_path(fd, Some(path), false).unwrap();
        debug!("path : {}", file_path.path());
        match get_stat_in_fs(&file_path) {
            Ok(kstat) => unsafe {
                (*stat).stx_dev_major = dev_convert(kstat.st_dev).0;
                (*stat).stx_dev_minor = dev_convert(kstat.st_dev).1;
                (*stat).stx_ino   = kstat.st_ino;
                (*stat).stx_mode  = kstat.st_mode as u16;
                (*stat).stx_nlink = kstat.st_nlink;
                (*stat).stx_uid   = kstat.st_uid;
                (*stat).stx_gid   = kstat.st_gid;
                (*stat).stx_atime.tv_sec  = kstat.st_atime_sec as u64;
                (*stat).stx_atime.tv_nsec = kstat.st_atime_nsec as u32;
                (*stat).stx_mtime.tv_sec  = kstat.st_mtime_sec as u64;
                (*stat).stx_mtime.tv_nsec = kstat.st_mtime_nsec as u32;
                (*stat).stx_ctime.tv_sec  = kstat.st_ctime_sec as u64;
                (*stat).stx_ctime.tv_nsec = kstat.st_ctime_nsec as u32;
                (*stat).stx_size    = kstat.st_size;
                (*stat).stx_blocks  = kstat.st_blocks;
                (*stat).stx_blksize = kstat.st_blksize;
                Ok(0)
            },
            Err(error_no) => {
                debug!("get stat error: {:?}", error_no);
                Err(error_no)
            }
        }
    } else {
        let process = current_process();
        let fd_table = process.fd_manager.fd_table.lock();
        if fd_table[fd].is_none() {
            debug!("fd {} is none", fd);
            return Err(SyscallError::EPERM);
        }
        let file = fd_table[fd].clone().unwrap();
        match file.get_stat() {
            Ok(kstat) => {
                unsafe {
                    (*stat).stx_dev_major = dev_convert(kstat.st_dev).0;
                    (*stat).stx_dev_minor = dev_convert(kstat.st_dev).1;
                    (*stat).stx_ino   = kstat.st_ino;
                    (*stat).stx_mode  = kstat.st_mode as u16;
                    (*stat).stx_nlink = kstat.st_nlink;
                    (*stat).stx_uid   = kstat.st_uid;
                    (*stat).stx_gid   = kstat.st_gid;
                    (*stat).stx_atime.tv_sec  = kstat.st_atime_sec as u64;
                    (*stat).stx_atime.tv_nsec = kstat.st_atime_nsec as u32;
                    (*stat).stx_mtime.tv_sec  = kstat.st_mtime_sec as u64;
                    (*stat).stx_mtime.tv_nsec = kstat.st_mtime_nsec as u32;
                    (*stat).stx_ctime.tv_sec  = kstat.st_ctime_sec as u64;
                    (*stat).stx_ctime.tv_nsec = kstat.st_ctime_nsec as u32;
                    (*stat).stx_size    = kstat.st_size;
                    (*stat).stx_blocks  = kstat.st_blocks;
                    (*stat).stx_blksize = kstat.st_blksize;
                }
                Ok(0)
            }
            Err(e) => {
                debug!("get stat error: {:?}", e);
                Err(SyscallError::EPERM)
            }
        }
    }
}
