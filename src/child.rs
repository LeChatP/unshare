use std::mem;
use std::os::unix::io::RawFd;
use std::ptr;

use capctl::{Cap, CapSet, CapState};
use nix::errno::Errno;
use nix::libc::{c_ulong, c_void, sigset_t, size_t};
use nix::libc::{kill, signal};
use nix::libc::{FD_CLOEXEC, F_DUPFD_CLOEXEC, F_GETFD, F_SETFD, MNT_DETACH};
use nix::libc::{SIG_DFL, SIG_SETMASK};
use nix;

use crate::error::ErrorCode as Err;
use crate::run::{ChildInfo, MAX_PID_LEN};

const CAPABILITIES_ERROR: &str =
    "You need at least setpcap, sys_admin, bpf, sys_resource, sys_ptrace capabilities to run capable";
fn cap_effective_error(caplist: &str) -> String {
    format!(
        "Unable to toggle {} privilege. {}",
        caplist, CAPABILITIES_ERROR
    )
}

fn cap_effective(cap: Cap, enable: bool) -> Result<(), capctl::Error> {
    let mut current = CapState::get_current()?;
    current.effective.set_state(cap, enable);
    current.set_current()
}

fn setpcap_effective(enable: bool) -> Result<(), capctl::Error> {
    cap_effective(Cap::SETPCAP, enable)
}

fn set_capabilities(caps: CapSet, requires_bounding: bool) {
    //set capabilities
    // case where capabilities are more than bounding set
    let bounding = capctl::bounding::probe();
    if bounding & caps != caps {
        panic!("Unable to setup the execution environment: There are more capabilities in this task than the current bounding set! You may are in a container or already in a RootAsRole session.");
    }
    setpcap_effective(true).unwrap_or_else(|_| panic!("{}", cap_effective_error("setpcap")));
    let mut capstate = CapState::empty();
    if requires_bounding {
        for cap in (!caps).iter() {
            capctl::bounding::drop(cap).expect("Failed to set bounding cap");
        }
    }
    capstate.permitted = caps;
    capstate.inheritable = caps;
    capstate.set_current().expect("Failed to set current cap");
    for cap in caps.iter() {
        capctl::ambient::raise(cap).expect("Failed to set ambiant cap");
    }
    setpcap_effective(false).unwrap_or_else(|_| panic!("{}", cap_effective_error("setpcap")));
    
}

// And at this point we've reached a special time in the life of the
// child. The child must now be considered hamstrung and unable to
// do anything other than syscalls really.
//
// ESPECIALLY YOU CAN NOT DO MEMORY (DE)ALLOCATIONS
//
// See better explanation at:
// https://github.com/rust-lang/rust/blob/c1e865c/src/libstd/sys/unix/process.rs#L202
//

// In particular ChildInfo is passed by refernce here to avoid
// deallocating (parts of) it.
pub unsafe fn child_after_clone(child: &ChildInfo) -> ! {
    let mut epipe = child.error_pipe;

    child.cfg.death_sig.as_ref().map(|&sig| {
        if nix::libc::prctl(ffi::PR_SET_PDEATHSIG, sig as c_ulong, 0, 0, 0) != 0 {
            fail(Err::ParentDeathSignal, epipe);
        }
    });

    // Now we must wait until parent set some environment for us. It's mostly
    // for uid_map/gid_map. But also used for attaching debugger and maybe
    // other things
    let mut wbuf = [0u8];
    loop {
        // TODO(tailhook) put some timeout on this pipe?
        let rc = nix::libc::read(child.wakeup_pipe, (&mut wbuf).as_ptr() as *mut c_void, 1);
        if rc == 0 {
            // Parent already dead presumably before we had a chance to
            // set PDEATHSIG, so just send signal ourself in that case
            if let Some(sig) = child.cfg.death_sig {
                kill(nix::libc::getpid(), sig as i32);
                nix::libc::_exit(127);
            } else {
                // In case we wanted to daemonize, just continue
                //
                // TODO(tailhook) not sure it's best thing to do. Maybe parent
                // failed to setup uid/gid map for us. Do we want to check
                // specific options? Or should we just always die?
                break;
            }
        } else if rc < 0 {
            let errno = Errno::last_raw();
            if errno == nix::libc::EINTR as i32 || errno == nix::libc::EAGAIN as i32 {
                continue;
            } else {
                fail(Err::PipeError, errno);
            }
        } else {
            // Do we need to check that exactly one byte is received?
            break;
        }
    }

    // Move error pipe file descriptors in case they clobber stdio
    while epipe < 3 {
        let nerr = nix::libc::fcntl(epipe, F_DUPFD_CLOEXEC, 3);
        if nerr < 0 {
            fail(Err::CreatePipe, epipe);
        }
        epipe = nerr;
    }

    for &(nstype, fd) in child.setns_namespaces {
        if nix::libc::setns(fd, nstype.bits()) != 0 {
            fail(Err::SetNs, epipe);
        }
    }

    if !child.pid_env_vars.is_empty() {
        let mut buf = [0u8; MAX_PID_LEN + 1];
        let data = format_pid_fixed(&mut buf, nix::libc::getpid());
        for &(index, offset) in child.pid_env_vars {
            // we know that there are at least MAX_PID_LEN+1 bytes in buffer
            child.environ[index]
                .offset(offset as isize)
                .copy_from(data.as_ptr() as *const nix::libc::c_char, data.len());
        }
    }

    child.pivot.as_ref().map(|piv| {
        if ffi::pivot_root(piv.new_root.as_ptr(), piv.put_old.as_ptr()) != 0 {
            fail(Err::ChangeRoot, epipe);
        }
        if nix::libc::chdir(piv.workdir.as_ptr()) != 0 {
            fail(Err::ChangeRoot, epipe);
        }
        if piv.unmount_old_root {
            if nix::libc::umount2(piv.old_inside.as_ptr(), MNT_DETACH) != 0 {
                fail(Err::ChangeRoot, epipe);
            }
        }
    });

    child.chroot.as_ref().map(|chroot| {
        if nix::libc::chroot(chroot.root.as_ptr()) != 0 {
            fail(Err::ChangeRoot, epipe);
        }
        if nix::libc::chdir(chroot.workdir.as_ptr()) != 0 {
            fail(Err::ChangeRoot, epipe);
        }
    });

    child.keep_caps.as_ref().map(|_| {
        // Don't use securebits because on older systems it doesn't work
        if nix::libc::prctl(nix::libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0 {
            fail(Err::CapSet, epipe);
        }
    });

    child.cfg.gid.as_ref().map(|&gid| {
        if nix::libc::setgid(gid) != 0 {
            fail(Err::SetUser, epipe);
        }
    });

    child.cfg.supplementary_gids.as_ref().map(|groups| {
        if nix::libc::setgroups(groups.len() as size_t, groups.as_ptr()) != 0 {
            fail(Err::SetUser, epipe);
        }
    });

    child.cfg.uid.as_ref().map(|&uid| {
        if nix::libc::setuid(uid) != 0 {
            fail(Err::SetUser, epipe);
        }
    });

    child.cfg.work_dir.as_ref().map(|dir| {
        if nix::libc::chdir(dir.as_ptr()) != 0 {
            fail(Err::Chdir, epipe);
        }
    });

    for &(dest_fd, src_fd) in child.fds {
        if src_fd == dest_fd {
            let flags = nix::libc::fcntl(src_fd, F_GETFD);
            if flags < 0 || nix::libc::fcntl(src_fd, F_SETFD, flags & !FD_CLOEXEC) < 0 {
                fail(Err::StdioError, epipe);
            }
        } else {
            if nix::libc::dup2(src_fd, dest_fd) < 0 {
                fail(Err::StdioError, epipe);
            }
        }
    }

    for &(start, end) in child.close_fds {
        if start < end {
            for fd in start..end {
                if child.fds.iter().find(|&&(cfd, _)| cfd == fd).is_none() {
                    // Close may fail with ebadf, and it's okay
                    nix::libc::close(fd);
                }
            }
        }
    }

    if child.cfg.restore_sigmask {
        let mut sigmask: sigset_t = mem::zeroed();
        nix::libc::sigemptyset(&mut sigmask);
        nix::libc::pthread_sigmask(SIG_SETMASK, &sigmask, ptr::null_mut());
        for sig in 1..32 {
            signal(sig, SIG_DFL);
        }
    }

    set_capabilities(child.keep_caps.unwrap_or(CapSet::empty()), false);

    nix::libc::execve(
        child.filename,
        child.args.as_ptr(),
        // cancelling mutability, it should be fine
        child.environ.as_ptr() as *const *const nix::libc::c_char,
    );
    fail(Err::Exec, epipe);
}

unsafe fn fail(code: Err, output: RawFd) -> ! {
    fail_errno(code, Errno::last_raw(), output)
}
unsafe fn fail_errno(code: Err, errno: i32, output: RawFd) -> ! {
    let bytes = [
        code as u8,
        (errno >> 24) as u8,
        (errno >> 16) as u8,
        (errno >> 8) as u8,
        (errno >> 0) as u8,
        // TODO(tailhook) rustc adds a special sentinel at the end of error
        // code. Do we really need it? Assuming our pipes are always cloexec'd.
    ];
    // Writes less than PIPE_BUF should be atomic. It's also unclear what
    // to do if error happened anyway
    nix::libc::write(output, bytes.as_ptr() as *const c_void, 5);
    nix::libc::_exit(127);
}

fn format_pid_fixed<'a>(buf: &'a mut [u8], pid: nix::libc::pid_t) -> &'a [u8] {
    buf[buf.len() - 1] = 0;
    if pid == 0 {
        buf[buf.len() - 2] = b'0';
        return &buf[buf.len() - 2..];
    } else {
        let mut tmp = pid;
        // can't use stdlib function because that can allocate
        for n in (0..buf.len() - 1).rev() {
            buf[n] = (tmp % 10) as u8 + b'0';
            tmp /= 10;
            if tmp == 0 {
                return &buf[n..];
            }
        }
        unreachable!("can't format pid");
    };
}
/// We don't use functions from nix here because they may allocate memory
/// which we can't to this this module.
mod ffi {
    use nix::libc::{c_char, c_int};

    pub const PR_SET_PDEATHSIG: c_int = 1;

    extern "C" {
        pub fn pivot_root(new_root: *const c_char, put_old: *const c_char) -> c_int;
    }
}

#[cfg(test)]
mod test {
    use super::format_pid_fixed;
    use crate::run::MAX_PID_LEN;
    use rand::{thread_rng, Rng};
    use std::ffi::CStr;

    fn fmt_normal(val: i32) -> String {
        let mut buf = [0u8; MAX_PID_LEN + 1];
        let slice = format_pid_fixed(&mut buf, val);
        return CStr::from_bytes_with_nul(slice)
            .unwrap()
            .to_string_lossy()
            .to_string();
    }
    #[test]
    fn test_format() {
        assert_eq!(fmt_normal(0), "0");
        assert_eq!(fmt_normal(1), "1");
        assert_eq!(fmt_normal(7), "7");
        assert_eq!(fmt_normal(79), "79");
        assert_eq!(fmt_normal(254), "254");
        assert_eq!(fmt_normal(1158), "1158");
        assert_eq!(fmt_normal(77839), "77839");
    }
    #[test]
    fn test_random() {
        for _ in 0..100000 {
            let x = thread_rng().gen();
            if x < 0 {
                continue;
            }
            assert_eq!(fmt_normal(x), format!("{}", x));
        }
    }
}