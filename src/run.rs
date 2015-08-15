use std::io;
use std::fs::File;
use std::ffi::CString;
use std::os::unix::io::{RawFd, FromRawFd};
use std::os::unix::ffi::{OsStrExt};

use nix;
use libc;
use libc::c_char;
use nix::errno::errno;

use child;
use config::Config;
use {Command, Child};
use error::Error;
use pipe::Pipe;

pub struct ChildInfo<'a> {
    pub filename: *const c_char,
    pub args: &'a [*const c_char],
    pub environ: &'a [*const c_char],
    pub cfg: &'a Config,
    pub wakeup_pipe: RawFd,
    pub error_pipe: RawFd,
    // TODO(tailhook) stdin, stdout, stderr
}

impl Command {
    pub fn spawn(&mut self) -> Result<Child, Error> {
        self.init_env_map();
        unsafe { self.spawn_inner() }
    }

    unsafe fn spawn_inner(&self) -> Result<Child, Error> {
        // TODO(tailhook) add RAII for pipes
        let wakeup = try!(Pipe::new());
        let errpipe = try!(Pipe::new());

        let c_args = self.args.iter().map(|a| a.as_ptr()).collect::<Vec<_>>();

        let environ: Vec<CString> = self.environ.as_ref().unwrap()
            .iter().map(|(k, v)| {
                let mut pair = k[..].as_bytes().to_vec();
                pair.push(b'=');
                pair.extend(v.as_bytes());
                CString::new(pair).unwrap()
            }).collect();
        let c_environ: Vec<_> = environ.iter().map(|x| x.as_ptr()).collect();

        let pid = libc::fork();
        if pid < 0 {
            return Err(Error::Fork(errno()));
        } else if pid == 0 {
            let child_info = ChildInfo {
                filename: self.filename.as_ptr(),
                args: &c_args[..],
                environ: &c_environ[..],
                cfg: &self.config,
                wakeup_pipe: wakeup.into_reader(),
                error_pipe: errpipe.into_writer(),
            };
            child::child_after_clone(&child_info);
        }
        let errpipe = File::from_raw_fd(errpipe.into_reader());
        let wakeup = File::from_raw_fd(wakeup.into_writer());

        Ok(Child {
            pid: pid,
            //status: None,
        })
    }
}