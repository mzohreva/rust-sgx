/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
//! Adaptors between the usercall ABI types and functions and (mostly) safe
//! Rust types.

use std::io::{Error as IoError, ErrorKind as IoErrorKind, Result as IoResult};
use std::slice;

use fortanix_sgx_abi::*;

use super::abi::{UsercallResult, Usercalls};
use super::{EnclaveAbort, IOHandlerInput};
use futures::future::Future;
use crate::futures::FutureExt;

pub(super) struct Handler<'a>(pub IOHandlerInput<'a>);

impl <'a> Usercalls<'a> for Handler<'a> {

    fn is_exiting(&'a self) -> bool {
        self.0.is_exiting()
    }

    fn read(&'a mut self, fd: Fd, buf: *mut u8, len: usize) -> std::pin::Pin<Box<dyn Future<Output = UsercallResult<(Result, usize)>>+'a>> {
        async {
            unsafe {
                Ok(from_raw_parts_mut_nonnull(buf, len)
                    .and_then(|buf| self.0.read(fd, buf))
                    .to_sgx_result())
            }
        }.boxed_local()
    }

    fn read_alloc(&'a mut self, fd: Fd, buf: *mut ByteBuffer) -> std::pin::Pin<Box<dyn Future <Output = UsercallResult<Result>> + 'a>> {
        async {
            unsafe {
                Ok((|| {
                    let mut out = OutputBuffer::new(buf.as_mut().ok_or(IoErrorKind::InvalidInput)?);
                    if !out.buf.data.is_null() {
                        return Err(IoErrorKind::InvalidInput.into());
                    }
                    self.0.read_alloc(fd, &mut out)
                })()
                    .to_sgx_result())
            }
        }.boxed_local()
    }

    fn write(&'a mut self, fd: Fd, buf: *const u8, len: usize) -> std::pin::Pin<Box<dyn Future <Output = UsercallResult<(Result, usize)>> + 'a>> {
        async {
            unsafe {
                Ok(from_raw_parts_nonnull(buf, len)
                    .and_then(|buf| self.0.write(fd, buf))
                    .to_sgx_result())
            }
        }.boxed_local()
    }

    fn flush(&'a mut self, fd: Fd) -> std::pin::Pin<Box<dyn Future <Output = UsercallResult<Result>> + 'a>> {
        async {
            Ok(self.0.flush(fd).to_sgx_result())
        }.boxed_local()
    }

    fn close(&'a mut self, fd: Fd) -> std::pin::Pin<Box<dyn Future <Output = UsercallResult<()>> + 'a>> {
        async {
            Ok(self.0.close(fd))
        }.boxed_local()
    }

    fn bind_stream(
        &'a mut self,
        addr: *const u8,
        len: usize,
        local_addr: *mut ByteBuffer,
    ) -> std::pin::Pin<Box<dyn Future <Output = UsercallResult<(Result, Fd)>> + 'a>> {
        async {
            unsafe {
                let mut local_addr = local_addr.as_mut().map(OutputBuffer::new);
                Ok(from_raw_parts_nonnull(addr, len)
                    .and_then(|addr| self.0.bind_stream(addr, local_addr.as_mut()))
                    .to_sgx_result())
            }
        }.boxed_local()
    }

    fn accept_stream(
        &'a mut self,
        fd: Fd,
        local_addr: *mut ByteBuffer,
        peer_addr: *mut ByteBuffer,
    ) -> std::pin::Pin<Box<dyn Future <Output = UsercallResult<(Result, Fd)>> + 'a>> {
        async {
            unsafe {
                let mut local_addr = local_addr.as_mut().map(OutputBuffer::new);
                let mut peer_addr = peer_addr.as_mut().map(OutputBuffer::new);
                Ok(self
                    .0
                    .accept_stream(fd, local_addr.as_mut(), peer_addr.as_mut())
                    .to_sgx_result())
            }
        }.boxed_local()
    }

    fn connect_stream(
        &'a mut self,
        addr: *const u8,
        len: usize,
        local_addr: *mut ByteBuffer,
        peer_addr: *mut ByteBuffer,
    ) -> std::pin::Pin<Box<dyn Future <Output = UsercallResult<(Result, Fd)>> + 'a>> {
        async {
            unsafe {
                let mut local_addr = local_addr.as_mut().map(OutputBuffer::new);
                let mut peer_addr = peer_addr.as_mut().map(OutputBuffer::new);
                Ok(from_raw_parts_nonnull(addr, len)
                    .and_then(|addr| {
                        self.0
                            .connect_stream(addr, local_addr.as_mut(), peer_addr.as_mut())
                    })
                    .to_sgx_result())
            }
        }.boxed_local()
    }

    fn launch_thread(&'a mut self) -> std::pin::Pin<Box<dyn Future <Output = UsercallResult<Result>> + 'a>> {
        async {
            Ok(self.0.launch_thread().to_sgx_result())
        }.boxed_local()
    }

    fn exit(&'a mut self, panic: bool) -> std::pin::Pin<Box<dyn Future <Output = EnclaveAbort<bool>> + 'a>> {
        async {
            self.0.exit(panic)
        }.boxed_local()
    }

    fn wait(&'a mut self, event_mask: u64, timeout: u64) -> std::pin::Pin<Box<dyn Future <Output = UsercallResult<(Result, u64)>> + 'a>> {
        async {
            if event_mask == 0 && timeout == WAIT_INDEFINITE {
                return Err(EnclaveAbort::IndefiniteWait);
            }

            Ok(self.0.wait(event_mask, timeout).await.to_sgx_result())
        }.boxed_local()
    }

    fn send(&'a mut self, event_set: u64, tcs: Option<Tcs>) -> std::pin::Pin<Box<dyn Future <Output = UsercallResult<Result>> + 'a>> {
        async {
            Ok(self.0.send(event_set, tcs).to_sgx_result())
        }.boxed_local()
    }

    fn insecure_time(&'a mut self) -> std::pin::Pin<Box<dyn Future <Output = UsercallResult<u64>> + 'a>> {
        async {
            Ok(self.0.insecure_time())
        }.boxed_local()
    }

    fn alloc(&'a mut self, size: usize, alignment: usize) -> std::pin::Pin<Box<dyn Future <Output = UsercallResult<(Result, *mut u8)>> + 'a>> {
        async {
            Ok(self.0.alloc(size, alignment).to_sgx_result())
        }.boxed_local()
    }

    fn free(&'a mut self, ptr: *mut u8, size: usize, alignment: usize) -> std::pin::Pin<Box<dyn Future <Output = UsercallResult<()>> + 'a>> {
        async {
            Ok(self.0.free(ptr, size, alignment).unwrap())
        }.boxed_local()
    }

    fn async_queues(
        &'a mut self,
        usercall_queue: *mut FifoDescriptor<Usercall>,
        return_queue: *mut FifoDescriptor<Return>,
    ) -> std::pin::Pin<Box<dyn Future <Output = UsercallResult<Result>> + 'a>> {
        async {
            unsafe {
                Ok((|| {
                    let usercall_queue = usercall_queue
                        .as_mut()
                        .ok_or(IoError::from(IoErrorKind::InvalidInput))?;
                    let return_queue = return_queue
                        .as_mut()
                        .ok_or(IoError::from(IoErrorKind::InvalidInput))?;
                    self.0.async_queues(usercall_queue, return_queue)
                })()
                    .to_sgx_result())
            }
        }.boxed_local()
    }
}

pub(super) struct OutputBuffer<'a> {
    buf: &'a mut ByteBuffer,
    data: Option<Box<[u8]>>,
}

impl<'a> OutputBuffer<'a> {
    fn new(buf: &'a mut ByteBuffer) -> Self {
        OutputBuffer { buf, data: None }
    }

    pub(super) fn set<T: Into<Box<[u8]>>>(&mut self, value: T) {
        // NB. this should use the same allocator as usercall alloc/free
        self.data = Some(value.into());
    }
}

impl<'a> Drop for OutputBuffer<'a> {
    fn drop(&mut self) {
        if let Some(buf) = self.data.take() {
            self.buf.len = buf.len();
            self.buf.data = Box::into_raw(buf) as _;
        } else {
            self.buf.len = 0;
        }
    }
}

fn result_from_io_error(err: IoError) -> Result {
    let ret = match err.kind() {
        IoErrorKind::NotFound => Error::NotFound,
        IoErrorKind::PermissionDenied => Error::PermissionDenied,
        IoErrorKind::ConnectionRefused => Error::ConnectionRefused,
        IoErrorKind::ConnectionReset => Error::ConnectionReset,
        IoErrorKind::ConnectionAborted => Error::ConnectionAborted,
        IoErrorKind::NotConnected => Error::NotConnected,
        IoErrorKind::AddrInUse => Error::AddrInUse,
        IoErrorKind::AddrNotAvailable => Error::AddrNotAvailable,
        IoErrorKind::BrokenPipe => Error::BrokenPipe,
        IoErrorKind::AlreadyExists => Error::AlreadyExists,
        IoErrorKind::WouldBlock => Error::WouldBlock,
        IoErrorKind::InvalidInput => Error::InvalidInput,
        IoErrorKind::InvalidData => Error::InvalidData,
        IoErrorKind::TimedOut => Error::TimedOut,
        IoErrorKind::WriteZero => Error::WriteZero,
        IoErrorKind::Interrupted => Error::Interrupted,
        IoErrorKind::Other => Error::Other,
        IoErrorKind::UnexpectedEof => Error::UnexpectedEof,
        _ => Error::Other,
    };
    ret as _
}

trait ToSgxResult {
    type Return;

    fn to_sgx_result(self) -> Self::Return;
}

trait SgxReturn {
    fn on_error() -> Self;
}

impl SgxReturn for u64 {
    fn on_error() -> Self {
        0
    }
}

impl SgxReturn for usize {
    fn on_error() -> Self {
        0
    }
}

impl SgxReturn for *mut u8 {
    fn on_error() -> Self {
        ::std::ptr::null_mut()
    }
}

impl<T: SgxReturn> ToSgxResult for IoResult<T> {
    type Return = (Result, T);

    fn to_sgx_result(self) -> Self::Return {
        match self {
            Err(e) => (result_from_io_error(e), T::on_error()),
            Ok(v) => (RESULT_SUCCESS, v),
        }
    }
}

impl ToSgxResult for IoResult<()> {
    type Return = Result;

    fn to_sgx_result(self) -> Self::Return {
        self.err()
            .map_or(RESULT_SUCCESS, |e| result_from_io_error(e))
    }
}

pub unsafe fn from_raw_parts_nonnull<'a, T>(p: *const T, len: usize) -> IoResult<&'a [T]> {
    if len == 0 {
        Ok(&[])
    } else if p.is_null() {
        Err(IoErrorKind::InvalidInput.into())
    } else {
        Ok(slice::from_raw_parts(p, len))
    }
}

pub unsafe fn from_raw_parts_mut_nonnull<'a, T>(p: *mut T, len: usize) -> IoResult<&'a mut [T]> {
    if len == 0 {
        Ok(&mut [])
    } else if p.is_null() {
        Err(IoErrorKind::InvalidInput.into())
    } else {
        Ok(slice::from_raw_parts_mut(p, len))
    }
}
