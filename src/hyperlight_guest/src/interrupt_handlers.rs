/*
Copyright 2024 The Hyperlight Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
 */

/// See AMD64 Architecture Programmer's Manual, Volume 2
///     §8.9.3 Interrupt Stack Frame, pp. 283--284
///       Figure 8-14: Long-Mode Stack After Interrupt---Same Privilege,
///       Figure 8-15: Long-Mode Stack After Interrupt---Higher Privilege
/// Subject to the proviso that we push a dummy error code of 0 for exceptions
/// for which the processor does not provide one
#[repr(C)]
pub struct ExceptionInfo {
    pub error_code: u64,
    pub rip:        u64,
    pub cs:         u64,
    pub rflags:     u64,
    pub rsp:        u64,
    pub ss:         u64,
}
const _:() = assert!(core::mem::offset_of!(ExceptionInfo, rip) == 8);
const _:() = assert!(core::mem::offset_of!(ExceptionInfo, rsp) == 32);

#[repr(C)]
/// Saved context, pushed onto the stack by exception entry code
pub struct Context {
    /// in order: gs, fs, es, ds
    pub segments: [u64; 4],
    /// no `rsp`, since the processor saved it
    /// `rax` is at the top, `r15` the bottom
    pub gprs: [u64; 15],
}
const _:() = assert!(size_of::<Context>() == 152);

// TODO: This will eventually need to end up in a per-thread context,
// when there are threads.
pub static handlers: [core::sync::atomic::AtomicU64; 31] =
    [const { core::sync::atomic::AtomicU64::new(0) }; 31];
type handler_t =
    fn(n: u64, info: *mut ExceptionInfo, ctx: *mut Context, pf_addr: u64) -> bool;

/// Exception handler
#[no_mangle]
pub extern "sysv64" fn hl_exception_handler(
    stack_pointer: u64,
    exception_number: u64,
    page_fault_address: u64,
) {
    // Note that this stack pointer was saved when it was pointing at the last
    // quadword of the context structure, so we add only size - 8
    let start_of_ctx = stack_pointer;
    let start_of_info = start_of_ctx + size_of::<Context>() as u64;
    if exception_number < 31 {
        let handler = handlers[exception_number as usize]
            .load(core::sync::atomic::Ordering::Acquire);
        if handler != 0 && unsafe { core::mem::transmute::<_, handler_t>(handler)(
            exception_number,
            start_of_info as *mut ExceptionInfo,
            start_of_ctx as *mut Context,
            page_fault_address,
        ) } {
            return;
        }
    }
    let exception_frame = stack_pointer + 152;
    let error_code = unsafe {
        ((exception_frame +  0) as *const u64).read_volatile()
    };
    let saved_rip = unsafe {
        ((exception_frame +  8) as *const u64).read_volatile()
    };
    let info = start_of_info as *mut ExceptionInfo;
    assert!(unsafe { &raw mut (*info).rip } as u64 == exception_frame +  8);
    let saved_rsp = unsafe {
        ((exception_frame + 32) as *const u64).read_volatile()
    };
    panic!(
        "EXCEPTION: {:#x}\n\
            Faulting Instruction: {:#x}\n\
            Thread RSP: {:#x}\n\
            Error Code: {:#x}\n\
            Page Fault Address: {:#x}\n\
            Stack Pointer: {:#x}",
        exception_number,
        saved_rip,
        saved_rsp,
        error_code,
        page_fault_address,
        stack_pointer
    );
}
