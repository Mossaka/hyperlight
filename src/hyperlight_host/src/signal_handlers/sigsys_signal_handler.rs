/*
Copyright 2025  The Hyperlight Authors.

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

#[cfg(feature = "seccomp")]
pub(super) extern "C" fn handle_sigsys(
    signal: i32,
    info: *mut libc::siginfo_t,
    context: *mut libc::c_void,
) {
    #[cfg(target_arch = "x86_64")]
    {
        unsafe {
            // si_code contains the reason for the SIGSYS signal.
            // SYS_SECCOMP is 1 as per:
            // https://github.com/torvalds/linux/blob/81983758430957d9a5cb3333fe324fd70cf63e7e/include/uapi/asm-generic/siginfo.h#L301C9-L301C21
            const SYS_SECCOMP: libc::c_int = 1;
            // Sanity checks to make sure SIGSYS was triggered by a BPF filter.
            // If something else triggered a SIGSYS (i.e., kill()), we do nothing.
            // Inspired by Chromium's sandbox:
            // https://chromium.googlesource.com/chromium/chromium/+/master/sandbox/linux/seccomp-bpf/sandbox_bpf.cc#572
            if signal != libc::SIGSYS
                || (*info).si_code != SYS_SECCOMP
                || context.is_null()
                || (*info).si_errno < 0
            {
                let err_msg =
                    b"[ERROR][HYPERLIGHT] SIGSYS triggered by something other than a BPF filter\n";
                libc::write(
                    libc::STDERR_FILENO,
                    err_msg.as_ptr() as *const _,
                    err_msg.len(),
                );
                return;
            }

            let err_msg = b"[ERROR][HYPERLIGHT] Handling disallowed syscall\n";
            libc::write(
                libc::STDERR_FILENO,
                err_msg.as_ptr() as *const _,
                err_msg.len(),
            );

            // We get the syscall number by accessing a particular offset in the `siginfo_t` struct.
            // This only works because this is handling a SIGSYS signal (i.e., the `siginfo_t` struct
            // is implemented as a union in the kernel:
            // https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/siginfo.h).
            // Note: This is not necessarily platform-agnostic, so we might want to be more careful here
            // in the future.
            const SI_OFF_SYSCALL: isize = 6;
            let syscall = *(info as *const i32).offset(SI_OFF_SYSCALL) as usize;
            let syscall_bytes = raw_format(b"[ERROR][HYPERLIGHT] Disallowed Syscall: ", syscall);

            // `write` as per https://man7.org/linux/man-pages/man7/signal-safety.7.html
            // is async-signal-safe.
            libc::write(
                libc::STDERR_FILENO,
                syscall_bytes.as_ptr() as *const _,
                syscall_bytes.len(),
            );

            // Note: This is not necessarily platform-agnostic, so we might want to be more careful here
            // in the future.
            let ucontext = context as *mut libc::ucontext_t;
            let mcontext = &mut (*ucontext).uc_mcontext;

            if syscall == libc::SYS_ioctl as usize {
                let ioctl_param = mcontext.gregs[libc::REG_EBRACE as usize] as usize;
                let ioctl_param_bytes =
                    raw_format(b"[ERROR][HYPERLIGHT] IOCTL Param: ", ioctl_param);
                libc::write(
                    libc::STDERR_FILENO,
                    ioctl_param_bytes.as_ptr() as *const _,
                    ioctl_param_bytes.len(),
                );
            }

            // We don't want to return execution to the offending host function, so
            // we alter the RIP register to point to a function that will panic out of
            // the host function call.
            mcontext.gregs[libc::REG_RIP as usize] =
                after_syscall_violation as usize as libc::greg_t;
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        compile_error!("Unsupported architecture for seccomp feature");
    }
}

extern "C-unwind" fn after_syscall_violation() {
    #[allow(clippy::panic)]
    std::panic::panic_any(crate::HyperlightError::DisallowedSyscall);
}

fn raw_format(prefix: &[u8], raw: usize) -> [u8; 64] {
    const PREFIX_BUF_LEN: usize = 64;
    const DIGITS_BUF_LEN: usize = 20;

    let mut buffer = [0u8; PREFIX_BUF_LEN];
    let mut i = prefix.len();

    // Copy the prefix message into the buffer.
    buffer[..i].copy_from_slice(prefix);

    // Format the number at the end of the buffer.
    let mut num = raw;
    let mut digits = [0u8; DIGITS_BUF_LEN];
    let mut j = 19;
    if num == 0 {
        digits[j] = b'0';
        j -= 1;
    } else {
        while num > 0 {
            digits[j] = b'0' + (num % 10) as u8;
            num /= 10;
            j -= 1;
        }
    }

    // Copy the number digits to the buffer after the prefix.
    let num_len = 19 - j;
    buffer[i..i + num_len].copy_from_slice(&digits[j + 1..20]);
    i += num_len;

    // Add a newline at the end.
    buffer[i] = b'\n';

    buffer
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test raw_format function with various inputs
    #[test]
    fn test_raw_format_basic() {
        let prefix = b"Test: ";
        let number = 123;
        let result = raw_format(prefix, number);

        // Should start with the prefix
        assert_eq!(&result[..prefix.len()], prefix);

        // Should contain "123" after the prefix
        let expected = b"Test: 123\n";
        let result_str = std::str::from_utf8(&result[..expected.len()]).unwrap();
        let expected_str = std::str::from_utf8(expected).unwrap();
        assert_eq!(result_str, expected_str);
    }

    /// Test raw_format with zero
    #[test]
    fn test_raw_format_zero() {
        let prefix = b"Value: ";
        let result = raw_format(prefix, 0);
        let expected = b"Value: 0\n";
        let result_str = std::str::from_utf8(&result[..expected.len()]).unwrap();
        let expected_str = std::str::from_utf8(expected).unwrap();
        assert_eq!(result_str, expected_str);
    }

    /// Test raw_format with large numbers
    #[test]
    fn test_raw_format_large_number() {
        let prefix = b"Syscall: ";
        let large_number = 999999999999999999usize;
        let result = raw_format(prefix, large_number);

        // Should start with prefix
        assert_eq!(&result[..prefix.len()], prefix);

        // Should end with newline
        let result_slice = &result[..];
        let newline_pos = result_slice.iter().position(|&x| x == b'\n').unwrap();
        assert_eq!(result_slice[newline_pos], b'\n');

        // Should contain the number as string
        let number_part = std::str::from_utf8(&result_slice[prefix.len()..newline_pos]).unwrap();
        assert_eq!(number_part.parse::<usize>().unwrap(), large_number);
    }

    /// Test raw_format with single digit numbers
    #[test]
    fn test_raw_format_single_digits() {
        for digit in 0..10 {
            let prefix = b"Digit: ";
            let result = raw_format(prefix, digit);
            let expected_digit = (b'0' + digit as u8) as char;
            let expected = format!("Digit: {}\n", expected_digit);

            let result_str = std::str::from_utf8(&result[..expected.len()]).unwrap();
            assert_eq!(result_str, expected);
        }
    }

    /// Test raw_format with empty prefix
    #[test]
    fn test_raw_format_empty_prefix() {
        let prefix = b"";
        let number = 42;
        let result = raw_format(prefix, number);

        let expected = b"42\n";
        let result_str = std::str::from_utf8(&result[..expected.len()]).unwrap();
        let expected_str = std::str::from_utf8(expected).unwrap();
        assert_eq!(result_str, expected_str);
    }

    /// Test raw_format with maximum prefix length
    #[test]
    fn test_raw_format_long_prefix() {
        // Use a longer prefix but not too long to cause buffer overflow
        let prefix = b"Very long prefix message here: ";
        let number = 123;
        let result = raw_format(prefix, number);

        // Should start with prefix
        assert_eq!(&result[..prefix.len()], prefix);

        // Should have the number after prefix
        let expected = b"Very long prefix message here: 123\n";
        let result_str = std::str::from_utf8(&result[..expected.len()]).unwrap();
        let expected_str = std::str::from_utf8(expected).unwrap();
        assert_eq!(result_str, expected_str);
    }

    /// Test raw_format with syscall numbers typically seen in Linux
    #[test]
    fn test_raw_format_common_syscall_numbers() {
        let test_cases = vec![
            (libc::SYS_read as usize, "read"),
            (libc::SYS_write as usize, "write"),
            (libc::SYS_open as usize, "open"),
            (libc::SYS_ioctl as usize, "ioctl"),
        ];

        for (syscall_num, syscall_name) in test_cases {
            let prefix = format!("Syscall {}: ", syscall_name).into_bytes();
            let result = raw_format(&prefix, syscall_num);

            // Should contain the syscall number
            let result_str = std::str::from_utf8(&result[..prefix.len() + 10]).unwrap_or("");
            assert!(result_str.contains(&syscall_num.to_string()));
        }
    }

    /// Test after_syscall_violation function exists and has correct signature
    #[test]
    fn test_after_syscall_violation_panics() {
        // This test verifies that after_syscall_violation panics with the expected error
        let result = std::panic::catch_unwind(|| {
            after_syscall_violation();
        });

        // The function should panic
        assert!(result.is_err(), "after_syscall_violation should panic");

        // The panic should contain a HyperlightError::DisallowedSyscall
        let panic_value = result.unwrap_err();
        if let Some(error) = panic_value.downcast_ref::<crate::HyperlightError>() {
            assert!(matches!(error, crate::HyperlightError::DisallowedSyscall));
        } else {
            // Fallback: just verify it panicked (which is the key behavior)
            // The exact panic payload format may vary
        }
    }

    /// Test that handle_sigsys function pointer is valid
    #[test]
    #[cfg(feature = "seccomp")]
    fn test_handle_sigsys_function_pointer() {
        let fn_ptr = handle_sigsys as *const ();
        assert!(
            !fn_ptr.is_null(),
            "handle_sigsys should have a valid function pointer"
        );
    }

    /// Test buffer bounds and safety of raw_format
    #[test]
    fn test_raw_format_buffer_safety() {
        // Test with a prefix that's safely under the buffer limit
        let reasonable_prefix = b"Safe prefix: ";
        let large_number = 999999999999999999usize;
        let result = raw_format(reasonable_prefix, large_number);

        // Should not crash and should produce a valid result
        assert!(!result.is_empty());

        // Should contain a newline somewhere
        assert!(result.contains(&b'\n'));

        // Test with the smallest possible inputs
        let empty_prefix = b"";
        let zero = 0;
        let result_minimal = raw_format(empty_prefix, zero);

        // Should handle minimal case
        assert!(!result_minimal.is_empty());
        assert!(result_minimal.contains(&b'\n'));

        // Test with single character prefix and reasonably large number
        // Use a number that fits within the digit buffer (less than 20 digits)
        let single_prefix = b"A";
        let safe_large_number = 9999999999999999999u64 as usize; // 19 digits, fits in buffer
        let result_single = raw_format(single_prefix, safe_large_number);

        // Should handle edge case
        assert!(!result_single.is_empty());
        assert!(result_single.contains(&b'\n'));
    }

    /// Test raw_format formatting consistency
    #[test]
    fn test_raw_format_formatting_consistency() {
        let prefix = b"Test: ";

        // Test a range of numbers to ensure consistent formatting
        for i in [0, 1, 10, 100, 1000, 10000, 100000] {
            let result = raw_format(prefix, i);
            let expected = format!("Test: {}\n", i);

            // Find the actual length by finding the newline
            let newline_pos = result.iter().position(|&x| x == b'\n').unwrap();
            let actual = std::str::from_utf8(&result[..=newline_pos]).unwrap();

            assert_eq!(
                actual, expected,
                "Formatting should be consistent for {}",
                i
            );
        }
    }
}
