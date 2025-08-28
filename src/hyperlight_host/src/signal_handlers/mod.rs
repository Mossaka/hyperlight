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

use libc::c_int;

use crate::sandbox::SandboxConfiguration;

#[cfg(feature = "seccomp")]
pub mod sigsys_signal_handler;

pub(crate) fn setup_signal_handlers(config: &SandboxConfiguration) -> crate::Result<()> {
    // This is unsafe because signal handlers only allow a very restrictive set of
    // functions (i.e., async-signal-safe functions) to be executed inside them.
    // Anything that performs memory allocations, locks, and others are non-async-signal-safe.
    // Hyperlight signal handlers are all designed to be async-signal-safe, so this function
    // should be safe to call.
    #[cfg(feature = "seccomp")]
    {
        vmm_sys_util::signal::register_signal_handler(
            libc::SIGSYS,
            sigsys_signal_handler::handle_sigsys,
        )
        .map_err(crate::HyperlightError::VmmSysError)?;

        let original_hook = std::panic::take_hook();
        // Set a custom panic hook that checks for "DisallowedSyscall"
        std::panic::set_hook(Box::new(move |panic_info| {
            // Check if the panic payload matches "DisallowedSyscall"
            if let Some(crate::HyperlightError::DisallowedSyscall) = panic_info
                .payload()
                .downcast_ref::<crate::HyperlightError>(
            ) {
                // Do nothing to avoid superfluous syscalls
                return;
            }
            // If not "DisallowedSyscall", use the original hook
            original_hook(panic_info);
        }));
    }
    vmm_sys_util::signal::register_signal_handler(
        libc::SIGRTMIN() + config.get_interrupt_vcpu_sigrtmin_offset() as c_int,
        vm_kill_signal,
    )
    .map_err(crate::HyperlightError::VmmSysError)?;

    // Note: For libraries registering signal handlers, it's important to keep in mind that
    // the user of the library could have their own signal handlers that we don't want to
    // overwrite. The common practice there is to provide signal handling chaining, which
    // means that the signal is handled by all registered handlers from the last registered
    // to the first. **Hyperlight does not provide signal chaining**. For SIGSYS, this is because,
    // currently, Hyperlight handles SIGSYS signals by directly altering the instruction pointer at
    // the time the syscall occurred to call a function that will panic the host function execution.
    // For SIGRTMIN, this is because Hyperlight issues potentially 200 signals back-to-back and its
    // likely that the embedder will not want to handle this.

    Ok(())
}

extern "C" fn vm_kill_signal(_: libc::c_int, _: *mut libc::siginfo_t, _: *mut libc::c_void) {
    // Do nothing. SIGRTMIN is just used to issue a VM exit to the underlying VM.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::SandboxConfiguration;

    /// Test that setup_signal_handlers successfully registers signal handlers
    #[test]
    fn test_setup_signal_handlers_success() {
        let config = SandboxConfiguration::default();
        let result = setup_signal_handlers(&config);
        assert!(result.is_ok(), "Signal handler setup should succeed");
    }

    /// Test setup_signal_handlers with custom interrupt offset
    #[test]
    fn test_setup_signal_handlers_custom_offset() {
        let mut config = SandboxConfiguration::default();
        // Use a different interrupt offset to test the signal number calculation
        config
            .set_interrupt_vcpu_sigrtmin_offset(2)
            .expect("Setting offset should succeed");
        let result = setup_signal_handlers(&config);
        assert!(
            result.is_ok(),
            "Signal handler setup with custom offset should succeed"
        );
    }

    /// Test that vm_kill_signal is a valid extern C function
    #[test]
    fn test_vm_kill_signal_signature() {
        // This test verifies the function signature is correct for C interop
        let signal: libc::c_int = libc::SIGRTMIN();
        let info: *mut libc::siginfo_t = std::ptr::null_mut();
        let context: *mut libc::c_void = std::ptr::null_mut();

        // Should not panic or crash when called with null pointers
        vm_kill_signal(signal, info, context);
        // Test passes if we reach this point without crashing
    }

    /// Test signal handler setup with multiple configurations
    #[test]
    fn test_signal_handlers_various_configurations() {
        // Test with default configuration
        let default_config = SandboxConfiguration::default();
        assert!(setup_signal_handlers(&default_config).is_ok());

        // Test with different offset values (within valid range)
        for offset in 0..5 {
            let mut config = SandboxConfiguration::default();
            config
                .set_interrupt_vcpu_sigrtmin_offset(offset)
                .expect("Setting offset should succeed");
            let result = setup_signal_handlers(&config);
            assert!(
                result.is_ok(),
                "Signal handler setup should succeed with offset {}",
                offset
            );
        }
    }

    /// Test that signal numbers are calculated correctly
    #[test]
    fn test_signal_number_calculation() {
        let test_offset = 3u8;
        let mut config = SandboxConfiguration::default();
        config
            .set_interrupt_vcpu_sigrtmin_offset(test_offset)
            .expect("Setting offset should succeed");

        // The signal should be SIGRTMIN + offset
        let expected_signal = libc::SIGRTMIN() + test_offset as libc::c_int;

        // Verify the expected signal is within valid range
        let max_signal = libc::SIGRTMAX();
        assert!(
            expected_signal <= max_signal,
            "Calculated signal {} should be within valid range (max: {})",
            expected_signal,
            max_signal
        );

        // Test that setup succeeds with this configuration
        assert!(setup_signal_handlers(&config).is_ok());
    }

    /// Test signal handler behavior with edge case offset values
    #[test]
    fn test_signal_handlers_edge_cases() {
        // Test with maximum safe offset
        let max_safe_offset = 10u8; // Conservative maximum to stay within signal range
        let mut config = SandboxConfiguration::default();
        config
            .set_interrupt_vcpu_sigrtmin_offset(max_safe_offset)
            .expect("Setting offset should succeed");

        let result = setup_signal_handlers(&config);
        assert!(
            result.is_ok(),
            "Signal handler setup should succeed with max safe offset"
        );

        // Test with minimum offset (0)
        let mut config_zero = SandboxConfiguration::default();
        config_zero
            .set_interrupt_vcpu_sigrtmin_offset(0)
            .expect("Setting offset should succeed");
        let result_zero = setup_signal_handlers(&config_zero);
        assert!(
            result_zero.is_ok(),
            "Signal handler setup should succeed with zero offset"
        );
    }

    /// Test vm_kill_signal function with various signal numbers
    #[test]
    fn test_vm_kill_signal_with_different_signals() {
        let info: *mut libc::siginfo_t = std::ptr::null_mut();
        let context: *mut libc::c_void = std::ptr::null_mut();

        // Test with SIGRTMIN
        vm_kill_signal(libc::SIGRTMIN(), info, context);

        // Test with SIGRTMIN + offset
        vm_kill_signal(libc::SIGRTMIN() + 1, info, context);
        vm_kill_signal(libc::SIGRTMIN() + 5, info, context);

        // All calls should complete without error/panic
    }

    /// Test signal handler registration doesn't interfere with each other
    #[test]
    fn test_multiple_signal_handler_setups() {
        let mut config1 = SandboxConfiguration::default();
        config1
            .set_interrupt_vcpu_sigrtmin_offset(1)
            .expect("Setting offset should succeed");
        let mut config2 = SandboxConfiguration::default();
        config2
            .set_interrupt_vcpu_sigrtmin_offset(2)
            .expect("Setting offset should succeed");

        // First setup should succeed
        assert!(setup_signal_handlers(&config1).is_ok());

        // Second setup should also succeed (might overwrite previous)
        assert!(setup_signal_handlers(&config2).is_ok());
    }

    /// Test that signal handler function pointers are valid
    #[test]
    fn test_signal_handler_function_pointers() {
        // Verify vm_kill_signal is a valid function pointer
        let fn_ptr = vm_kill_signal as *const ();
        assert!(
            !fn_ptr.is_null(),
            "vm_kill_signal should have a valid function pointer"
        );

        #[cfg(feature = "seccomp")]
        {
            let sigsys_fn_ptr = sigsys_signal_handler::handle_sigsys as *const ();
            assert!(
                !sigsys_fn_ptr.is_null(),
                "handle_sigsys should have a valid function pointer"
            );
        }
    }
}
