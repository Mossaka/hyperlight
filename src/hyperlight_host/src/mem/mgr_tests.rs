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

use crate::Result;

// These are simple tests to verify basic constants and functionality
// Most of the memory manager's functionality is internal and tested through integration

#[test]
fn test_stack_cookie_length() -> Result<()> {
    // Test that the stack cookie length constant has the expected value
    use super::mgr::STACK_COOKIE_LEN;

    assert_eq!(STACK_COOKIE_LEN, 16);

    Ok(())
}

#[cfg(feature = "init-paging")]
#[test]
fn test_paging_constants() -> Result<()> {
    // Test that paging constants have expected bit patterns
    use super::mgr::{AMOUNT_OF_MEMORY_PER_PT, PAGE_NX, PAGE_PRESENT, PAGE_RW, PAGE_USER};

    // Verify basic paging flags
    assert_eq!(PAGE_PRESENT, 1);
    assert_eq!(PAGE_RW, 2);
    assert_eq!(PAGE_USER, 4);
    assert_eq!(PAGE_NX, 1u64 << 63);

    // Verify memory per page table is 2MB
    assert_eq!(AMOUNT_OF_MEMORY_PER_PT, 0x200_000);

    Ok(())
}

#[test]
fn test_basic_configuration_creation() -> Result<()> {
    // Just verify we can create a default configuration without panic
    let _config = crate::sandbox::config::SandboxConfiguration::default();

    // If we got here, configuration creation succeeded
    assert!(true);

    Ok(())
}
