//! C FFI exports for integration with Go.
//!
//! This module provides C-compatible functions that can be called from Go
//! via CGO for proof conversion and witness generation.

use crate::verifier::{ProofConverter, VerifierConfig};
use crate::witness::{PcsConfig, WitnessInput};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

/// Error codes for FFI functions.
#[repr(C)]
pub enum FfiError {
    Success = 0,
    NullPointer = 1,
    InvalidUtf8 = 2,
    SerializationError = 3,
    IoError = 4,
}

/// Configuration passed from Go.
#[repr(C)]
pub struct FfiVerifierConfig {
    pub num_preprocessed_columns: u32,
    pub num_trace_columns: u32,
    pub num_interaction_columns: u32,
    pub log_trace_size: u32,
    pub pow_bits: u32,
    pub log_blowup_factor: u32,
    pub log_last_layer_deg: u32,
    pub num_queries: u32,
}

impl From<FfiVerifierConfig> for VerifierConfig {
    fn from(ffi: FfiVerifierConfig) -> Self {
        Self {
            num_preprocessed_columns: ffi.num_preprocessed_columns as usize,
            num_trace_columns: ffi.num_trace_columns as usize,
            num_interaction_columns: ffi.num_interaction_columns as usize,
            log_trace_size: ffi.log_trace_size,
            pcs_config: PcsConfig {
                pow_bits: ffi.pow_bits,
                log_blowup_factor: ffi.log_blowup_factor,
                log_last_layer_deg: ffi.log_last_layer_deg,
                num_queries: ffi.num_queries,
            },
        }
    }
}

/// Generate a mock witness and write to a file.
///
/// # Safety
///
/// The output_path must be a valid null-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn generate_mock_witness(
    config: FfiVerifierConfig,
    output_path: *const c_char,
) -> FfiError {
    if output_path.is_null() {
        return FfiError::NullPointer;
    }

    let path = match CStr::from_ptr(output_path).to_str() {
        Ok(s) => s,
        Err(_) => return FfiError::InvalidUtf8,
    };

    let verifier_config: VerifierConfig = config.into();
    let converter = ProofConverter::new(verifier_config);
    let witness = converter.create_mock_witness();

    match witness.write_to_file(path) {
        Ok(_) => FfiError::Success,
        Err(_) => FfiError::IoError,
    }
}

/// Generate a mock witness and return as JSON string.
///
/// # Safety
///
/// The caller must free the returned string using `free_string`.
#[no_mangle]
pub unsafe extern "C" fn generate_mock_witness_json(
    config: FfiVerifierConfig,
    output: *mut *mut c_char,
) -> FfiError {
    if output.is_null() {
        return FfiError::NullPointer;
    }

    let verifier_config: VerifierConfig = config.into();
    let converter = ProofConverter::new(verifier_config);
    let witness = converter.create_mock_witness();

    match witness.to_json() {
        Ok(json) => match CString::new(json) {
            Ok(cstr) => {
                *output = cstr.into_raw();
                FfiError::Success
            }
            Err(_) => FfiError::SerializationError,
        },
        Err(_) => FfiError::SerializationError,
    }
}

/// Read a witness from a JSON file.
///
/// # Safety
///
/// The input_path must be a valid null-terminated UTF-8 string.
/// The caller must free the returned string using `free_string`.
#[no_mangle]
pub unsafe extern "C" fn read_witness_file(
    input_path: *const c_char,
    output: *mut *mut c_char,
) -> FfiError {
    if input_path.is_null() || output.is_null() {
        return FfiError::NullPointer;
    }

    let path = match CStr::from_ptr(input_path).to_str() {
        Ok(s) => s,
        Err(_) => return FfiError::InvalidUtf8,
    };

    match WitnessInput::read_from_file(path) {
        Ok(witness) => match witness.to_json() {
            Ok(json) => match CString::new(json) {
                Ok(cstr) => {
                    *output = cstr.into_raw();
                    FfiError::Success
                }
                Err(_) => FfiError::SerializationError,
            },
            Err(_) => FfiError::SerializationError,
        },
        Err(_) => FfiError::IoError,
    }
}

/// Free a string allocated by this library.
///
/// # Safety
///
/// The pointer must have been returned by one of the functions in this module.
#[no_mangle]
pub unsafe extern "C" fn free_string(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

/// Get the version of this library.
#[no_mangle]
pub extern "C" fn get_version() -> *const c_char {
    static VERSION: &[u8] = b"0.1.0\0";
    VERSION.as_ptr() as *const c_char
}

// ============================================================================
// Real proof generation functions
// ============================================================================

/// Generate a simple AIR proof (proving_an_air) and return witness JSON.
///
/// # Safety
///
/// The caller must free the returned string using `free_string`.
#[no_mangle]
pub unsafe extern "C" fn generate_proving_an_air_witness(
    output: *mut *mut c_char,
) -> FfiError {
    if output.is_null() {
        return FfiError::NullPointer;
    }

    match crate::proof_generators::generate_proving_an_air() {
        Ok(witness) => match witness.to_json() {
            Ok(json) => match CString::new(json) {
                Ok(cstr) => {
                    *output = cstr.into_raw();
                    FfiError::Success
                }
                Err(_) => FfiError::SerializationError,
            },
            Err(_) => FfiError::SerializationError,
        },
        Err(_) => FfiError::IoError,
    }
}

/// Generate a LogUp proof (static_lookups) and return witness JSON.
///
/// # Safety
///
/// The caller must free the returned string using `free_string`.
#[no_mangle]
pub unsafe extern "C" fn generate_static_lookups_witness(
    output: *mut *mut c_char,
) -> FfiError {
    if output.is_null() {
        return FfiError::NullPointer;
    }

    match crate::proof_generators::generate_static_lookups() {
        Ok(witness) => match witness.to_json() {
            Ok(json) => match CString::new(json) {
                Ok(cstr) => {
                    *output = cstr.into_raw();
                    FfiError::Success
                }
                Err(_) => FfiError::SerializationError,
            },
            Err(_) => FfiError::SerializationError,
        },
        Err(_) => FfiError::IoError,
    }
}

// ============================================================================
// Circuit Definition Export Functions
// ============================================================================

/// Extract simple AIR circuit definition and return as JSON.
///
/// # Safety
///
/// The caller must free the returned string using `free_string`.
#[no_mangle]
pub unsafe extern "C" fn extract_simple_air_circuit_def(
    output: *mut *mut c_char,
) -> FfiError {
    if output.is_null() {
        return FfiError::NullPointer;
    }

    match crate::proof_generators::extract_simple_air_circuit_def() {
        Ok(circuit_def) => match circuit_def.to_json() {
            Ok(json) => match CString::new(json) {
                Ok(cstr) => {
                    *output = cstr.into_raw();
                    FfiError::Success
                }
                Err(_) => FfiError::SerializationError,
            },
            Err(_) => FfiError::SerializationError,
        },
        Err(_) => FfiError::IoError,
    }
}

/// Extract static lookups circuit definition and return as JSON.
///
/// # Safety
///
/// The caller must free the returned string using `free_string`.
#[no_mangle]
pub unsafe extern "C" fn extract_static_lookups_circuit_def(
    output: *mut *mut c_char,
) -> FfiError {
    if output.is_null() {
        return FfiError::NullPointer;
    }

    match crate::proof_generators::extract_static_lookups_circuit_def() {
        Ok(circuit_def) => match circuit_def.to_json() {
            Ok(json) => match CString::new(json) {
                Ok(cstr) => {
                    *output = cstr.into_raw();
                    FfiError::Success
                }
                Err(_) => FfiError::SerializationError,
            },
            Err(_) => FfiError::SerializationError,
        },
        Err(_) => FfiError::IoError,
    }
}
