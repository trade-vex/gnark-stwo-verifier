// Package ffi provides CGO bindings to the Rust stwo-gnark library.
package ffi

/*
#cgo LDFLAGS: -L${SRCDIR}/../rust/target/release -lstwo_gnark -ldl -lpthread -lm
#cgo CFLAGS: -I${SRCDIR}/../rust

#include <stdlib.h>

// FFI error codes
typedef enum {
    FFI_SUCCESS = 0,
    FFI_NULL_POINTER = 1,
    FFI_INVALID_UTF8 = 2,
    FFI_SERIALIZATION_ERROR = 3,
    FFI_IO_ERROR = 4,
} FfiError;

// Function declarations
extern FfiError generate_proving_an_air_witness(char** output);
extern FfiError generate_static_lookups_witness(char** output);
extern void free_string(char* s);
extern const char* get_version();
*/
import "C"

import (
	"errors"
	"unsafe"
)

// FfiError represents error codes from the Rust FFI.
type FfiError int

const (
	FfiSuccess            FfiError = 0
	FfiNullPointer        FfiError = 1
	FfiInvalidUtf8        FfiError = 2
	FfiSerializationError FfiError = 3
	FfiIoError            FfiError = 4
)

func (e FfiError) Error() string {
	switch e {
	case FfiSuccess:
		return "success"
	case FfiNullPointer:
		return "null pointer"
	case FfiInvalidUtf8:
		return "invalid UTF-8"
	case FfiSerializationError:
		return "serialization error"
	case FfiIoError:
		return "I/O error"
	default:
		return "unknown error"
	}
}

// GenerateProvingAnAirWitness generates a simple AIR proof and returns the witness JSON.
func GenerateProvingAnAirWitness() (string, error) {
	var output *C.char
	result := C.generate_proving_an_air_witness(&output)
	if result != C.FFI_SUCCESS {
		return "", errors.New("failed to generate proving_an_air witness: " + FfiError(result).Error())
	}
	if output == nil {
		return "", errors.New("null output from FFI")
	}
	defer C.free_string(output)
	return C.GoString(output), nil
}

// GenerateStaticLookupsWitness generates a LogUp proof and returns the witness JSON.
func GenerateStaticLookupsWitness() (string, error) {
	var output *C.char
	result := C.generate_static_lookups_witness(&output)
	if result != C.FFI_SUCCESS {
		return "", errors.New("failed to generate static_lookups witness: " + FfiError(result).Error())
	}
	if output == nil {
		return "", errors.New("null output from FFI")
	}
	defer C.free_string(output)
	return C.GoString(output), nil
}

// GetVersion returns the version of the Rust library.
func GetVersion() string {
	return C.GoString(C.get_version())
}

// Ensure unsafe is used (required for CGO)
var _ = unsafe.Pointer(nil)
