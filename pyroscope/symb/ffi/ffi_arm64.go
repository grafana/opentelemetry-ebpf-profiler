//go:build arm64

package ffi

/*
#cgo LDFLAGS: ${SRCDIR}/../../../target/aarch64-unknown-linux-musl/release/libsymblib_capi.a
*/
import "C"
