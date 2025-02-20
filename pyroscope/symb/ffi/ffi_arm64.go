//go:build arm64 && symbliblink

package ffi

/*
#cgo LDFLAGS: target/aarch64-unknown-linux-musl/release/libsymblib_capi.a
*/
import "C"
