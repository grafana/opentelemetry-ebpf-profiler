//go:build amd64 && symbliblink

package ffi

/*
#cgo LDFLAGS: target/x86_64-unknown-linux-musl/release/libsymblib_capi.a
*/
import "C"
