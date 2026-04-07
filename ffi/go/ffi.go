package ffi

/*
#cgo CFLAGS: -I${SRCDIR}/..
#cgo darwin LDFLAGS: -L${SRCDIR}/../target/release -Wl,-rpath,${SRCDIR}/../target/release -lbdu_parser_ffi
#cgo linux LDFLAGS: -L${SRCDIR}/../target/release -Wl,-rpath,${SRCDIR}/../target/release -lbdu_parser_ffi
#include "bdu_parser_ffi.h"
*/
import "C"

func takeCString(ptr *C.char) string {
	if ptr == nil {
		return ""
	}
	defer C.bdu_parser_free_string(ptr)
	return C.GoString(ptr)
}

func Version() string {
	return takeCString(C.bdu_parser_version())
}

func UpdateNil() string {
	return takeCString(C.bdu_parser_update(nil))
}
