package ffi

/*
#cgo CFLAGS: -I${SRCDIR}/..
#cgo darwin LDFLAGS: -L${SRCDIR}/../target/release -Wl,-rpath,${SRCDIR}/../target/release -lbdu_parser_ffi
#cgo linux LDFLAGS: -L${SRCDIR}/../target/release -Wl,-rpath,${SRCDIR}/../target/release -lbdu_parser_ffi
#include "bdu_parser_ffi.h"
#include <stdlib.h>
*/
import "C"

import "unsafe"

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

func Update(postgresURL string) string {
	postgresURLC := C.CString(postgresURL)
	defer C.free(unsafe.Pointer(postgresURLC))
	return takeCString(C.bdu_parser_update(postgresURLC))
}

func GenerateReports(postgresURL, sbomPath, reportName string, full bool) string {
	postgresURLC := C.CString(postgresURL)
	sbomPathC := C.CString(sbomPath)
	reportNameC := C.CString(reportName)
	defer C.free(unsafe.Pointer(postgresURLC))
	defer C.free(unsafe.Pointer(sbomPathC))
	defer C.free(unsafe.Pointer(reportNameC))

	return takeCString(C.bdu_parser_generate_reports(postgresURLC, sbomPathC, reportNameC, C.bool(full)))
}
