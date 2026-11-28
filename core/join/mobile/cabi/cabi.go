//go:build cgo && (android || ios || hogman_mobile_cabi)

package main

/*
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

typedef int (*hogman_protect_fn)(int fd, void *user_data);
typedef int (*hogman_reconfig_fn)(const char *reconfig_json, void *user_data);

static inline int hogman_call_protect(hogman_protect_fn fn, int fd, void *user_data) {
	if (fn == NULL) {
		return 0;
	}
	return fn(fd, user_data);
}

static inline int hogman_call_reconfig(hogman_reconfig_fn fn, const char *json, void *user_data) {
	if (fn == NULL) {
		return -1;
	}
	return fn(json, user_data);
}
*/
import "C"

import (
	"encoding/json"
	"errors"
	"fmt"
	"unsafe"

	"hogman/join/mobile"
)

var defaultCtrl = mobile.NewController()

func main() {}

func cStr(p *C.char) string {
	if p == nil {
		return ""
	}
	return C.GoString(p)
}

// copyStateKey copies a raw byte buffer from C into a mutable Go slice and
// enforces exact 32-byte length (D-56: reject invalid length, never truncate).
func copyStateKey(ptr *C.uint8_t, n C.size_t) ([]byte, error) {
	if ptr == nil || n != C.size_t(mobile.StateKeyLen) {
		return nil, fmt.Errorf("state_key must be exactly %d bytes (got %d)", mobile.StateKeyLen, uint64(n))
	}
	src := unsafe.Slice((*byte)(unsafe.Pointer(ptr)), mobile.StateKeyLen)
	key := make([]byte, mobile.StateKeyLen)
	copy(key, src)
	return key, nil
}

func errCString(err error) *C.char {
	b, _ := json.Marshal(struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}{OK: false, Error: err.Error()})
	return C.CString(string(b))
}

//export hogman_parse_link
func hogman_parse_link(rawLink *C.char) *C.char {
	return C.CString(defaultCtrl.ParseLinkJSON(cStr(rawLink)))
}

//export hogman_join
func hogman_join(
	dataDir *C.char,
	stateKey *C.uint8_t,
	stateKeyLen C.size_t,
	rawLink *C.char,
	handle *C.char,
	deviceName *C.char,
	controlCAPEM *C.char,
) *C.char {
	key, err := copyStateKey(stateKey, stateKeyLen)
	if err != nil {
		return errCString(err)
	}
	defer clear(key)
	return C.CString(defaultCtrl.JoinJSON(
		cStr(dataDir),
		key,
		cStr(rawLink),
		cStr(handle),
		cStr(deviceName),
		cStr(controlCAPEM),
	))
}

//export hogman_list_pens
func hogman_list_pens(dataDir *C.char) *C.char {
	return C.CString(defaultCtrl.ListPensJSON(cStr(dataDir)))
}

//export hogman_start_tunnel
func hogman_start_tunnel(
	dataDir *C.char,
	stateKey *C.uint8_t,
	stateKeyLen C.size_t,
	zone *C.char,
	mtu C.int,
	upstreamDNSJSON *C.char,
	protectFn C.hogman_protect_fn,
	reconfigFn C.hogman_reconfig_fn,
	userData unsafe.Pointer,
) *C.char {
	key, err := copyStateKey(stateKey, stateKeyLen)
	if err != nil {
		return errCString(err)
	}
	defer clear(key)

	cb := mobile.TunnelCallbacks{}
	if protectFn != nil {
		cb.ProtectFD = func(fd int) error {
			rc := int(C.hogman_call_protect(protectFn, C.int(fd), userData))
			if rc != 0 {
				return errors.New("platform protect(fd) failed")
			}
			return nil
		}
	}
	if reconfigFn != nil {
		cb.ReconfigVPN = func(cfg mobile.TunnelReconfig) int {
			b, err := json.Marshal(cfg)
			if err != nil {
				return -2
			}
			cs := C.CString(string(b))
			defer C.free(unsafe.Pointer(cs))
			return int(C.hogman_call_reconfig(reconfigFn, cs, userData))
		}
	}
	return C.CString(defaultCtrl.StartTunnelJSON(
		cStr(dataDir),
		key,
		cStr(zone),
		int(mtu),
		cStr(upstreamDNSJSON),
		cb,
	))
}

//export hogman_update_network
func hogman_update_network(upstreamDNSJSON *C.char, linkChanged C.int) *C.char {
	return C.CString(defaultCtrl.UpdateNetworkJSON(cStr(upstreamDNSJSON), linkChanged != 0))
}

//export hogman_status
func hogman_status() *C.char {
	return C.CString(defaultCtrl.StatusJSON())
}

//export hogman_stop_tunnel
func hogman_stop_tunnel() *C.char {
	return C.CString(defaultCtrl.StopTunnelJSON())
}

//export hogman_leave
func hogman_leave(
	dataDir *C.char,
	stateKey *C.uint8_t,
	stateKeyLen C.size_t,
	zone *C.char,
	force C.int,
) *C.char {
	key, err := copyStateKey(stateKey, stateKeyLen)
	if err != nil {
		return errCString(err)
	}
	defer clear(key)
	return C.CString(defaultCtrl.LeaveJSON(cStr(dataDir), key, cStr(zone), force != 0))
}

//export hogman_free
func hogman_free(ptr *C.char) {
	if ptr != nil {
		C.free(unsafe.Pointer(ptr))
	}
}
