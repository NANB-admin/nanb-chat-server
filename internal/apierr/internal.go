// Package apierr builds the APIErrors the services return for unexpected
// (non-domain) failures, so raw internal error text never reaches a client.
package apierr

import (
	"log"
	"runtime"
	"strings"

	"github.com/nanb/nanb-server/internal/proto"
)

// InternalMessage is the only text a client ever sees for an internal failure.
const InternalMessage = "internal error"

// Internal logs err server-side, tagged with the calling function, and returns
// an ErrCodeInternal APIError carrying a generic message. Use it wherever a
// store/S3/provider failure used to be returned as Message: err.Error() — that
// leaked pgx/SQL/driver text (table and constraint names, hostnames) to callers.
//
// The log line carries the operation and the error only; callers must not add
// account or device ids to the wrapped error beyond what it already contains.
func Internal(err error) proto.APIError {
	log.Printf("internal error in %s: %v", callerName(), err)
	return proto.APIError{Code: proto.ErrCodeInternal, Message: InternalMessage}
}

// callerName returns the short name of the function that called Internal.
func callerName() string {
	pc, _, _, ok := runtime.Caller(2)
	if !ok {
		return "unknown"
	}
	fn := runtime.FuncForPC(pc)
	if fn == nil {
		return "unknown"
	}
	name := fn.Name()
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	return name
}
