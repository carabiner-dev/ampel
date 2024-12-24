package dsse

import (
	sigstoreProtoDSSE "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
)

type Envelope struct {
	sigstoreProtoDSSE.Envelope
}
