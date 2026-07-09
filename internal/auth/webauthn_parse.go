package auth

import (
	"bytes"
	"io"

	"github.com/go-webauthn/webauthn/protocol"
)

// The protocol package exposes ParseCredentialCreationResponseBody /
// ParseCredentialRequestResponseBody. Isolate them here so webauthn.go stays
// focused on the flow.

func parseCredentialCreation(body []byte) (*protocol.ParsedCredentialCreationData, error) {
	return protocol.ParseCredentialCreationResponseBody(readerNoClose(body))
}

func parseCredentialAssertion(body []byte) (*protocol.ParsedCredentialAssertionData, error) {
	return protocol.ParseCredentialRequestResponseBody(readerNoClose(body))
}

// readerNoClose wraps a byte slice as an io.Reader so we can pass it to the
// library's ParseXxxResponseBody helpers.
func readerNoClose(b []byte) io.Reader { return bytes.NewReader(b) }
