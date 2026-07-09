package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/TrippingKelsea/nebula-starcaller/internal/config"
	"github.com/TrippingKelsea/nebula-starcaller/internal/domain"
	"github.com/TrippingKelsea/nebula-starcaller/internal/store"
)

// WebAuthnService wraps go-webauthn with our Store-backed credential list.
type WebAuthnService struct {
	rp    *webauthn.WebAuthn
	store store.Store
}

func NewWebAuthnService(cfg config.WebAuthn, s store.Store) (*WebAuthnService, error) {
	rp, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPDisplayName,
		RPOrigins:     cfg.RPOrigins,
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn: %w", err)
	}
	return &WebAuthnService{rp: rp, store: s}, nil
}

// wauser adapts domain.User + stored credentials to webauthn.User.
type wauser struct {
	id          []byte
	username    string
	displayName string
	credentials []webauthn.Credential
}

func (u *wauser) WebAuthnID() []byte                         { return u.id }
func (u *wauser) WebAuthnName() string                       { return u.username }
func (u *wauser) WebAuthnDisplayName() string                { return u.displayName }
func (u *wauser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func (s *WebAuthnService) makeUser(ctx context.Context, u domain.User) (*wauser, error) {
	creds, err := s.store.ListWebAuthnCredentials(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	wcreds := make([]webauthn.Credential, 0, len(creds))
	for _, c := range creds {
		wcreds = append(wcreds, webauthn.Credential{
			ID:              c.CredentialID,
			PublicKey:       c.PublicKey,
			AttestationType: c.AttestType,
			Authenticator: webauthn.Authenticator{
				AAGUID:       c.AAGUID,
				SignCount:    c.SignCount,
				CloneWarning: c.CloneWarning,
			},
		})
	}
	displayName := u.Username
	if u.Email != "" {
		displayName = u.Email
	}
	return &wauser{
		id: []byte(u.ID), username: u.Username, displayName: displayName,
		credentials: wcreds,
	}, nil
}

// BeginRegistration produces the credential-creation options JSON to send
// to the browser and a serialized session blob to persist server-side.
func (s *WebAuthnService) BeginRegistration(ctx context.Context, u domain.User) ([]byte, []byte, error) {
	wu, err := s.makeUser(ctx, u)
	if err != nil {
		return nil, nil, err
	}
	opts, session, err := s.rp.BeginRegistration(wu)
	if err != nil {
		return nil, nil, err
	}
	optJSON, err := json.Marshal(opts)
	if err != nil {
		return nil, nil, err
	}
	sessJSON, err := json.Marshal(session)
	if err != nil {
		return nil, nil, err
	}
	return optJSON, sessJSON, nil
}

// FinishRegistration validates the browser's response and persists the credential.
func (s *WebAuthnService) FinishRegistration(ctx context.Context, u domain.User, sessionBlob []byte, responseBody []byte, credName string) error {
	var session webauthn.SessionData
	if err := json.Unmarshal(sessionBlob, &session); err != nil {
		return err
	}
	wu, err := s.makeUser(ctx, u)
	if err != nil {
		return err
	}
	parsed, err := parseCredentialCreation(responseBody)
	if err != nil {
		return err
	}
	cred, err := s.rp.CreateCredential(wu, session, parsed)
	if err != nil {
		return err
	}
	return s.store.AddWebAuthnCredential(ctx, domain.WebAuthnCredential{
		ID: uuid.NewString(), UserID: u.ID,
		CredentialID: cred.ID, PublicKey: cred.PublicKey,
		AttestType: cred.AttestationType,
		AAGUID:     cred.Authenticator.AAGUID,
		SignCount:  cred.Authenticator.SignCount,
		Name:       credName,
		CreatedAt:  time.Now().UTC(),
	})
}

// BeginLogin returns credential-request options + a session blob.
func (s *WebAuthnService) BeginLogin(ctx context.Context, u domain.User) ([]byte, []byte, error) {
	wu, err := s.makeUser(ctx, u)
	if err != nil {
		return nil, nil, err
	}
	if len(wu.credentials) == 0 {
		return nil, nil, errors.New("webauthn: user has no credentials")
	}
	opts, session, err := s.rp.BeginLogin(wu)
	if err != nil {
		return nil, nil, err
	}
	optJSON, err := json.Marshal(opts)
	if err != nil {
		return nil, nil, err
	}
	sessJSON, err := json.Marshal(session)
	if err != nil {
		return nil, nil, err
	}
	return optJSON, sessJSON, nil
}

// FinishLogin validates the login response and updates sign-count bookkeeping.
func (s *WebAuthnService) FinishLogin(ctx context.Context, u domain.User, sessionBlob []byte, responseBody []byte) error {
	var session webauthn.SessionData
	if err := json.Unmarshal(sessionBlob, &session); err != nil {
		return err
	}
	wu, err := s.makeUser(ctx, u)
	if err != nil {
		return err
	}
	parsed, err := parseCredentialAssertion(responseBody)
	if err != nil {
		return err
	}
	cred, err := s.rp.ValidateLogin(wu, session, parsed)
	if err != nil {
		return err
	}
	creds, err := s.store.ListWebAuthnCredentials(ctx, u.ID)
	if err != nil {
		return err
	}
	for _, c := range creds {
		if string(c.CredentialID) == string(cred.ID) {
			return s.store.UpdateWebAuthnSignCount(ctx, c.ID, cred.Authenticator.SignCount)
		}
	}
	return errors.New("webauthn: credential used to log in was not stored (this should not happen)")
}
