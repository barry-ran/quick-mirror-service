package peerloom

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/barry-ran/quick-mirror-service/internal/identity"
)

var ErrRenewalRejected = errors.New("PEERLOOM_RENEWAL_REJECTED")
var ErrRenewalJournalConflict = errors.New("PEERLOOM_RENEWAL_JOURNAL_CONFLICT")
var ErrRenewalUnavailable = errors.New("PEERLOOM_RENEWAL_UNAVAILABLE")
var ErrRenewalDeferred = errors.New("PEERLOOM_RENEWAL_DEFERRED")

type ServiceCredentialInfo struct {
	RenewalEnabled       bool      `json:"renewal_enabled"`
	SubjectID            string    `json:"subject_id"`
	TenantID             string    `json:"tenant_id"`
	CredentialID         string    `json:"credential_id"`
	Scope                string    `json:"scope"`
	ExpiresAt            time.Time `json:"expires_at"`
	RenewAfter           time.Time `json:"renew_after"`
	EffectiveAcceptUntil time.Time `json:"effective_accept_until"`
}
type RenewalResult struct {
	ServiceCredentialInfo
	ServiceCredential    string    `json:"service_credential"`
	PreviousCredentialID string    `json:"previous_credential_id"`
	PreviousAcceptUntil  time.Time `json:"previous_accept_until"`
}

// RenewalAPI authenticates the service itself, never an end-user supplied identity.
type RenewalAPI interface {
	Self(context.Context, string) (ServiceCredentialInfo, error)
	Renew(context.Context, string, string) (RenewalResult, error)
}
type renewalClient struct {
	origin string
	tenant string
	client *http.Client
}

func NewRenewalClient(config IdentityConfig, client *http.Client) (RenewalAPI, error) {
	c, err := NewIdentityClient(config, client)
	if err != nil {
		return nil, err
	}
	return &renewalClient{strings.TrimSuffix(c.endpoint, "/v1/device-self"), c.tenantID, c.client}, nil
}
func (c *renewalClient) request(ctx context.Context, secret, operation, path string, out any) error {
	if !visibleASCII(secret, 1, 512) {
		return ErrCredentialUnavailable
	}
	method := http.MethodGet
	var body io.Reader
	if operation != "" {
		method = http.MethodPost
		body = bytes.NewBufferString("{}")
	}
	req, err := http.NewRequestWithContext(ctx, method, c.origin+path, body)
	if err != nil {
		return ErrCredentialUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Accept", "application/json")
	if operation != "" {
		req.Header.Set("Idempotency-Key", operation)
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return ErrCredentialUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return ErrRenewalRejected
	}
	if resp.StatusCode == 409 {
		data, err := io.ReadAll(io.LimitReader(resp.Body, (16<<10)+1))
		var problem struct {
			Code string `json:"code"`
		}
		if err != nil || len(data) > 16<<10 || json.Unmarshal(data, &problem) != nil {
			return ErrCredentialUnavailable
		}
		switch problem.Code {
		case "RENEWAL_TOO_EARLY":
			return ErrRenewalDeferred
		case "RENEWAL_ALREADY_EXISTS":
			return ErrRenewalJournalConflict
		case "RENEWAL_UNAVAILABLE":
			return ErrRenewalUnavailable
		default:
			return ErrCredentialUnavailable
		}
	}
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return ErrCredentialUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, (16<<10)+1))
	if err != nil || len(data) > 16<<10 || json.Unmarshal(data, out) != nil {
		return ErrCredentialUnavailable
	}
	return nil
}
func validServiceInfo(v ServiceCredentialInfo, tenant string) bool {
	_, a := identity.NormalizeUUID(v.SubjectID)
	_, b := identity.NormalizeUUID(v.CredentialID)
	return a && b && v.TenantID == tenant && (v.Scope == "read" || v.Scope == "admin") && !v.ExpiresAt.IsZero() && !v.RenewAfter.IsZero() && v.RenewAfter.Before(v.ExpiresAt) && !v.EffectiveAcceptUntil.IsZero() && !v.EffectiveAcceptUntil.After(v.ExpiresAt)
}
func (c *renewalClient) Self(ctx context.Context, secret string) (ServiceCredentialInfo, error) {
	var v ServiceCredentialInfo
	err := c.request(ctx, secret, "", "/v1/service-credentials/self", &v)
	if err == nil && !validServiceInfo(v, c.tenant) {
		err = ErrCredentialUnavailable
	}
	return v, err
}
func (c *renewalClient) Renew(ctx context.Context, secret, operation string) (RenewalResult, error) {
	var v RenewalResult
	if _, ok := identity.NormalizeUUID(operation); !ok {
		return v, ErrCredentialUnavailable
	}
	err := c.request(ctx, secret, operation, "/v1/service-credentials/renew", &v)
	if err == nil && (!visibleASCII(v.ServiceCredential, 1, 512) || !validServiceInfo(v.ServiceCredentialInfo, c.tenant) || v.PreviousCredentialID == "" || v.PreviousAcceptUntil.IsZero()) {
		err = ErrCredentialUnavailable
	}
	return v, err
}
