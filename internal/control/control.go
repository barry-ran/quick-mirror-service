// Package control owns business control intents, not Peerloom transport state.
package control

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/barry-ran/quick-mirror-service/internal/catalog"
	"math"
	"strconv"

	"github.com/barry-ran/quick-mirror-service/internal/identity"
	"github.com/barry-ran/quick-mirror-service/internal/peerloom"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/001_control.sql
var migration string

type Error struct {
	Code   string
	Status int
}

func (e *Error) Error() string           { return e.Code }
func fail(code string, status int) error { return &Error{code, status} }

var errUnknown = fail("UNKNOWN", 410)

type Upstream interface {
	ReplayDomain() string
	CreateGrant(context.Context, string, string, string) (peerloom.ControlGrant, error)
	GetGrant(context.Context, string) (peerloom.ControlGrant, error)
	RevokeGrant(context.Context, string, string) error
	GetSession(context.Context, string) (peerloom.ControlSession, error)
	GetDevice(context.Context, string) (peerloom.ControlDevice, error)
}
type Intent struct {
	ID                                  string `json:"intent_id"`
	Target                              string `json:"device_uuid"`
	Owner                               string `json:"owner_pc_uuid"`
	Generation                          string `json:"business_generation"`
	Revision                            string `json:"revision"`
	State                               string `json:"state"`
	Outcome                             string `json:"operation_outcome"`
	Session                             string `json:"session_id,omitempty"`
	DrainToken                          string `json:"drain_token,omitempty"`
	CloseReason                         string `json:"close_reason,omitempty"`
	grant, createKey, revokeKey, domain string
	runtimeBoot                         string
	runtimeHash                         []byte
	dispatched, revoked                 bool
	expired                             bool
}
type Store struct {
	pool                     *pgxpool.Pool
	scope, tenant, mobileApp string
	upstream                 Upstream
}

func NewStore(pool *pgxpool.Pool, scope, tenant, mobileApp string, u Upstream) (*Store, error) {
	scope, a := identity.NormalizeUUID(scope)
	tenant, b := identity.NormalizeUUID(tenant)
	mobileApp, c := identity.NormalizeUUID(mobileApp)
	if pool == nil || !a || !b || !c || u == nil || u.ReplayDomain() == "" {
		return nil, fail("INVALID_CONFIGURATION", 500)
	}
	return &Store{pool, scope, tenant, mobileApp, u}, nil
}
func (s *Store) Migrate(ctx context.Context) error { _, e := s.pool.Exec(ctx, migration); return e }
func uuid() (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}
func canonical(v string) (string, error) {
	v, ok := identity.NormalizeUUID(v)
	if !ok {
		return "", fail("INVALID_INPUT", 400)
	}
	return v, nil
}
func (s *Store) principal(p identity.Principal) (identity.Principal, error) {
	var e error
	p.DeviceID, e = canonical(p.DeviceID)
	if e != nil {
		return p, identity.ErrForbidden
	}
	tenant, ok := identity.NormalizeUUID(p.TenantID)
	if !ok || tenant != s.tenant || (p.Role != identity.PC && p.Role != identity.Mobile) {
		return p, identity.ErrForbidden
	}
	return p, nil
}
func (s *Store) begin(ctx context.Context) (pgx.Tx, error) {
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return nil, e
	}
	// One short business serialization lock per scope. No network operation holds it.
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "qm-control:"+s.scope); e != nil {
		tx.Rollback(ctx)
		return nil, e
	}
	return tx, nil
}

const columns = `id::text,target_uuid::text,owner_uuid::text,generation::text,revision::text,state,outcome,
COALESCE(session_id::text,''),COALESCE(drain_token::text,''),COALESCE(close_reason,''),COALESCE(grant_id::text,''),create_key::text,revoke_key::text,replay_domain,dispatched,revoked,
COALESCE(terminal_at+interval '24 hours'<=clock_timestamp(),false),runtime_boot::text,runtime_hash`

type scanner interface{ Scan(...any) error }

func scan(row scanner) (Intent, error) {
	var i Intent
	e := row.Scan(&i.ID, &i.Target, &i.Owner, &i.Generation, &i.Revision, &i.State, &i.Outcome, &i.Session, &i.DrainToken, &i.CloseReason, &i.grant, &i.createKey, &i.revokeKey, &i.domain, &i.dispatched, &i.revoked, &i.expired, &i.runtimeBoot, &i.runtimeHash)
	return i, e
}
func (s *Store) load(ctx context.Context, tx pgx.Tx, id string) (Intent, error) {
	i, e := scan(tx.QueryRow(ctx, "SELECT "+columns+" FROM qm_control_intents WHERE service_scope=$1 AND id=$2 FOR UPDATE", s.scope, id))
	if errors.Is(e, pgx.ErrNoRows) {
		return i, fail("INTENT_NOT_FOUND", 404)
	}
	return i, e
}
func visible(i Intent, p identity.Principal) Intent {
	if p.Role != identity.Mobile {
		i.DrainToken = ""
	}
	return i
}
func allowed(i Intent, p identity.Principal) bool {
	return (p.Role == identity.PC && p.DeviceID == i.Owner) || (p.Role == identity.Mobile && p.DeviceID == i.Target)
}
func hash(v any) []byte { b, _ := json.Marshal(v); h := sha256.Sum256(b); return h[:] }
func (s *Store) replay(ctx context.Context, tx pgx.Tx, p identity.Principal, op, key string, body any) (Intent, bool, error) {
	var id string
	var old []byte
	e := tx.QueryRow(ctx, `SELECT intent_id::text,request_hash FROM qm_control_commands WHERE service_scope=$1 AND principal_uuid=$2 AND operation=$3 AND command_id=$4`, s.scope, p.DeviceID, op, key).Scan(&id, &old)
	if errors.Is(e, pgx.ErrNoRows) {
		return Intent{}, false, nil
	}
	if e != nil {
		return Intent{}, false, e
	}
	if string(old) != string(hash(body)) {
		return Intent{}, true, fail("IDEMPOTENCY_CONFLICT", 409)
	}
	i, e := s.load(ctx, tx, id)
	if e == nil && i.expired {
		e = errUnknown
	}
	return i, true, e
}
func (s *Store) record(ctx context.Context, tx pgx.Tx, p identity.Principal, op, key string, body any, id string) error {
	_, e := tx.Exec(ctx, `INSERT INTO qm_control_commands(service_scope,principal_uuid,operation,command_id,request_hash,intent_id)VALUES($1,$2,$3,$4,$5,$6)`, s.scope, p.DeviceID, op, key, hash(body), id)
	return e
}
func bump(i Intent) error {
	v, e := strconv.ParseInt(i.Revision, 10, 64)
	if e != nil || v == math.MaxInt64 {
		return fail("RESOURCE_EXHAUSTED", 503)
	}
	return nil
}
func (s *Store) finish(ctx context.Context, tx pgx.Tx, id, state string) error {
	_, e := tx.Exec(ctx, `UPDATE qm_control_intents SET state=$3,outcome='confirmed',terminal_at=clock_timestamp(),revision=revision+1 WHERE service_scope=$1 AND id=$2 AND revision<9223372036854775807`, s.scope, id, state)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `UPDATE qm_control_slots SET active_intent=NULL WHERE service_scope=$1 AND active_intent=$2`, s.scope, id)
	return e
}
func (s *Store) Get(ctx context.Context, p identity.Principal, id string) (Intent, error) {
	p, e := s.principal(p)
	if e != nil {
		return Intent{}, e
	}
	id, e = canonical(id)
	if e != nil {
		return Intent{}, e
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return Intent{}, e
	}
	defer tx.Rollback(ctx)
	i, e := s.load(ctx, tx, id)
	if e != nil {
		return i, e
	}
	if !allowed(i, p) {
		return Intent{}, fail("INTENT_NOT_FOUND", 404)
	}
	if i.expired {
		return Intent{}, errUnknown
	}
	return visible(i, p), nil
}
func (s *Store) Current(ctx context.Context, p identity.Principal) (*Intent, error) {
	p, e := s.principal(p)
	if e != nil {
		return nil, e
	}
	if p.Role != identity.Mobile {
		return nil, identity.ErrForbidden
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(ctx)
	var id string
	e = tx.QueryRow(ctx, `SELECT active_intent::text FROM qm_control_slots WHERE service_scope=$1 AND target_uuid=$2 AND active_intent IS NOT NULL`, s.scope, p.DeviceID).Scan(&id)
	if errors.Is(e, pgx.ErrNoRows) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	i, e := s.load(ctx, tx, id)
	return &i, e
}
func (s *Store) ByCommand(ctx context.Context, p identity.Principal, key string) (Intent, error) {
	p, e := s.principal(p)
	if e != nil {
		return Intent{}, e
	}
	if p.Role != identity.PC {
		return Intent{}, identity.ErrForbidden
	}
	key, e = canonical(key)
	if e != nil {
		return Intent{}, e
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return Intent{}, e
	}
	defer tx.Rollback(ctx)
	var id string
	e = tx.QueryRow(ctx, `SELECT intent_id::text FROM qm_control_commands WHERE service_scope=$1 AND principal_uuid=$2 AND operation='create' AND command_id=$3`, s.scope, p.DeviceID, key).Scan(&id)
	if errors.Is(e, pgx.ErrNoRows) {
		return Intent{}, errUnknown
	}
	if e != nil {
		return Intent{}, e
	}
	i, e := s.load(ctx, tx, id)
	if e == nil && i.expired {
		e = errUnknown
	}
	return visible(i, p), e
}
func (s *Store) Create(ctx context.Context, p identity.Principal, target, key string) (Intent, bool, error) {
	p, e := s.principal(p)
	if e != nil {
		return Intent{}, false, e
	}
	if p.Role != identity.PC {
		return Intent{}, false, identity.ErrForbidden
	}
	target, e = canonical(target)
	if e != nil {
		return Intent{}, false, e
	}
	key, e = canonical(key)
	if e != nil {
		return Intent{}, false, e
	}
	body := []string{target, "default"}
	// A replay never depends on the current target presence.
	tx, e := s.begin(ctx)
	if e != nil {
		return Intent{}, false, e
	}
	old, found, e := s.replay(ctx, tx, p, "create", key, body)
	tx.Rollback(ctx)
	if found || e != nil {
		return visible(old, p), false, e
	}
	d, e := s.upstream.GetDevice(ctx, target)
	if errors.Is(e, peerloom.ErrDeviceNotFound) {
		return Intent{}, false, fail("DEVICE_NOT_FOUND", 404)
	}
	if e != nil {
		return Intent{}, false, identity.ErrUnavailable
	}
	if d.ID != target || d.TenantID != s.tenant || d.ApplicationID != s.mobileApp || d.Status != "active" {
		return Intent{}, false, fail("DEVICE_NOT_FOUND", 404)
	}
	if d.Online == nil {
		return Intent{}, false, identity.ErrUnavailable
	}
	if !*d.Online {
		return Intent{}, false, fail("DEVICE_OFFLINE", 409)
	}
	tx, e = s.begin(ctx)
	if e != nil {
		return Intent{}, false, e
	}
	defer tx.Rollback(ctx)
	old, found, e = s.replay(ctx, tx, p, "create", key, body)
	if found || e != nil {
		return visible(old, p), false, e
	}
	_, e = tx.Exec(ctx, `INSERT INTO qm_control_slots(service_scope,target_uuid)VALUES($1,$2)ON CONFLICT DO NOTHING`, s.scope, target)
	if e != nil {
		return Intent{}, false, e
	}
	var generation int64
	var active *string
	e = tx.QueryRow(ctx, `SELECT generation,active_intent::text FROM qm_control_slots WHERE service_scope=$1 AND target_uuid=$2 FOR UPDATE`, s.scope, target).Scan(&generation, &active)
	if e != nil {
		return Intent{}, false, e
	}
	if active != nil {
		return Intent{}, false, fail("DEVICE_OCCUPIED", 409)
	}
	if generation == math.MaxInt64 {
		return Intent{}, false, fail("RESOURCE_EXHAUSTED", 503)
	}
	var boot string
	var proofHash []byte
	e = tx.QueryRow(ctx, `SELECT boot_id::text,runtime_proof_hash FROM qm_device_catalog WHERE service_scope=$1 AND device_uuid=$2 AND boot_id IS NOT NULL AND runtime_proof_hash IS NOT NULL FOR SHARE`, s.scope, target).Scan(&boot, &proofHash)
	if errors.Is(e, pgx.ErrNoRows) {
		return Intent{}, false, fail("RUNTIME_NOT_READY", 409)
	}
	if e != nil {
		return Intent{}, false, e
	}
	if len(proofHash) != 32 {
		return Intent{}, false, fail("RUNTIME_NOT_READY", 409)
	}
	id, e := uuid()
	if e != nil {
		return Intent{}, false, e
	}
	createKey, e := uuid()
	if e != nil {
		return Intent{}, false, e
	}
	revokeKey, e := uuid()
	if e != nil {
		return Intent{}, false, e
	}
	_, e = tx.Exec(ctx, `INSERT INTO qm_control_intents(service_scope,id,target_uuid,owner_uuid,generation,state,outcome,create_key,revoke_key,replay_domain,runtime_boot,runtime_hash)VALUES($1,$2,$3,$4,$5,'reserving','pending',$6,$7,$8,$9,$10)`, s.scope, id, target, p.DeviceID, generation+1, createKey, revokeKey, s.upstream.ReplayDomain(), boot, proofHash)
	if e != nil {
		return Intent{}, false, e
	}
	_, e = tx.Exec(ctx, `UPDATE qm_control_slots SET active_intent=$3,generation=$4 WHERE service_scope=$1 AND target_uuid=$2`, s.scope, target, id, generation+1)
	if e != nil {
		return Intent{}, false, e
	}
	if e = s.record(ctx, tx, p, "create", key, body, id); e != nil {
		return Intent{}, false, e
	}
	if e = tx.Commit(ctx); e != nil {
		return Intent{}, false, e
	}
	// Dispatch is claimed durably before network I/O. A lost outcome is never re-created.
	if e = s.dispatch(ctx, id); e != nil {
		return Intent{}, true, e
	}
	i, e := s.Get(ctx, p, id)
	return i, true, e
}
func (s *Store) dispatch(ctx context.Context, id string) error {
	tx, e := s.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	i, e := s.load(ctx, tx, id)
	if e != nil {
		return e
	}
	if i.dispatched || i.State != "reserving" || i.Outcome == "unknown" {
		return nil
	}
	if e = bump(i); e != nil {
		return e
	}
	var boot string
	var runtimeHash []byte
	e = tx.QueryRow(ctx, `SELECT boot_id::text,runtime_proof_hash FROM qm_device_catalog WHERE service_scope=$1 AND device_uuid=$2 FOR SHARE`, s.scope, i.Target).Scan(&boot, &runtimeHash)
	if e != nil {
		return e
	}
	if boot != i.runtimeBoot || subtle.ConstantTimeCompare(runtimeHash, i.runtimeHash) != 1 {
		if e = s.finish(ctx, tx, id, "failed"); e != nil {
			return e
		}
		return tx.Commit(ctx)
	}
	if i.domain != s.upstream.ReplayDomain() {
		_, e = tx.Exec(ctx, `UPDATE qm_control_intents SET outcome='unknown',revision=revision+1 WHERE service_scope=$1 AND id=$2`, s.scope, id)
		if e != nil {
			return e
		}
		return tx.Commit(ctx)
	}
	_, e = tx.Exec(ctx, `UPDATE qm_control_intents SET dispatched=true,outcome='unknown',revision=revision+1 WHERE service_scope=$1 AND id=$2`, s.scope, id)
	if e != nil {
		return e
	}
	if e = tx.Commit(ctx); e != nil {
		return e
	}
	g, callErr := s.upstream.CreateGrant(ctx, i.Owner, i.Target, i.createKey)
	if callErr != nil {
		return nil
	}
	if g.TenantID != s.tenant || g.SourceDeviceID != i.Owner || g.TargetDeviceID != i.Target || g.ID == "" {
		return nil
	}
	tx, e = s.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	i, e = s.load(ctx, tx, id)
	if e != nil {
		return e
	}
	if e = bump(i); e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `UPDATE qm_control_intents SET grant_id=$3,outcome='confirmed',revision=revision+1 WHERE service_scope=$1 AND id=$2`, s.scope, id, g.ID)
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}

// runtime matches both the immutable intent enrollment and the current catalog boot.
func (s *Store) runtime(ctx context.Context, tx pgx.Tx, i Intent, boot, proof string) error {
	boot, e := canonical(boot)
	if e != nil {
		return e
	}
	h, ok := catalog.RuntimeProofHash(proof)
	if !ok {
		return fail("INVALID_INPUT", 400)
	}
	if boot != i.runtimeBoot || subtle.ConstantTimeCompare(h, i.runtimeHash) != 1 {
		return fail("RUNTIME_MISMATCH", 409)
	}
	var current string
	var stored []byte
	e = tx.QueryRow(ctx, `SELECT boot_id::text,runtime_proof_hash FROM qm_device_catalog WHERE service_scope=$1 AND device_uuid=$2 AND boot_id IS NOT NULL FOR SHARE`, s.scope, i.Target).Scan(&current, &stored)
	if e != nil || current != boot || subtle.ConstantTimeCompare(stored, h) != 1 {
		return fail("RUNTIME_MISMATCH", 409)
	}
	return nil
}
func generation(v string) error {
	n, e := strconv.ParseInt(v, 10, 64)
	if e != nil || n <= 0 || strconv.FormatInt(n, 10) != v {
		return fail("INVALID_INPUT", 400)
	}
	return nil
}
func (s *Store) Close(ctx context.Context, p identity.Principal, id, key, reason string) (Intent, error) {
	p, e := s.principal(p)
	if e != nil {
		return Intent{}, e
	}
	id, e = canonical(id)
	if e != nil {
		return Intent{}, e
	}
	key, e = canonical(key)
	if e != nil {
		return Intent{}, e
	}
	if reason != "error" && !((reason == "user_pc" && p.Role == identity.PC) || (reason == "user_phone" && p.Role == identity.Mobile)) {
		return Intent{}, fail("INVALID_INPUT", 400)
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return Intent{}, e
	}
	defer tx.Rollback(ctx)
	i, e := s.load(ctx, tx, id)
	if e != nil {
		return i, e
	}
	if !allowed(i, p) {
		return Intent{}, fail("INTENT_NOT_FOUND", 404)
	}
	body := []string{id, reason}
	old, found, e := s.replay(ctx, tx, p, "close", key, body)
	if found || e != nil {
		return visible(old, p), e
	}
	if i.expired {
		return Intent{}, errUnknown
	}
	if e = s.record(ctx, tx, p, "close", key, body, id); e != nil {
		return Intent{}, e
	}
	if i.State != "released" && i.State != "failed" && i.State != "draining" {
		if e = bump(i); e != nil {
			return Intent{}, e
		}
		if !i.dispatched {
			if e = s.finish(ctx, tx, id, "failed"); e != nil {
				return Intent{}, e
			}
		} else {
			_, e = tx.Exec(ctx, `UPDATE qm_control_intents SET state='draining',close_reason=$3,revision=revision+1 WHERE service_scope=$1 AND id=$2`, s.scope, id, reason)
			if e != nil {
				return Intent{}, e
			}
		}
	}
	if e = tx.Commit(ctx); e != nil {
		return Intent{}, e
	}
	// Query/close failures leave a visible draining intent, never a false release.
	_ = s.progressDrain(ctx, id)
	return s.Get(ctx, p, id)
}
func (s *Store) Bind(ctx context.Context, p identity.Principal, id, key, gen, session, boot, proof string) (Intent, error) {
	p, e := s.principal(p)
	if e != nil {
		return Intent{}, e
	}
	if p.Role != identity.Mobile {
		return Intent{}, identity.ErrForbidden
	}
	id, e = canonical(id)
	if e != nil {
		return Intent{}, e
	}
	key, e = canonical(key)
	if e != nil {
		return Intent{}, e
	}
	session, e = canonical(session)
	if e != nil {
		return Intent{}, e
	}
	if e = generation(gen); e != nil {
		return Intent{}, e
	}
	// Do not fetch arbitrary upstream sessions before checking that this phone owns the intent.
	initial, e := s.Get(ctx, p, id)
	if e != nil {
		return Intent{}, e
	}
	if initial.State == "draining" || initial.State == "released" || initial.State == "failed" {
		return Intent{}, fail("INTENT_CLOSING", 409)
	}
	remote, e := s.upstream.GetSession(ctx, session)
	if e != nil {
		return Intent{}, fail("SESSION_UNAVAILABLE", 503)
	}
	grant, e := s.upstream.GetGrant(ctx, remote.GrantID)
	if e != nil {
		return Intent{}, fail("SESSION_UNAVAILABLE", 503)
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return Intent{}, e
	}
	defer tx.Rollback(ctx)
	i, e := s.load(ctx, tx, id)
	if e != nil {
		return i, e
	}
	if !allowed(i, p) {
		return Intent{}, fail("INTENT_NOT_FOUND", 404)
	}
	if e = s.runtime(ctx, tx, i, boot, proof); e != nil {
		return Intent{}, e
	}
	if gen != i.Generation {
		return Intent{}, fail("STALE_GENERATION", 409)
	}
	body := []string{id, gen, session, boot, proof}
	old, found, e := s.replay(ctx, tx, p, "bind", key, body)
	if found || e != nil {
		return visible(old, p), e
	}
	if i.State != "reserving" && i.State != "active" {
		return Intent{}, fail("INTENT_CLOSING", 409)
	}
	if i.grant == "" || remote.ID != session || remote.GrantID != i.grant || remote.SourceDeviceID != i.Owner || remote.TargetDeviceID != i.Target || grant.ID != i.grant || grant.TenantID != s.tenant || grant.SourceDeviceID != i.Owner || grant.TargetDeviceID != i.Target || grant.RevokedAt != nil || remote.State == "closed" || (i.Session != "" && i.Session != session) {
		return Intent{}, fail("SESSION_MISMATCH", 409)
	}
	if remote.State != "authorizing" && remote.State != "connecting" && remote.State != "connected" && remote.State != "reconnecting" {
		return Intent{}, fail("SESSION_MISMATCH", 409)
	}
	var valid bool
	e = tx.QueryRow(ctx, `SELECT $1::timestamptz>clock_timestamp() AND $2::timestamptz>clock_timestamp()`, remote.SourceLeaseExpiresAt, remote.TargetLeaseExpiresAt).Scan(&valid)
	if e != nil {
		return Intent{}, e
	}
	if !valid {
		return Intent{}, fail("SESSION_MISMATCH", 409)
	}
	if e = bump(i); e != nil {
		return Intent{}, e
	}
	if e = s.record(ctx, tx, p, "bind", key, body, id); e != nil {
		return Intent{}, e
	}
	_, e = tx.Exec(ctx, `UPDATE qm_control_intents SET session_id=$3,state='active',outcome='confirmed',revision=revision+1 WHERE service_scope=$1 AND id=$2`, s.scope, id, session)
	if e != nil {
		return Intent{}, e
	}
	if e = tx.Commit(ctx); e != nil {
		return Intent{}, e
	}
	return s.Get(ctx, p, id)
}
func (s *Store) Drained(ctx context.Context, p identity.Principal, id, key, gen, session, token, boot, proof string) (Intent, error) {
	p, e := s.principal(p)
	if e != nil {
		return Intent{}, e
	}
	if p.Role != identity.Mobile {
		return Intent{}, identity.ErrForbidden
	}
	id, e = canonical(id)
	if e != nil {
		return Intent{}, e
	}
	key, e = canonical(key)
	if e != nil {
		return Intent{}, e
	}
	token, e = canonical(token)
	if e != nil {
		return Intent{}, e
	}
	if session != "" {
		session, e = canonical(session)
		if e != nil {
			return Intent{}, e
		}
	}
	if e = generation(gen); e != nil {
		return Intent{}, e
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return Intent{}, e
	}
	defer tx.Rollback(ctx)
	i, e := s.load(ctx, tx, id)
	if e != nil {
		return i, e
	}
	if !allowed(i, p) {
		return Intent{}, fail("INTENT_NOT_FOUND", 404)
	}
	body := []string{id, gen, session, token, boot, proof}
	old, found, e := s.replay(ctx, tx, p, "drained", key, body)
	if found || e != nil {
		return visible(old, p), e
	}
	if e = s.runtime(ctx, tx, i, boot, proof); e != nil {
		return Intent{}, e
	}
	if i.Generation != gen {
		return Intent{}, fail("STALE_GENERATION", 409)
	}
	if i.State != "draining" || !i.revoked || i.grant == "" || i.DrainToken == "" || i.DrainToken != token {
		return Intent{}, fail("DRAIN_NOT_READY", 409)
	}
	if i.Session != session {
		return Intent{}, fail("SESSION_MISMATCH", 409)
	}
	if e = bump(i); e != nil {
		return Intent{}, e
	}
	if e = s.record(ctx, tx, p, "drained", key, body, id); e != nil {
		return Intent{}, e
	}
	if e = s.finish(ctx, tx, id, "released"); e != nil {
		return Intent{}, e
	}
	if e = tx.Commit(ctx); e != nil {
		return Intent{}, e
	}
	return s.Get(ctx, p, id)
}
func (s *Store) progressDrain(ctx context.Context, id string) error {
	tx, e := s.begin(ctx)
	if e != nil {
		return e
	}
	i, e := s.load(ctx, tx, id)
	tx.Rollback(ctx)
	if e != nil {
		return e
	}
	if i.State != "draining" || i.grant == "" || i.revoked {
		return nil
	}
	g, e := s.upstream.GetGrant(ctx, i.grant)
	if e != nil {
		return e
	}
	if g.ID != i.grant || g.TenantID != s.tenant || g.SourceDeviceID != i.Owner || g.TargetDeviceID != i.Target {
		return identity.ErrUnavailable
	}
	if g.RevokedAt == nil {
		_ = s.upstream.RevokeGrant(ctx, i.grant, i.revokeKey)
		g, e = s.upstream.GetGrant(ctx, i.grant)
		if e != nil {
			return e
		}
	}
	if g.RevokedAt == nil || g.ID != i.grant || g.TenantID != s.tenant || g.SourceDeviceID != i.Owner || g.TargetDeviceID != i.Target {
		return identity.ErrUnavailable
	}
	token, e := uuid()
	if e != nil {
		return e
	}
	tx, e = s.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	i, e = s.load(ctx, tx, id)
	if e != nil {
		return e
	}
	if i.State != "draining" || i.revoked {
		return nil
	}
	if e = bump(i); e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `UPDATE qm_control_intents SET revoked=true,outcome='confirmed',drain_token=$3,revision=revision+1 WHERE service_scope=$1 AND id=$2`, s.scope, id, token)
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}

// Recover never re-dispatches an attempt already marked dispatched. Unknown grants remain occupied.
// Work is keyset-paged, bounded per pass; the cursor is returned to avoid starving later targets.
func (s *Store) Recover(ctx context.Context, after string) (string, error) {
	if after == "" {
		after = "00000000-0000-0000-0000-000000000000"
	}
	if _, e := canonical(after); e != nil {
		return "", e
	}
	rows, e := s.pool.Query(ctx, `SELECT id::text FROM qm_control_intents WHERE service_scope=$1 AND id>$2 AND state IN ('reserving','active','draining') ORDER BY id LIMIT 100`, s.scope, after)
	if e != nil {
		return after, e
	}
	var ids []string
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return after, e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return after, e
	}
	var failures []error
	for _, id := range ids {
		for _, step := range []func(context.Context, string) error{s.checkRuntime, s.dispatch, s.progressDrain} {
			e = step(ctx, id)
			if e == nil {
				continue
			}
			// Only explicitly classified intent/upstream failures are skippable.
			// Cancellation and unclassified (including database) errors stop this
			// page at the preceding cursor, never falsely marking work complete.
			var local *Error
			if ctx.Err() != nil || (!errors.As(e, &local) && !errors.Is(e, identity.ErrUnavailable) && !errors.Is(e, peerloom.ErrOutcomeUnknown)) {
				return after, errors.Join(append(failures, e)...)
			}
			failures = append(failures, e)
			break
		}
		// A permanently exhausted row must not starve later targets. It stays
		// occupied and is revisited on the next bounded scan cycle.
		after = id
	}
	if len(ids) < 100 {
		after = ""
	}
	return after, errors.Join(failures...)
}

// A new enrolled boot cannot acknowledge the old runtime. It starts draining,
// but still needs the old runtime ACK or separately verified cutoff to release.
func (s *Store) checkRuntime(ctx context.Context, id string) error {
	tx, e := s.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	i, e := s.load(ctx, tx, id)
	if e != nil {
		return e
	}
	if i.State != "active" && i.State != "reserving" {
		return nil
	}
	var boot *string
	var proof []byte
	e = tx.QueryRow(ctx, `SELECT boot_id::text,runtime_proof_hash FROM qm_device_catalog WHERE service_scope=$1 AND device_uuid=$2 FOR SHARE`, s.scope, i.Target).Scan(&boot, &proof)
	if e != nil {
		return e
	}
	if boot != nil && *boot == i.runtimeBoot && subtle.ConstantTimeCompare(proof, i.runtimeHash) == 1 {
		return nil
	}
	if e = bump(i); e != nil {
		return e
	}
	if !i.dispatched {
		if e = s.finish(ctx, tx, id, "failed"); e != nil {
			return e
		}
	} else {
		_, e = tx.Exec(ctx, `UPDATE qm_control_intents SET state='draining',close_reason='error',revision=revision+1 WHERE service_scope=$1 AND id=$2`, s.scope, id)
		if e != nil {
			return e
		}
	}
	return tx.Commit(ctx)
}
