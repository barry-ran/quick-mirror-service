package binding

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"errors"
	"github.com/barry-ran/quick-mirror-service/internal/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"strconv"
	"strings"
)

//go:embed migrations/001_binding.sql
var migration string

type Store struct {
	pool          *pgxpool.Pool
	scope, tenant string
	generateCode  func() (string, error)
}

func NewStore(pool *pgxpool.Pool, scope, tenant string) (*Store, error) {
	scope, a := identity.NormalizeUUID(scope)
	tenant, b := identity.NormalizeUUID(tenant)
	if pool == nil || !a || !b {
		return nil, ErrInvalidInput
	}
	return &Store{pool: pool, scope: scope, tenant: tenant, generateCode: newCode}, nil
}
func (s *Store) Migrate(ctx context.Context) error { _, e := s.pool.Exec(ctx, migration); return e }
func (s *Store) principal(p identity.Principal) (identity.Principal, error) {
	var a, b, c bool
	p.DeviceID, a = identity.NormalizeUUID(p.DeviceID)
	p.ApplicationID, b = identity.NormalizeUUID(p.ApplicationID)
	p.TenantID, c = identity.NormalizeUUID(p.TenantID)
	if !a || !b || !c || p.TenantID != s.tenant || (p.Role != identity.PC && p.Role != identity.Mobile) {
		return p, identity.ErrForbidden
	}
	return p, nil
}
func (s *Store) begin(ctx context.Context) (pgx.Tx, error) {
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return nil, e
	}
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "qm-control:"+s.scope); e != nil {
		_ = tx.Rollback(ctx)
		return nil, e
	}
	// Purge expired response bodies in bounded batches; keep key/hash tombstones.
	if _, e = tx.Exec(ctx, `UPDATE qm_binding_receipts SET result=NULL WHERE ctid IN (SELECT ctid FROM qm_binding_receipts WHERE service_scope=$1 AND expires_at<=clock_timestamp() AND result IS NOT NULL LIMIT 200)`, s.scope); e != nil {
		_ = tx.Rollback(ctx)
		return nil, e
	}
	return tx, nil
}
func (s *Store) checkInstallation(ctx context.Context, tx pgx.Tx, p identity.Principal) error {
	var app, role string
	e := tx.QueryRow(ctx, `SELECT application_id::text,role FROM qm_installations WHERE service_scope=$1 AND device_id=$2 FOR UPDATE`, s.scope, p.DeviceID).Scan(&app, &role)
	if errors.Is(e, pgx.ErrNoRows) {
		return ErrCodeInvalid
	}
	if e != nil {
		return e
	}
	if app != p.ApplicationID || role != string(p.Role) {
		return identity.ErrForbidden
	}
	return nil
}
func (s *Store) allocate(ctx context.Context, tx pgx.Tx, id string) (string, error) {
	for i := 0; i < 64; i++ {
		code, e := s.generateCode()
		if e != nil {
			return "", e
		}
		if !ValidCode(code) {
			return "", ErrInvalidInput
		}
		r, e := tx.Exec(ctx, `INSERT INTO qm_binding_codes(service_scope,code,owner_device_id) VALUES($1,$2,$3) ON CONFLICT(service_scope,code) DO NOTHING`, s.scope, code, id)
		if e != nil {
			return "", e
		}
		if r.RowsAffected() == 1 {
			return code, nil
		}
	}
	var count int
	e := tx.QueryRow(ctx, `SELECT count(*) FROM qm_binding_codes WHERE service_scope=$1`, s.scope).Scan(&count)
	if e != nil {
		return "", e
	}
	if count >= 1000000 {
		return "", ErrCodeSpaceExhausted
	}
	return "", ErrAllocationRetry
}
func (s *Store) Ensure(ctx context.Context, p identity.Principal) (Code, error) {
	p, e := s.principal(p)
	if e != nil {
		return Code{}, e
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return Code{}, e
	}
	defer tx.Rollback(ctx)
	_, e = tx.Exec(ctx, `INSERT INTO qm_installations(service_scope,device_id,application_id,role) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, s.scope, p.DeviceID, p.ApplicationID, p.Role)
	if e != nil {
		return Code{}, e
	}
	if e = s.checkInstallation(ctx, tx, p); e != nil {
		return Code{}, e
	}
	var exists bool
	e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM qm_binding_codes WHERE service_scope=$1 AND owner_device_id=$2 AND current)`, s.scope, p.DeviceID).Scan(&exists)
	if e != nil {
		return Code{}, e
	}
	if !exists {
		if _, e = s.allocate(ctx, tx, p.DeviceID); e != nil {
			return Code{}, e
		}
	}
	result, e := s.selfCode(ctx, tx, p)
	if e != nil {
		return Code{}, e
	}
	return result, tx.Commit(ctx)
}

const relationColumns = `binding_id::text,revision::text,pc_id::text,mobile_id::text,active,EXISTS(SELECT 1 FROM qm_binding_close_tasks c WHERE c.service_scope=b.service_scope AND c.binding_id=b.binding_id AND c.completed_at IS NULL)`

func scanRelation(row pgx.Row) (Relation, error) {
	var r Relation
	e := row.Scan(&r.ID, &r.Revision, &r.PCID, &r.MobileID, &r.Active, &r.ClosePending)
	return r, e
}
func (s *Store) selfCode(ctx context.Context, tx pgx.Tx, p identity.Principal) (Code, error) {
	result := Code{}
	if p.Role == identity.Mobile {
		r, e := scanRelation(tx.QueryRow(ctx, `SELECT `+relationColumns+` FROM qm_bindings b WHERE service_scope=$1 AND mobile_id=$2 AND active`, s.scope, p.DeviceID))
		if e == nil {
			return Code{Bound: true, Binding: &r}, nil
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return result, e
		}
	}
	e := tx.QueryRow(ctx, `SELECT code FROM qm_binding_codes WHERE service_scope=$1 AND owner_device_id=$2 AND current`, s.scope, p.DeviceID).Scan(&result.Code)
	if errors.Is(e, pgx.ErrNoRows) {
		return result, ErrCodeInvalid
	}
	return result, e
}
func (s *Store) SelfCode(ctx context.Context, p identity.Principal) (Code, error) {
	p, e := s.principal(p)
	if e != nil {
		return Code{}, e
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return Code{}, e
	}
	defer tx.Rollback(ctx)
	if e = s.checkInstallation(ctx, tx, p); e != nil {
		return Code{}, e
	}
	r, e := s.selfCode(ctx, tx, p)
	if e != nil {
		return r, e
	}
	return r, tx.Commit(ctx)
}

// Receipts retain request-key tombstones. Expired results are never silently re-executed.
func (s *Store) replay(ctx context.Context, tx pgx.Tx, p identity.Principal, op, key, body string, out any) (bool, error) {
	if len(key) < 8 || len(key) > 128 || strings.ContainsAny(key, "\r\n\x00") {
		return false, ErrInvalidInput
	}
	sum := sha256.Sum256([]byte(body))
	var digest, result []byte
	var live bool
	e := tx.QueryRow(ctx, `SELECT request_hash,result,expires_at>clock_timestamp() FROM qm_binding_receipts WHERE service_scope=$1 AND actor_id=$2 AND operation=$3 AND request_key=$4`, s.scope, p.DeviceID, op, key).Scan(&digest, &result, &live)
	if errors.Is(e, pgx.ErrNoRows) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	if string(digest) != string(sum[:]) {
		return false, ErrIdempotencyConflict
	}
	if !live || len(result) == 0 {
		return false, ErrOutcomeUnknown
	}
	return true, json.Unmarshal(result, out)
}
func (s *Store) receipt(ctx context.Context, tx pgx.Tx, p identity.Principal, op, key, body string, result any) error {
	sum := sha256.Sum256([]byte(body))
	encoded, e := json.Marshal(result)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `INSERT INTO qm_binding_receipts(service_scope,actor_id,operation,request_key,request_hash,result) VALUES($1,$2,$3,$4,$5,$6)`, s.scope, p.DeviceID, op, key, sum[:], encoded)
	return e
}
func (s *Store) Refresh(ctx context.Context, p identity.Principal, key string) (Code, error) {
	p, e := s.principal(p)
	if e != nil {
		return Code{}, e
	}
	if p.Role != identity.Mobile {
		return Code{}, ErrRefreshNotAllowed
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return Code{}, e
	}
	defer tx.Rollback(ctx)
	if e = s.checkInstallation(ctx, tx, p); e != nil {
		return Code{}, e
	}
	cur, e := s.selfCode(ctx, tx, p)
	if e != nil {
		return Code{}, e
	}
	if cur.Bound {
		return Code{}, ErrRefreshNotAllowed
	}
	var out Code
	ok, e := s.replay(ctx, tx, p, "refresh", key, "", &out)
	if e != nil {
		return out, e
	}
	if ok {
		return out, tx.Commit(ctx)
	}
	_, e = tx.Exec(ctx, `UPDATE qm_binding_codes SET current=false,retired_at=clock_timestamp() WHERE service_scope=$1 AND owner_device_id=$2 AND current`, s.scope, p.DeviceID)
	if e != nil {
		return out, e
	}
	out.Code, e = s.allocate(ctx, tx, p.DeviceID)
	if e != nil {
		return out, e
	}
	if e = s.receipt(ctx, tx, p, "refresh", key, "", out); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}
func (s *Store) Bind(ctx context.Context, p identity.Principal, code, key string) (Relation, error) {
	if !ValidCode(code) {
		return Relation{}, ErrInvalidCodeFormat
	}
	p, e := s.principal(p)
	if e != nil {
		return Relation{}, e
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return Relation{}, e
	}
	defer tx.Rollback(ctx)
	if e = s.checkInstallation(ctx, tx, p); e != nil {
		return Relation{}, e
	}
	var out Relation
	ok, e := s.replay(ctx, tx, p, "bind", key, code, &out)
	if e != nil {
		return out, e
	}
	if ok {
		return out, tx.Commit(ctx)
	}
	var target, role string
	e = tx.QueryRow(ctx, `SELECT i.device_id::text,i.role FROM qm_binding_codes c JOIN qm_installations i ON i.service_scope=c.service_scope AND i.device_id=c.owner_device_id WHERE c.service_scope=$1 AND c.code=$2 AND c.current`, s.scope, code).Scan(&target, &role)
	if errors.Is(e, pgx.ErrNoRows) {
		return out, ErrCodeInvalid
	}
	if e != nil {
		return out, e
	}
	if role == string(p.Role) {
		return out, ErrRoleMismatch
	}
	pc, mobile := p.DeviceID, target
	if p.Role == identity.Mobile {
		pc, mobile = target, p.DeviceID
	}
	// All relation mutations share the control advisory lock before any row locks.
	if _, e = tx.Exec(ctx, `SELECT device_id FROM qm_installations WHERE service_scope=$1 AND device_id=$2 FOR UPDATE`, s.scope, mobile); e != nil {
		return out, e
	}
	out, e = s.Active(ctx, tx, pc, mobile)
	if errors.Is(e, ErrAlreadyBound) {
		return Relation{}, e
	}
	if e != nil && !errors.Is(e, ErrNotBound) {
		return out, e
	}
	if errors.Is(e, ErrNotBound) {
		out = Relation{PCID: pc, MobileID: mobile, Revision: "1", Active: true}
		out.ID, e = newID()
		if e != nil {
			return out, e
		}
		_, e = tx.Exec(ctx, `INSERT INTO qm_bindings(service_scope,binding_id,pc_id,mobile_id) VALUES($1,$2,$3,$4)`, s.scope, out.ID, pc, mobile)
		if e != nil {
			return out, e
		}
	}
	if e = s.receipt(ctx, tx, p, "bind", key, code, out); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}
func (s *Store) Active(ctx context.Context, tx pgx.Tx, pcID, mobileID string) (Relation, error) {
	r, e := scanRelation(tx.QueryRow(ctx, `SELECT `+relationColumns+` FROM qm_bindings b WHERE service_scope=$1 AND mobile_id=$2 AND active FOR UPDATE`, s.scope, mobileID))
	if errors.Is(e, pgx.ErrNoRows) {
		return r, ErrNotBound
	}
	if e != nil {
		return r, e
	}
	if r.PCID != pcID {
		return Relation{}, ErrAlreadyBound
	}
	return r, nil
}
func (s *Store) List(ctx context.Context, p identity.Principal, cursor string, limit int) (Page, error) {
	p, e := s.principal(p)
	if e != nil {
		return Page{}, e
	}
	if limit < 1 || limit > BatchSize {
		return Page{}, ErrInvalidInput
	}
	if cursor != "" {
		if _, ok := identity.NormalizeUUID(cursor); !ok {
			return Page{}, ErrInvalidInput
		}
	}
	var authorized bool
	e = s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM qm_installations WHERE service_scope=$1 AND device_id=$2 AND application_id=$3 AND role=$4)`, s.scope, p.DeviceID, p.ApplicationID, p.Role).Scan(&authorized)
	if e != nil {
		return Page{}, e
	}
	if !authorized {
		return Page{}, identity.ErrForbidden
	}

	rows, e := s.pool.Query(ctx, `SELECT `+relationColumns+` FROM qm_bindings b WHERE service_scope=$1 AND active AND (pc_id=$2 OR mobile_id=$2) AND ($3='' OR binding_id::text>$3) ORDER BY binding_id LIMIT $4`, s.scope, p.DeviceID, cursor, limit+1)
	if e != nil {
		return Page{}, e
	}
	defer rows.Close()
	out := Page{Items: []Relation{}}
	for rows.Next() {
		r, e := scanRelation(rows)
		if e != nil {
			return out, e
		}
		out.Items = append(out.Items, r)
	}
	if e = rows.Err(); e != nil {
		return out, e
	}
	if len(out.Items) > limit {
		out.Items = out.Items[:limit]
		out.NextCursor = out.Items[limit-1].ID
	}
	return out, nil
}
func (s *Store) Unbind(ctx context.Context, p identity.Principal, id, revision, key string) (Relation, error) {
	p, e := s.principal(p)
	if e != nil {
		return Relation{}, e
	}
	id, valid := identity.NormalizeUUID(id)
	if !valid || !revisionPattern.MatchString(revision) {
		return Relation{}, ErrInvalidInput
	}
	n, e := strconv.ParseInt(revision, 10, 64)
	if e != nil || n <= 0 {
		return Relation{}, ErrInvalidInput
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return Relation{}, e
	}
	defer tx.Rollback(ctx)
	if e = s.checkInstallation(ctx, tx, p); e != nil {
		return Relation{}, e
	}
	body := id + ":" + revision
	var out Relation
	ok, e := s.replay(ctx, tx, p, "unbind", key, body, &out)
	if e != nil {
		return out, e
	}
	if ok {
		out, e = scanRelation(tx.QueryRow(ctx, `SELECT `+relationColumns+` FROM qm_bindings b WHERE service_scope=$1 AND binding_id=$2`, s.scope, id))
		if e != nil {
			return Relation{}, e
		}
		return out, tx.Commit(ctx)
	}
	out, e = scanRelation(tx.QueryRow(ctx, `SELECT `+relationColumns+` FROM qm_bindings b WHERE service_scope=$1 AND binding_id=$2 FOR UPDATE`, s.scope, id))
	if errors.Is(e, pgx.ErrNoRows) {
		return out, ErrNotBound
	}
	if e != nil {
		return out, e
	}
	if (p.Role == identity.PC && out.PCID != p.DeviceID) || (p.Role == identity.Mobile && out.MobileID != p.DeviceID) {
		return Relation{}, identity.ErrForbidden
	}
	if out.Active {
		if out.Revision != revision {
			return Relation{}, ErrBindingChanged
		}
		_, e = tx.Exec(ctx, `UPDATE qm_bindings SET active=false,revision=revision+1,revoked_at=clock_timestamp() WHERE service_scope=$1 AND binding_id=$2`, s.scope, id)
		if e != nil {
			return out, e
		}
		out.Active = false
		out.Revision = strconv.FormatInt(n+1, 10)
		out.ClosePending = true
		_, e = tx.Exec(ctx, `INSERT INTO qm_binding_close_tasks(service_scope,binding_id,pc_id,mobile_id,binding_revision) VALUES($1,$2,$3,$4,$5)`, s.scope, id, out.PCID, out.MobileID, n+1)
		if e != nil {
			return out, e
		}
	}
	if e = s.receipt(ctx, tx, p, "unbind", key, body, out); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}

// PendingClosures exposes only durable relation-owned recovery tasks, not control tables.
func (s *Store) PendingClosures(ctx context.Context, limit int) ([]Relation, error) {
	if limit < 1 || limit > BatchSize {
		return nil, ErrInvalidInput
	}
	rows, err := s.pool.Query(ctx, `WITH candidates AS (
 SELECT service_scope,binding_id FROM qm_binding_close_tasks WHERE service_scope=$1 AND completed_at IS NULL
 ORDER BY last_checked_at NULLS FIRST,binding_id FOR UPDATE SKIP LOCKED LIMIT $2
), checked AS (
 UPDATE qm_binding_close_tasks c SET last_checked_at=clock_timestamp() FROM candidates p
 WHERE c.service_scope=p.service_scope AND c.binding_id=p.binding_id RETURNING c.binding_id
) SELECT `+relationColumns+` FROM qm_bindings b WHERE service_scope=$1 AND binding_id IN(SELECT binding_id FROM checked) ORDER BY binding_id`, s.scope, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Relation{}
	for rows.Next() {
		r, err := scanRelation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CompleteClosure must share the caller's control lock transaction after proving all intents terminal.
func (s *Store) CompleteClosure(ctx context.Context, tx pgx.Tx, bindingID string) error {
	_, err := tx.Exec(ctx, `UPDATE qm_binding_close_tasks SET completed_at=COALESCE(completed_at,clock_timestamp()) WHERE service_scope=$1 AND binding_id=$2`, s.scope, bindingID)
	return err
}
