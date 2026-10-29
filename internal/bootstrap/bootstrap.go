// Package bootstrap 持久化安装注册尝试的语义绑定，不保存 grant 或管理凭证。
package bootstrap

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/barry-ran/quick-mirror-service/internal/identity"
	"github.com/barry-ran/quick-mirror-service/internal/peerloom"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/001_bootstrap.sql
var migration string

var ErrInvalidInput = errors.New("INVALID_INPUT")

type Request struct {
	Role           identity.Role
	Label          string
	IdempotencyKey string
}

type GrantIssuer interface {
	Issue(context.Context, identity.Role, string, int) (peerloom.RegistrationGrant, error)
	ReplayDomain() string
}

type Store struct {
	pool   *pgxpool.Pool
	scope  string
	issuer GrantIssuer
}

func NewStore(pool *pgxpool.Pool, scope string, issuer GrantIssuer) (*Store, error) {
	scope, valid := identity.NormalizeUUID(scope)
	if pool == nil || !valid || issuer == nil || len(issuer.ReplayDomain()) != 64 {
		return nil, ErrInvalidInput
	}
	return &Store{pool: pool, scope: scope, issuer: issuer}, nil
}

func (s *Store) Migrate(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, migration)
	return err
}

func (r Request) fingerprints() ([32]byte, [32]byte, error) {
	var empty [32]byte
	key, valid := identity.NormalizeUUID(r.IdempotencyKey)
	if !valid || (r.Role != identity.PC && r.Role != identity.Mobile) || !utf8.ValidString(r.Label) || len(r.Label) > 256 || strings.IndexFunc(r.Label, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
		return empty, empty, ErrInvalidInput
	}
	// key 只作为随机安装尝试标识；不是身份或防滥用凭证。
	body, err := json.Marshal(struct {
		Role  identity.Role `json:"role"`
		Label string        `json:"label"`
	}{r.Role, r.Label})
	if err != nil {
		return empty, empty, ErrInvalidInput
	}
	return sha256.Sum256([]byte(key)), sha256.Sum256(body), nil
}

// Issue 在网络调用之前提交语义绑定；超时/重启重试仍使用同一个随机 upstream key。
// 不持有数据库事务跨网络请求，也不在业务库保存 bearer grant 明文。
func (s *Store) Issue(ctx context.Context, request Request) (peerloom.RegistrationGrant, error) {
	var empty peerloom.RegistrationGrant
	keyHash, requestHash, err := request.fingerprints()
	if err != nil {
		return empty, err
	}
	var random [24]byte
	if _, err := rand.Read(random[:]); err != nil {
		return empty, identity.ErrUnavailable
	}
	upstreamKey := "qm-bootstrap-" + hex.EncodeToString(random[:])
	// ON CONFLICT 锁定同 key；RETURNING 返回已存在行，不覆盖它的语义和上游 key。
	var savedHash []byte
	var expired bool
	var savedDomain string
	err = s.pool.QueryRow(ctx, `INSERT INTO qm_bootstrap_intents(service_scope,key_hash,request_hash,upstream_key,replay_domain)
VALUES($1,$2,$3,$4,$5) ON CONFLICT(service_scope,key_hash) DO UPDATE SET key_hash=qm_bootstrap_intents.key_hash
RETURNING request_hash,upstream_key,expires_at<=clock_timestamp(),replay_domain`, s.scope, keyHash[:], requestHash[:], upstreamKey, s.issuer.ReplayDomain()).Scan(&savedHash, &upstreamKey, &expired, &savedDomain)
	if err != nil {
		return empty, identity.ErrUnavailable
	}
	if string(savedHash) != string(requestHash[:]) {
		return empty, peerloom.ErrIdempotencyConflict
	}
	if expired || savedDomain != s.issuer.ReplayDomain() {
		return empty, peerloom.ErrReplayExpired
	}
	return s.issuer.Issue(ctx, request.Role, upstreamKey, 300)
}

// PurgeExpired 只供部署维护入口调用。收据清理后，相同 key 不再享有幂等保证；
// 客户端不得自动重用过期 key，明确的新注册尝试须生成新 UUID。
func (s *Store) PurgeExpired(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM qm_bootstrap_intents WHERE service_scope=$1 AND expires_at<=clock_timestamp()`, s.scope)
	return err
}
