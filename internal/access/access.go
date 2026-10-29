// Package access 定义业务令牌边界：必须有可信凭证期限，且每请求重验来源身份。
// 不提供缺少上游能力时的允许分支，也不接入原产品账号 token。
package access

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/barry-ran/quick-mirror-service/internal/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/001_access.sql
var migration string

var ErrInvalidConfig = errors.New("INVALID_AUTH_CONFIGURATION")

// VerifiedCredential 的期限必须来自同次权威认证结果，不接受客户端自报值。
// 上游公开 credential_expires_at 来自同次身份认证，正式v0.1.3已通过实际联调。
type VerifiedCredential struct {
	Principal identity.Principal
	ExpiresAt time.Time
}

type CredentialVerifier interface {
	VerifyCredential(context.Context, string) (VerifiedCredential, error)
}

type Token struct {
	AccessToken string    `json:"access_token"`
	ExpiresAt   time.Time `json:"expires_at"`
	Scope       string    `json:"scope"`
}

type Store struct {
	pool     *pgxpool.Pool
	scope    string
	tenant   string
	verifier CredentialVerifier
	aead     cipher.AEAD
	keyHash  [32]byte
}

func NewStore(pool *pgxpool.Pool, scope, tenant string, key []byte, verifier CredentialVerifier) (*Store, error) {
	scope, validScope := identity.NormalizeUUID(scope)
	tenant, validTenant := identity.NormalizeUUID(tenant)
	if pool == nil || !validScope || !validTenant || len(key) != 32 || verifier == nil {
		return nil, ErrInvalidConfig
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	keyHash := sha256.Sum256(append([]byte("qm-access-key-v1\x00"), key...))
	return &Store{pool: pool, scope: scope, tenant: tenant, verifier: verifier, aead: aead, keyHash: keyHash}, nil
}

func (s *Store) Migrate(ctx context.Context) error { _, err := s.pool.Exec(ctx, migration); return err }

func canonicalPrincipal(p identity.Principal) (identity.Principal, bool) {
	var device, tenant, application bool
	p.DeviceID, device = identity.NormalizeUUID(p.DeviceID)
	p.TenantID, tenant = identity.NormalizeUUID(p.TenantID)
	p.ApplicationID, application = identity.NormalizeUUID(p.ApplicationID)
	return p, device && tenant && application && (p.Role == identity.PC || p.Role == identity.Mobile)
}

func aad(scope string, hash [32]byte, p identity.Principal, expiry time.Time) []byte {
	data, _ := json.Marshal([]any{"qm-access-v1", scope, hex.EncodeToString(hash[:]), p.DeviceID, p.TenantID, p.ApplicationID, p.Role, expiry.UnixMicro()})
	return data
}

func tokenHash(token string) ([32]byte, bool) {
	var empty [32]byte
	if len(token) != 47 || !strings.HasPrefix(token, "qma_") {
		return empty, false
	}
	value, err := base64.RawURLEncoding.DecodeString(token[4:])
	if err != nil || len(value) != 32 || base64.RawURLEncoding.EncodeToString(value) != token[4:] {
		return empty, false
	}
	return sha256.Sum256([]byte(token)), true
}

func validCredential(credential string) bool {
	return len(credential) > 0 && len(credential) <= 512 && strings.IndexFunc(credential, func(r rune) bool { return r < 33 || r > 126 }) < 0
}

func (s *Store) Exchange(ctx context.Context, role identity.Role, credential string) (Token, error) {
	token, _, err := s.ExchangeVerified(ctx, role, credential)
	return token, err
}

// ExchangeVerified 返回同次认证的主体，供业务接线幂等建档；不重复猜测或解码凭证。
func (s *Store) ExchangeVerified(ctx context.Context, role identity.Role, credential string) (Token, identity.Principal, error) {
	var empty Token
	if !validCredential(credential) {
		return empty, identity.Principal{}, identity.ErrInvalidCredential
	}
	if role != identity.PC && role != identity.Mobile {
		return empty, identity.Principal{}, identity.ErrForbidden
	}
	verified, err := s.verifier.VerifyCredential(ctx, credential)
	if err != nil {
		return empty, identity.Principal{}, verificationError(err)
	}
	p, valid := canonicalPrincipal(verified.Principal)
	if !valid || p.TenantID != s.tenant || p.Role != role {
		return empty, identity.Principal{}, identity.ErrForbidden
	}
	if verified.ExpiresAt.IsZero() {
		return empty, identity.Principal{}, identity.ErrUnavailable
	}
	var now time.Time
	if err := s.pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return empty, identity.Principal{}, identity.ErrUnavailable
	}
	expiry := now.Add(15 * time.Minute)
	if verified.ExpiresAt.Before(expiry) {
		expiry = verified.ExpiresAt
	}
	expiry = expiry.UTC().Truncate(time.Microsecond)
	if !expiry.After(now) {
		return empty, identity.Principal{}, identity.ErrInvalidCredential
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return empty, identity.Principal{}, identity.ErrUnavailable
	}
	token := "qma_" + base64.RawURLEncoding.EncodeToString(random[:])
	hash, _ := tokenHash(token)
	// 随机96-bit nonce 的每key加密预算跨实例持久累计；失败/不确定的尝试不退款。
	if err := s.reserveEncryption(ctx); err != nil {
		return empty, identity.Principal{}, identity.ErrUnavailable
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return empty, identity.Principal{}, identity.ErrUnavailable
	}
	sealed := s.aead.Seal(nil, nonce, []byte(credential), aad(s.scope, hash, p, expiry))
	result, err := s.pool.Exec(ctx, `INSERT INTO qm_access_tokens(service_scope,token_hash,device_uuid,tenant_uuid,application_uuid,role,expires_at,credential_nonce,credential_ciphertext)
SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9 WHERE $7::timestamptz>clock_timestamp()`, s.scope, hash[:], p.DeviceID, p.TenantID, p.ApplicationID, p.Role, expiry, nonce, sealed)
	if err != nil {
		return empty, identity.Principal{}, identity.ErrUnavailable
	}
	if result.RowsAffected() != 1 {
		return empty, identity.Principal{}, identity.ErrInvalidCredential
	}
	return Token{AccessToken: token, ExpiresAt: expiry, Scope: s.scope}, p, nil
}

func (s *Store) reserveEncryption(ctx context.Context) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// 不能在异步提交可能丢失计数时先使用 nonce；仅更改本事务，不修改数据库全局设置。
	if _, err := tx.Exec(ctx, `SET LOCAL synchronous_commit = on`); err != nil {
		return err
	}
	var encryptions int64
	if err := tx.QueryRow(ctx, `INSERT INTO qm_access_key_usage(key_hash,encryptions) VALUES($1,1)
ON CONFLICT(key_hash) DO UPDATE SET encryptions=qm_access_key_usage.encryptions+1
WHERE qm_access_key_usage.encryptions<4294967296 RETURNING encryptions`, s.keyHash[:]).Scan(&encryptions); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// VerifyAccess 有意不同于安装凭证 Verify，防止把两个 bearer 类型直接混接。
func (s *Store) VerifyAccess(ctx context.Context, token string) (identity.Principal, error) {
	var empty identity.Principal
	hash, valid := tokenHash(token)
	if !valid {
		return empty, identity.ErrInvalidCredential
	}
	var p identity.Principal
	var expiry time.Time
	var nonce, sealed []byte
	err := s.pool.QueryRow(ctx, `SELECT device_uuid::text,tenant_uuid::text,application_uuid::text,role,expires_at,credential_nonce,credential_ciphertext FROM qm_access_tokens
WHERE service_scope=$1 AND token_hash=$2 AND expires_at>clock_timestamp()`, s.scope, hash[:]).Scan(&p.DeviceID, &p.TenantID, &p.ApplicationID, &p.Role, &expiry, &nonce, &sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		return empty, identity.ErrInvalidCredential
	}
	if err != nil {
		return empty, identity.ErrUnavailable
	}
	if len(nonce) != s.aead.NonceSize() {
		return empty, identity.ErrInvalidCredential
	}
	credential, err := s.aead.Open(nil, nonce, sealed, aad(s.scope, hash, p, expiry))
	if err != nil {
		return empty, identity.ErrInvalidCredential
	}
	defer clear(credential)
	verified, err := s.verifier.VerifyCredential(ctx, string(credential))
	if err != nil {
		return empty, verificationError(err)
	}
	current, valid := canonicalPrincipal(verified.Principal)
	if !valid || current != p || current.TenantID != s.tenant {
		return empty, identity.ErrInvalidCredential
	}
	if verified.ExpiresAt.IsZero() {
		return empty, identity.ErrUnavailable
	}
	// 不把源凭证有效期延长到业务记录期限；缩短/撤销会在每次权威认证时生效。
	var usable bool
	if err := s.pool.QueryRow(ctx, `SELECT $1::timestamptz>clock_timestamp() AND $2::timestamptz>clock_timestamp()`, expiry, verified.ExpiresAt).Scan(&usable); err != nil {
		return empty, identity.ErrUnavailable
	}
	if !usable {
		return empty, identity.ErrInvalidCredential
	}
	return current, nil
}

func verificationError(err error) error {
	if errors.Is(err, identity.ErrInvalidCredential) || errors.Is(err, identity.ErrForbidden) {
		return identity.ErrInvalidCredential
	}
	return identity.ErrUnavailable
}

func (s *Store) PurgeExpired(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM qm_access_tokens WHERE service_scope=$1 AND expires_at<=clock_timestamp()`, s.scope)
	return err
}
