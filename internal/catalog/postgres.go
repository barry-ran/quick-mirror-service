package catalog

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"errors"

	"github.com/barry-ran/quick-mirror-service/internal/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/001_catalog.sql
var migration string

//go:embed migrations/002_runtime.sql
var runtimeMigration string

type Store struct {
	pool   *pgxpool.Pool
	scope  string
	tenant string
}

func NewStore(pool *pgxpool.Pool, scope, tenant string) (*Store, error) {
	scope, validScope := identity.NormalizeUUID(scope)
	tenant, validTenant := identity.NormalizeUUID(tenant)
	if pool == nil || !validScope || !validTenant {
		return nil, ErrInvalidInput
	}
	return &Store{pool: pool, scope: scope, tenant: tenant}, nil
}

// Migrate 由部署迁移入口显式调用，普通请求不能触发 schema 变更。
func (s *Store) Migrate(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, migration+"\n"+runtimeMigration)
	return err
}

func (s *Store) mobile(principal identity.Principal) (string, string, error) {
	id, validID := identity.NormalizeUUID(principal.DeviceID)
	application, validApplication := identity.NormalizeUUID(principal.ApplicationID)
	tenant, validTenant := identity.NormalizeUUID(principal.TenantID)
	if !validID || !validApplication || !validTenant || tenant != s.tenant || principal.Role != identity.Mobile {
		return "", "", identity.ErrForbidden
	}
	return id, application, nil
}

// EnsureRegistration 用于身份交换后的幂等建档；重交换不能清空已有版本、boot或权限快照。
// 它只接受可信手机主体，不从请求正文获取 device/application UUID。
func (s *Store) EnsureRegistration(ctx context.Context, principal identity.Principal) error {
	id, application, err := s.mobile(principal)
	if err != nil {
		return err
	}
	result, err := s.pool.Exec(ctx, `INSERT INTO qm_device_catalog(service_scope,device_uuid,application_id,app_version)
VALUES($1,$2,$3,'') ON CONFLICT(service_scope,device_uuid) DO UPDATE
SET application_id=qm_device_catalog.application_id
WHERE qm_device_catalog.application_id=EXCLUDED.application_id`, s.scope, id, application)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return identity.ErrForbidden
	}
	return nil
}

// Register 仅接受已验证的手机主体；没有录屏权限也允许注册目录。
func (s *Store) Register(ctx context.Context, principal identity.Principal, version string) error {
	id, application, err := s.mobile(principal)
	if err != nil {
		return err
	}
	if !validVersion(version) {
		return ErrInvalidInput
	}
	result, err := s.pool.Exec(ctx, `INSERT INTO qm_device_catalog(service_scope,device_uuid,application_id,app_version)
VALUES($1,$2,$3,$4) ON CONFLICT(service_scope,device_uuid) DO UPDATE
SET app_version=EXCLUDED.app_version,updated_at=clock_timestamp()
WHERE qm_device_catalog.application_id=EXCLUDED.application_id`, s.scope, id, application, version)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return identity.ErrForbidden
	}
	return nil
}

// UpdateStatus 序号只在当前 boot 内递增；已退役 boot 的延迟包不能覆盖新进程状态。
func (s *Store) UpdateStatus(ctx context.Context, principal identity.Principal, status Status) error {
	id, application, err := s.mobile(principal)
	if err != nil {
		return err
	}
	if err := status.validate(); err != nil {
		return err
	}
	boot, _ := identity.NormalizeUUID(status.BootID)
	proofHash, _ := RuntimeProofHash(status.RuntimeProof)
	payload, _ := json.Marshal(status)
	payloadHash := sha256.Sum256(payload)
	permissions, err := json.Marshal(status.Permissions)
	if err != nil {
		return err
	}
	capabilities, err := encodeCapabilities(status.Capabilities)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var currentBoot *string
	var currentSequence int64
	var currentProof, currentPayload []byte
	err = tx.QueryRow(ctx, `SELECT boot_id::text,status_seq,runtime_proof_hash,status_payload_hash FROM qm_device_catalog
WHERE service_scope=$1 AND device_uuid=$2 AND application_id=$3 FOR UPDATE`, s.scope, id, application).Scan(&currentBoot, &currentSequence, &currentProof, &currentPayload)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if currentBoot != nil && *currentBoot == boot {
		if len(currentProof) > 0 && subtle.ConstantTimeCompare(currentProof, proofHash) != 1 {
			return ErrStaleStatus
		}
		if len(proofHash) > 0 && status.Sequence == currentSequence && subtle.ConstantTimeCompare(currentPayload, payloadHash[:]) == 1 {
			return nil
		}
		if status.Sequence <= currentSequence {
			return ErrStaleStatus
		}
	} else {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM qm_device_boots WHERE service_scope=$1 AND device_uuid=$2 AND boot_id=$3)`, s.scope, id, boot).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return ErrStaleStatus
		}
		if _, err := tx.Exec(ctx, `INSERT INTO qm_device_boots(service_scope,device_uuid,boot_id) VALUES($1,$2,$3)`, s.scope, id, boot); err != nil {
			return err
		}
	}
	_, err = tx.Exec(ctx, `UPDATE qm_device_catalog SET boot_id=$3,status_seq=$4,app_version=$5,permissions=$6,capabilities=$7,runtime_proof_hash=$8,status_payload_hash=$9,updated_at=clock_timestamp()
WHERE service_scope=$1 AND device_uuid=$2`, s.scope, id, boot, status.Sequence, status.AppVersion, permissions, capabilities, proofHash, payloadHash[:])
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ResolveBatch 限制单次 SQL 请求大小，不限制目录总设备数；逐项保留非法输入结果。
// 返回权限只是最近快照；调用者必须另查权威 presence/session，不能据此显示当前可操作。
func (s *Store) ResolveBatch(ctx context.Context, principal identity.Principal, values []string) ([]Resolution, error) {
	tenant, ok := identity.NormalizeUUID(principal.TenantID)
	_, validID := identity.NormalizeUUID(principal.DeviceID)
	_, validApplication := identity.NormalizeUUID(principal.ApplicationID)
	if !ok || !validID || !validApplication || tenant != s.tenant || principal.Role != identity.PC {
		return nil, identity.ErrForbidden
	}
	if len(values) > BatchSize {
		return nil, ErrInvalidInput
	}
	result := make([]Resolution, len(values))
	ids := make([]string, 0, len(values))
	for i, value := range values {
		id, valid := identity.NormalizeUUID(value)
		result[i].UUID = value
		if !valid {
			result[i].ErrorCode = "INVALID_UUID"
			continue
		}
		result[i].UUID = id
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return result, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT device_uuid::text,app_version,permissions,capabilities FROM qm_device_catalog WHERE service_scope=$1 AND device_uuid=ANY($2::uuid[])`, s.scope, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	found := make(map[string]Device)
	for rows.Next() {
		var d Device
		var permissions, capabilities []byte
		if err := rows.Scan(&d.UUID, &d.AppVersion, &permissions, &capabilities); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(permissions, &d.Permissions); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(capabilities, &d.Capabilities); err != nil {
			return nil, err
		}
		found[d.UUID] = d
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range result {
		if d, exists := found[result[i].UUID]; exists {
			result[i].Found = true
			result[i].Device = &d
		}
	}
	return result, nil
}
