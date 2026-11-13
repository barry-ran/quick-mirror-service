package control

import (
	"context"
	"errors"

	"github.com/barry-ran/quick-mirror-service/internal/binding"
	"github.com/jackc/pgx/v5"
)

// BindingAuthority 使用调用方的短事务读取权威关系，不进行网络调用。
type BindingAuthority interface {
	Active(context.Context, pgx.Tx, string, string) (binding.Relation, error)
}

func (s *Store) SetBindings(authority BindingAuthority) { s.bindings = authority }

func (s *Store) activeBinding(ctx context.Context, tx pgx.Tx, pc, mobile string) (binding.Relation, error) {
	if s.bindings == nil {
		return binding.Relation{}, fail("NOT_BOUND", 409)
	}
	return s.bindings.Active(ctx, tx, pc, mobile)
}

func (s *Store) bindingValid(ctx context.Context, tx pgx.Tx, i Intent) (bool, error) {
	b, err := s.activeBinding(ctx, tx, i.Owner, i.Target)
	if err != nil {
		var business *binding.Error
		var local *Error
		if errors.As(err, &business) || errors.As(err, &local) {
			return false, nil
		}
		return false, err
	}
	return b.ID == i.BindingID && b.Revision == i.BindingRevision, nil
}

// 无有效关系的旧意图只能查询关闭状态、排空，不能再取得业务授权。
func (s *Store) checkBinding(ctx context.Context, id string) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	i, err := s.load(ctx, tx, id)
	if err != nil {
		return err
	}
	if i.State != "reserving" && i.State != "active" {
		return nil
	}
	valid, err := s.bindingValid(ctx, tx, i)
	if err != nil || valid {
		return err
	}
	if err = bump(i); err != nil {
		return err
	}
	if !i.dispatched {
		err = s.finish(ctx, tx, id, "failed")
	} else {
		_, err = tx.Exec(ctx, `UPDATE qm_control_intents SET state='draining',close_reason='unbound',revision=revision+1 WHERE service_scope=$1 AND id=$2`, s.scope, id)
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// 完成标志只在所有旧控制均已安全排空后写回；外部撤销失败不影响关系revoked事实。
func (s *Store) completeBindingClosures(ctx context.Context) error {
	coordinator, ok := s.bindings.(interface {
		PendingClosures(context.Context, int) ([]binding.Relation, error)
		CompleteClosure(context.Context, pgx.Tx, string) error
	})
	if !ok {
		return nil
	}
	pending, err := coordinator.PendingClosures(ctx, 100)
	if err != nil {
		return err
	}
	for _, b := range pending {
		tx, e := s.begin(ctx)
		if e != nil {
			return e
		}
		var occupied bool
		e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM qm_control_intents WHERE service_scope=$1 AND binding_id=$2 AND state IN ('reserving','active','draining'))`, s.scope, b.ID).Scan(&occupied)
		if e == nil && !occupied {
			e = coordinator.CompleteClosure(ctx, tx, b.ID)
		}
		if e == nil {
			e = tx.Commit(ctx)
		} else {
			tx.Rollback(ctx)
		}
		if e != nil {
			return e
		}
	}
	return nil
}
