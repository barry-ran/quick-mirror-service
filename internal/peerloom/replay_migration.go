package peerloom

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"
)

// MigrateReplayDomains may only receive freshly authenticated snapshots of the current credential.
// It never guesses an older credential hash or widens matching to every row in a tenant.
func MigrateReplayDomains(ctx context.Context, pool *pgxpool.Pool, scope string, registration *RegistrationClient, control *ControlClient) error {
	r, err := registration.Snapshot()
	if err != nil {
		return err
	}
	c, err := control.Snapshot()
	if err != nil {
		return err
	}
	if r.subject == "" || r.subject != c.subject || r.credential != c.credential {
		return errors.New("PEERLOOM_REPLAY_SUBJECT_UNVERIFIED")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, v := range []struct{ kind, old, new, table string }{{"bootstrap", r.LegacyReplayDomain(), r.ReplayDomain(), "qm_bootstrap_intents"}, {"control", c.LegacyReplayDomain(), c.ReplayDomain(), "qm_control_intents"}} {
		var stored, subject string
		err = tx.QueryRow(ctx, `INSERT INTO qm_peerloom_replay_domains(service_scope,kind,legacy_domain,stable_domain,subject_id)VALUES($1,$2,$3,$4,$5) ON CONFLICT(service_scope,kind,legacy_domain) DO UPDATE SET legacy_domain=qm_peerloom_replay_domains.legacy_domain RETURNING stable_domain,subject_id::text`, scope, v.kind, v.old, v.new, r.subject).Scan(&stored, &subject)
		if err != nil {
			return err
		}
		if stored != v.new || subject != r.subject {
			return errors.New("PEERLOOM_REPLAY_SUBJECT_CONFLICT")
		}
		// Table names are compile-time constants, not input.
		_, err = tx.Exec(ctx, `UPDATE `+v.table+` SET replay_domain=$3 WHERE service_scope=$1 AND replay_domain=$2`, scope, v.old, v.new)
		if err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func MigrateReplaySchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS qm_peerloom_replay_domains(service_scope uuid NOT NULL,kind text NOT NULL,legacy_domain text NOT NULL,stable_domain text NOT NULL,subject_id uuid NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(service_scope,kind,legacy_domain))`)
	return err
}
