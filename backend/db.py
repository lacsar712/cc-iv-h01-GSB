import os
import psycopg
from psycopg.rows import dict_row

DSN = os.environ.get("DATABASE_URL", "postgresql://app:app@localhost:54402/pvivscan")


def connect():
    return psycopg.connect(DSN, row_factory=dict_row)


SCHEMA = """
CREATE TABLE IF NOT EXISTS iv_scans (
    id serial PRIMARY KEY,
    string_code text NOT NULL,
    voc_v double precision NOT NULL,
    isc_a double precision NOT NULL,
    fill_factor double precision NOT NULL,
    status text NOT NULL DEFAULT 'pending',
    verdict text,
    reason text,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL,
    processed_at timestamptz
);

-- 一致性约束：pending 不得带结论；done 必须结论/脚注/处理时间齐全；
-- 结论只能是合格/衰减，且必须与 0.72 压线规则一致。杜绝半填或被改写的脏记录。
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'iv_scans_status_chk') THEN
        ALTER TABLE iv_scans ADD CONSTRAINT iv_scans_status_chk
            CHECK (status IN ('pending', 'done'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'iv_scans_pending_chk') THEN
        ALTER TABLE iv_scans ADD CONSTRAINT iv_scans_pending_chk
            CHECK (status <> 'pending'
                   OR (verdict IS NULL AND reason IS NULL AND processed_at IS NULL));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'iv_scans_done_chk') THEN
        ALTER TABLE iv_scans ADD CONSTRAINT iv_scans_done_chk
            CHECK (status <> 'done'
                   OR (verdict IS NOT NULL AND reason IS NOT NULL
                       AND processed_at IS NOT NULL));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'iv_scans_verdict_chk') THEN
        ALTER TABLE iv_scans ADD CONSTRAINT iv_scans_verdict_chk
            CHECK (verdict IS NULL OR verdict IN ('合格', '衰减'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'iv_scans_verdict_rule_chk') THEN
        ALTER TABLE iv_scans ADD CONSTRAINT iv_scans_verdict_rule_chk
            CHECK (
                verdict IS NULL
                OR (fill_factor >= 0.72 AND verdict = '合格')
                OR (fill_factor <  0.72 AND verdict = '衰减')
            );
    END IF;
END $$;

CREATE OR REPLACE FUNCTION notify_iv_scan() RETURNS trigger AS $$
BEGIN
  PERFORM pg_notify('iv_scan_new', NEW.id::text);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS trg_iv_scan_notify ON iv_scans;
CREATE TRIGGER trg_iv_scan_notify
AFTER INSERT ON iv_scans
FOR EACH ROW EXECUTE FUNCTION notify_iv_scan();
"""
