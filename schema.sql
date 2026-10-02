CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  username VARCHAR(80) UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role VARCHAR(20) NOT NULL DEFAULT 'sub' CHECK (role IN ('master','sub')),
  balance NUMERIC(12,2) NOT NULL DEFAULT 0,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS khatians (
  id UUID PRIMARY KEY,
  khatian_no VARCHAR(100) NOT NULL,
  district VARCHAR(100) NOT NULL,
  upazila VARCHAR(100),
  mouza VARCHAR(150),
  jl_no VARCHAR(100),
  record_type VARCHAR(50) NOT NULL DEFAULT 'বি.আর.এস',
  owner TEXT NOT NULL,
  guardian TEXT,
  dag VARCHAR(100),
  land_class VARCHAR(150) DEFAULT 'ভিটি',
  land_amount VARCHAR(150),
  address TEXT,
  remarks TEXT,
  created_by BIGINT NOT NULL REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_khatians_khatian_no ON khatians(khatian_no);
CREATE INDEX IF NOT EXISTS idx_khatians_owner ON khatians(owner);
CREATE INDEX IF NOT EXISTS idx_khatians_created_by ON khatians(created_by);

CREATE TABLE IF NOT EXISTS recharge_requests (
  id UUID PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id),
  amount NUMERIC(12,2) NOT NULL CHECK (amount >= 10),
  txn_id VARCHAR(150) NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected')),
  reviewed_by BIGINT REFERENCES users(id),
  reviewed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_recharge_status ON recharge_requests(status);

CREATE TABLE IF NOT EXISTS wallet_transactions (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id),
  type VARCHAR(30) NOT NULL CHECK (type IN ('recharge','print_charge','adjustment')),
  amount NUMERIC(12,2) NOT NULL,
  reference_id UUID,
  note TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_wallet_user ON wallet_transactions(user_id);
