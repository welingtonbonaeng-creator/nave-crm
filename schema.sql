-- ════════════════════════════════════════════════
-- Nave CRM — Schema Supabase
-- Execute este SQL no SQL Editor do seu projeto
-- ════════════════════════════════════════════════

-- Usuários
CREATE TABLE IF NOT EXISTS nave_users (
  username   TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  password   TEXT NOT NULL,
  role       TEXT NOT NULL DEFAULT 'corretor',
  nascimento TEXT DEFAULT ''
);

-- Estado por usuário (todos os dados do CRM)
CREATE TABLE IF NOT EXISTS nave_state (
  username   TEXT PRIMARY KEY REFERENCES nave_users(username) ON DELETE CASCADE,
  leads      JSONB NOT NULL DEFAULT '[]',
  eventos    JSONB NOT NULL DEFAULT '[]',
  imoveis    JSONB NOT NULL DEFAULT '[]',
  vendas     JSONB NOT NULL DEFAULT '[]',
  next_id    INTEGER NOT NULL DEFAULT 1,
  pipe_ordem JSONB,
  alertas    JSONB,
  updated_at TIMESTAMPTZ DEFAULT now()
);

-- Configurações globais (código de acesso, etc)
CREATE TABLE IF NOT EXISTS nave_config (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- Admin padrão
INSERT INTO nave_users (username, name, password, role)
VALUES ('carioca', 'Carlos Henrique', '1406', 'admin')
ON CONFLICT DO NOTHING;

-- Código de convite (vazio = bloqueado; admin gera via painel)
INSERT INTO nave_config (key, value)
VALUES ('access_code', '')
ON CONFLICT DO NOTHING;

-- RLS: habilitar e permitir acesso via anon key (controle no app)
ALTER TABLE nave_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE nave_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE nave_config ENABLE ROW LEVEL SECURITY;

CREATE POLICY "nave_users_all"  ON nave_users  FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "nave_state_all"  ON nave_state  FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "nave_config_all" ON nave_config FOR ALL USING (true) WITH CHECK (true);
