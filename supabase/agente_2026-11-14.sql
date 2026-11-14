alter table nave_users add column if not exists agente boolean not null default false;
update nave_users set agente = true where username = 'well';
create table if not exists agente_config (
  username text primary key references nave_users(username) on delete cascade,
  alerta_numero text, alerta_ativo boolean not null default true,
  atualizado_em timestamptz default now());
create table if not exists agente_precos (
  id bigserial primary key,
  username text not null references nave_users(username) on delete cascade,
  regiao text not null default 'Porto Maravilha', empreendimento text not null, bairro text,
  tipologia text not null, valor numeric, entrega text, observacao text,
  bloqueado boolean not null default false, atualizado_em timestamptz default now());
create table if not exists agente_clientes (
  username text not null references nave_users(username) on delete cascade,
  telefone text not null, nome text, origem text, origem_detalhe text,
  perfil text, empreendimento text, etapa text default 'novo',
  renda text, entrada text, objecoes jsonb not null default '[]', resumo text,
  horas_resposta int[] not null default array_fill(0, array[24]),
  dias_resposta int[] not null default array_fill(0, array[7]),
  msgs_cliente int not null default 0, audios_cliente int not null default 0,
  soma_resposta_min numeric not null default 0, n_respostas int not null default 0,
  ultimo_msg_cliente timestamptz, ultimo_msg_nosso timestamptz, proximo_followup timestamptz,
  passado_humano boolean not null default false,
  aprendizados jsonb not null default '[]',
  criado_em timestamptz default now(), atualizado_em timestamptz default now(),
  primary key (username, telefone));
create table if not exists agente_eventos (
  id bigserial primary key, username text not null, telefone text, tipo text not null,
  dados jsonb, criado_em timestamptz default now());
create index if not exists agente_eventos_user_idx on agente_eventos(username, criado_em desc);
alter table agente_config enable row level security;
alter table agente_precos enable row level security;
alter table agente_clientes enable row level security;
alter table agente_eventos enable row level security;
revoke all on agente_config, agente_precos, agente_clientes, agente_eventos from anon, authenticated;
revoke all on sequence agente_precos_id_seq, agente_eventos_id_seq from anon, authenticated;
