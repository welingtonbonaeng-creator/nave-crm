// Nave CRM — API autenticada. Todo acesso ao banco passa por aqui (service role).
// O navegador nunca lê as tabelas diretamente.
import { createClient } from "npm:@supabase/supabase-js@2.45.4";
import bcrypt from "npm:bcryptjs@2.4.3";

const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
  auth: { persistSession: false },
});
const SECRET = Deno.env.get("NAVE_SESSION_SECRET")!;
const ORIGINS = ["https://welingtonbonaeng-creator.github.io", "http://localhost:3000", "http://localhost:5173", "http://127.0.0.1:5500"];
const SESSION_DAYS = 30;

const enc = new TextEncoder();
const b64u = (b: Uint8Array) => btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const fromB64u = (s: string) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
let _key: CryptoKey | null = null;
async function hmacKey() {
  if (!_key) _key = await crypto.subtle.importKey("raw", enc.encode(SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
  return _key;
}
async function signToken(username: string, role: string) {
  const body = b64u(enc.encode(JSON.stringify({ u: username, r: role, exp: Date.now() + SESSION_DAYS * 864e5 })));
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", await hmacKey(), enc.encode(body)));
  return `${body}.${b64u(sig)}`;
}
async function readToken(tok?: string) {
  if (!tok || !tok.includes(".")) return null;
  const [body, sig] = tok.split(".");
  try {
    const ok = await crypto.subtle.verify("HMAC", await hmacKey(), fromB64u(sig), enc.encode(body));
    if (!ok) return null;
    const p = JSON.parse(new TextDecoder().decode(fromB64u(body)));
    if (!p.exp || p.exp < Date.now()) return null;
    return p as { u: string; r: string };
  } catch { return null; }
}
function randomCode(n = 8) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const r = crypto.getRandomValues(new Uint8Array(n));
  return Array.from(r, (x) => chars[x % chars.length]).join("");
}
const publicUser = (u: any) => ({ username: u.username, name: u.name, role: u.role, nascimento: u.nascimento || "", agente: !!u.agente });
const AGENT_KEY = Deno.env.get("NAVE_AGENT_KEY") || "";
const normFone = (s: unknown) => { const d = String(s || "").replace(/\D/g, ""); return d ? "+" + d : ""; };
// hora/dia no fuso de Brasília (o agente responde no horário do Well)
function brt(iso: string) {
  const d = new Date(iso);
  const p = new Intl.DateTimeFormat("en-US", { timeZone: "America/Sao_Paulo", hour: "numeric", hour12: false, weekday: "short" }).formatToParts(d);
  const h = Number(p.find((x) => x.type === "hour")!.value) % 24;
  const w = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"].indexOf(p.find((x) => x.type === "weekday")!.value);
  return { h, w };
}
const CLIENTE_CAMPOS = ["nome", "origem", "origem_detalhe", "perfil", "empreendimento", "etapa", "renda", "entrada", "resumo", "proximo_followup", "passado_humano", "objecoes"];
async function agenteUser(s: Ctx) {
  const u = await getUser(s!.u);
  if (!u?.agente) fail(403, "Agente não liberado para este usuário");
  return u;
}
const normUser = (s: unknown) => String(s || "").trim().toLowerCase().replace(/\s/g, "");

class HttpErr extends Error { constructor(public status: number, msg: string) { super(msg); } }
const fail = (status: number, msg: string): never => { throw new HttpErr(status, msg); };

async function getUser(username: string) {
  const { data } = await db.from("nave_users").select("*").eq("username", username).maybeSingle();
  return data;
}

// Tentativas de login: limite simples em memória por instância
const attempts = new Map<string, { n: number; t: number }>();
function checkRate(key: string) {
  const now = Date.now(), a = attempts.get(key);
  if (a && now - a.t < 15 * 60e3 && a.n >= 10) fail(429, "Muitas tentativas. Aguarde alguns minutos.");
}
function noteFail(key: string) {
  const now = Date.now(), a = attempts.get(key);
  if (!a || now - a.t > 15 * 60e3) attempts.set(key, { n: 1, t: now }); else a.n++;
}

type Ctx = { u: string; r: string } | null;
const actions: Record<string, (b: any, s: Ctx) => Promise<unknown>> = {
  // ── Público ──
  async login(b) {
    const username = normUser(b.username), password = String(b.password || "");
    checkRate(username);
    const u = await getUser(username);
    if (!u || !(await bcrypt.compare(password, u.password))) { noteFail(username); fail(401, "Usuário ou senha incorretos."); }
    attempts.delete(username);
    return { token: await signToken(u.username, u.role), user: publicUser(u) };
  },
  async register(b) {
    const name = String(b.name || "").trim(), user = normUser(b.username), pass = String(b.password || "");
    const code = String(b.code || "").trim();
    if (!name) fail(400, "Informe seu nome completo");
    if (!user) fail(400, "Informe um login");
    if (pass.length < 4) fail(400, "Senha deve ter pelo menos 4 caracteres");
    if (!code) fail(400, "Código inválido ou já utilizado. Solicite um novo ao administrador.");
    let requestId: number | null = null, codeValid = false;
    const { data: cfg } = await db.from("nave_config").select("value").eq("key", "access_code").maybeSingle();
    if (cfg?.value && code.toLowerCase() === cfg.value.toLowerCase()) codeValid = true;
    if (!codeValid) {
      const { data: req } = await db.from("nave_requests").select("id").eq("code", code).eq("status", "approved").maybeSingle();
      if (req) { codeValid = true; requestId = req.id; }
    }
    if (!codeValid) fail(400, "Código inválido ou já utilizado. Solicite um novo ao administrador.");
    if (await getUser(user)) fail(409, "Este login já existe");
    const { error } = await db.from("nave_users").insert({
      username: user, name, password: await bcrypt.hash(pass, 10), role: "corretor", nascimento: String(b.nascimento || ""),
    });
    if (error) fail(500, "Erro ao criar conta: " + error.message);
    if (requestId) await db.from("nave_requests").update({ status: "used" }).eq("id", requestId);
    else await db.from("nave_config").upsert({ key: "access_code", value: "" }, { onConflict: "key" });
    const u = await getUser(user);
    return { token: await signToken(u.username, u.role), user: publicUser(u) };
  },
  async request_access(b) {
    const name = String(b.name || "").trim(), user = normUser(b.username);
    if (!name) fail(400, "Informe seu nome completo");
    if (!user) fail(400, "Informe o login desejado");
    if (await getUser(user)) fail(409, "Este login já está em uso, escolha outro");
    const ticket = randomCode(24);
    const { data, error } = await db.from("nave_requests").insert({ name, username: user, status: "pending", ticket }).select("id").single();
    if (error) fail(500, "Erro ao enviar: " + error.message);
    return { id: data!.id, ticket };
  },
  async check_request(b) {
    const { data } = await db.from("nave_requests").select("status,code,ticket").eq("id", Number(b.id)).maybeSingle();
    if (!data || !data.ticket || data.ticket !== String(b.ticket || "")) fail(404, "Solicitação não encontrada");
    return { status: data!.status, code: data!.status === "approved" ? data!.code : null };
  },

  // ── Logado ──
  async me(_b, s) {
    const u = await getUser(s!.u);
    if (!u) fail(401, "Sessão inválida");
    return { user: publicUser(u) };
  },
  async load_state(_b, s) {
    const { data } = await db.from("nave_state").select("leads,eventos,imoveis,vendas,next_id,pipe_ordem,alertas").eq("username", s!.u).maybeSingle();
    return { state: data };
  },
  async save_state(b, s) {
    const p = b.state || {};
    const row = {
      username: s!.u,
      leads: Array.isArray(p.leads) ? p.leads : [],
      eventos: Array.isArray(p.eventos) ? p.eventos : [],
      imoveis: Array.isArray(p.imoveis) ? p.imoveis : [],
      vendas: Array.isArray(p.vendas) ? p.vendas : [],
      next_id: Number(p.next_id) || 1,
      pipe_ordem: p.pipe_ordem ?? null,
      alertas: p.alertas ?? null,
      updated_at: new Date().toISOString(),
    };
    const { error } = await db.from("nave_state").upsert(row, { onConflict: "username" });
    if (error) fail(500, error.message);
    return { ok: true };
  },
  async change_password(b, s) {
    const u = await getUser(s!.u);
    if (!u || !(await bcrypt.compare(String(b.atual || ""), u.password))) fail(400, "Senha atual incorreta");
    const nova = String(b.nova || "");
    if (nova.length < 4) fail(400, "Nova senha deve ter mínimo 4 caracteres");
    await db.from("nave_users").update({ password: await bcrypt.hash(nova, 10) }).eq("username", s!.u);
    return { ok: true };
  },

  // ── Agente (tela do corretor) ──
  async agente_get(_b, s) {
    await agenteUser(s);
    const [cfg, precos, clientes] = await Promise.all([
      db.from("agente_config").select("alerta_numero,alerta_ativo").eq("username", s!.u).maybeSingle(),
      db.from("agente_precos").select("*").eq("username", s!.u).order("regiao").order("empreendimento").order("valor", { nullsFirst: false }),
      db.from("agente_clientes").select("*").eq("username", s!.u).order("ultimo_msg_cliente", { ascending: false, nullsFirst: false }).limit(500),
    ]);
    return { config: cfg.data || {}, precos: precos.data || [], clientes: clientes.data || [] };
  },
  async agente_set_config(b, s) {
    await agenteUser(s);
    let numero = normFone(b.alerta_numero);
    if (numero.length === 11 || numero.length === 12) numero = "+55" + numero.slice(1); // digitado sem DDI (DDD + número)
    if (b.alerta_numero && (numero.length < 12 || numero.length > 16)) fail(400, "Número inválido. Use DDI + DDD + número, ex.: 55 21 99999-9999");
    await db.from("agente_config").upsert({ username: s!.u, alerta_numero: numero || null, alerta_ativo: b.alerta_ativo !== false, atualizado_em: new Date().toISOString() }, { onConflict: "username" });
    return { ok: true, alerta_numero: numero };
  },
  async agente_preco_salvar(b, s) {
    await agenteUser(s);
    const row: any = {
      username: s!.u, regiao: String(b.regiao || "Porto Maravilha").trim(), empreendimento: String(b.empreendimento || "").trim(),
      bairro: String(b.bairro || "").trim() || null, tipologia: String(b.tipologia || "").trim(),
      valor: b.valor === "" || b.valor == null ? null : Number(b.valor), entrega: String(b.entrega || "").trim() || null,
      observacao: String(b.observacao || "").trim() || null, bloqueado: !!b.bloqueado, atualizado_em: new Date().toISOString(),
    };
    if (!row.empreendimento || !row.tipologia) fail(400, "Informe empreendimento e tipologia");
    if (row.valor != null && !(row.valor > 0)) fail(400, "Valor inválido");
    const q = b.id ? db.from("agente_precos").update(row).eq("id", Number(b.id)).eq("username", s!.u) : db.from("agente_precos").insert(row);
    const { error } = await q;
    if (error) fail(500, error.message);
    return { ok: true };
  },
  async agente_preco_excluir(b, s) {
    await agenteUser(s);
    await db.from("agente_precos").delete().eq("id", Number(b.id)).eq("username", s!.u);
    return { ok: true };
  },

  // ── Admin ──
  async admin_users() {
    const { data } = await db.from("nave_users").select("username,name,role,nascimento").order("name");
    return { users: data || [] };
  },
  async admin_create_user(b) {
    const username = normUser(b.username), name = String(b.name || "").trim(), password = String(b.password || "");
    const role = b.role === "admin" ? "admin" : "corretor";
    if (!username || !name || !password) fail(400, "Preencha todos os campos");
    if (password.length < 4) fail(400, "Senha mínimo 4 caracteres");
    if (await getUser(username)) fail(409, "Usuário já existe");
    const { error } = await db.from("nave_users").insert({ username, name, password: await bcrypt.hash(password, 10), role, nascimento: "" });
    if (error) fail(500, "Erro: " + error.message);
    return { ok: true };
  },
  async admin_delete_user(b, s) {
    const username = normUser(b.username);
    if (username === s!.u) fail(400, "Você não pode remover a si mesmo");
    await db.from("nave_state").delete().eq("username", username);
    await db.from("nave_users").delete().eq("username", username);
    return { ok: true };
  },
  async admin_reset_password(b) {
    const nova = String(b.password || "");
    if (nova.length < 4) fail(400, "Senha mínimo 4 caracteres");
    const { error } = await db.from("nave_users").update({ password: await bcrypt.hash(nova, 10) }).eq("username", normUser(b.username));
    if (error) fail(500, error.message);
    return { ok: true };
  },
  async admin_requests() {
    const { data } = await db.from("nave_requests").select("id,name,username,status,code,created_at").order("created_at", { ascending: false });
    return { requests: data || [] };
  },
  async admin_approve_request(b) {
    const code = randomCode();
    const { error } = await db.from("nave_requests").update({ status: "approved", code }).eq("id", Number(b.id));
    if (error) fail(500, error.message);
    return { code };
  },
  async admin_get_code() {
    const { data } = await db.from("nave_config").select("value").eq("key", "access_code").maybeSingle();
    return { code: data?.value || "" };
  },
  async admin_set_code(b) {
    const code = b.clear ? "" : randomCode();
    await db.from("nave_config").upsert({ key: "access_code", value: code }, { onConflict: "key" });
    return { code };
  },
};
const PUBLIC = new Set(["login", "register", "request_access", "check_request"]);

// ── Entrada do agente (servidor do WhatsApp → CRM). Só com a chave secreta x-agent-key. ──
const agentActions: Record<string, (b: any) => Promise<unknown>> = {
  // Cada mensagem trocada alimenta o "perfil vivo": horário em que o cliente responde, velocidade, se prefere áudio.
  async agente_mensagem(b) {
    const username = normUser(b.username), telefone = normFone(b.telefone);
    if (!username || !telefone) fail(400, "username e telefone obrigatórios");
    const u = await getUser(username);
    if (!u?.agente) fail(403, "Agente não liberado para este usuário");
    const em = b.em ? new Date(b.em).toISOString() : new Date().toISOString();
    const de = b.de === "nos" ? "nos" : "cliente";
    const { data: c0 } = await db.from("agente_clientes").select("*").eq("username", username).eq("telefone", telefone).maybeSingle();
    const c: any = c0 || { username, telefone, horas_resposta: Array(24).fill(0), dias_resposta: Array(7).fill(0), msgs_cliente: 0, audios_cliente: 0, soma_resposta_min: 0, n_respostas: 0 };
    if (b.nome && !c.nome) c.nome = String(b.nome).slice(0, 120);
    if (b.origem && !c.origem) { c.origem = String(b.origem).slice(0, 60); c.origem_detalhe = b.origem_detalhe ? String(b.origem_detalhe).slice(0, 300) : null; }
    if (de === "cliente") {
      const { h, w } = brt(em);
      c.horas_resposta[h]++; c.dias_resposta[w]++; c.msgs_cliente++;
      if (b.tipo === "audio") c.audios_cliente++;
      // tempo de resposta do cliente: só conta se a última mensagem foi nossa e ele respondeu em até 3 dias
      if (c.ultimo_msg_nosso && (!c.ultimo_msg_cliente || c.ultimo_msg_nosso > c.ultimo_msg_cliente)) {
        const min = (Date.parse(em) - Date.parse(c.ultimo_msg_nosso)) / 60000;
        if (min >= 0 && min < 4320) { c.soma_resposta_min = Number(c.soma_resposta_min) + min; c.n_respostas++; }
      }
      c.ultimo_msg_cliente = em;
    } else c.ultimo_msg_nosso = em;
    c.atualizado_em = new Date().toISOString();
    const { error } = await db.from("agente_clientes").upsert(c, { onConflict: "username,telefone" });
    if (error) fail(500, error.message);
    return { ok: true };
  },
  // O agente grava o que entendeu (etapa, perfil, objeções...) e aprendizados sobre o cliente.
  async agente_cliente(b) {
    const username = normUser(b.username), telefone = normFone(b.telefone);
    if (!username || !telefone) fail(400, "username e telefone obrigatórios");
    const upd: any = { username, telefone, atualizado_em: new Date().toISOString() };
    for (const k of CLIENTE_CAMPOS) if (k in (b.campos || {})) upd[k] = b.campos[k];
    if (b.aprendizado) {
      const { data } = await db.from("agente_clientes").select("aprendizados").eq("username", username).eq("telefone", telefone).maybeSingle();
      upd.aprendizados = [...(data?.aprendizados || []), { em: upd.atualizado_em, texto: String(b.aprendizado).slice(0, 500), aprovado: false }];
    }
    const { error } = await db.from("agente_clientes").upsert(upd, { onConflict: "username,telefone" });
    if (error) fail(500, error.message);
    return { ok: true };
  },
  async agente_evento(b) {
    const username = normUser(b.username);
    if (!username || !b.tipo) fail(400, "username e tipo obrigatórios");
    await db.from("agente_eventos").insert({ username, telefone: normFone(b.telefone) || null, tipo: String(b.tipo).slice(0, 40), dados: b.dados || null });
    return { ok: true };
  },
  // O que o agente precisa saber antes de responder: preços válidos, número de alerta e o perfil do cliente.
  async agente_contexto(b) {
    const username = normUser(b.username), telefone = normFone(b.telefone);
    const [cfg, precos, cli] = await Promise.all([
      db.from("agente_config").select("alerta_numero,alerta_ativo").eq("username", username).maybeSingle(),
      db.from("agente_precos").select("regiao,empreendimento,bairro,tipologia,valor,entrega,observacao,bloqueado,atualizado_em").eq("username", username),
      telefone ? db.from("agente_clientes").select("*").eq("username", username).eq("telefone", telefone).maybeSingle() : Promise.resolve({ data: null }),
    ]);
    return { config: cfg.data, precos: precos.data || [], cliente: cli.data };
  },
};
function safeEq(a: string, b: string) {
  if (!a || a.length !== b.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

Deno.serve(async (req) => {
  const origin = req.headers.get("origin") || "";
  const cors = {
    "Access-Control-Allow-Origin": ORIGINS.includes(origin) ? origin : ORIGINS[0],
    "Access-Control-Allow-Headers": "content-type, authorization, apikey, x-client-info, x-nave-token",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Vary": "Origin",
  };
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });
  try {
    if (req.method !== "POST") fail(405, "Método não permitido");
    const b = await req.json().catch(() => ({}));
    if (agentActions[b.action]) {
      if (!safeEq(req.headers.get("x-agent-key") || "", AGENT_KEY)) fail(401, "Chave do agente inválida");
      return json(200, await agentActions[b.action](b));
    }
    const fn = actions[b.action];
    if (!fn) fail(400, "Ação desconhecida");
    let s: Ctx = null;
    if (!PUBLIC.has(b.action)) {
      s = await readToken(req.headers.get("x-nave-token") || "");
      if (!s) fail(401, "Sessão expirada. Entre novamente.");
      if (String(b.action).startsWith("admin_")) {
        const u = await getUser(s!.u); // papel conferido no banco, não só no token
        if (!u || u.role !== "admin") fail(403, "Acesso restrito ao administrador");
      }
    }
    return json(200, await fn(b, s));
  } catch (e) {
    if (e instanceof HttpErr) return json(e.status, { error: e.message });
    console.error(e);
    return json(500, { error: "Erro interno" });
  }
});
