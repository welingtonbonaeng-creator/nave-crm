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
const publicUser = (u: any) => ({ username: u.username, name: u.name, role: u.role, nascimento: u.nascimento || "" });
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
