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
const DONO = Deno.env.get("NAVE_DONO") || "well"; // dono do produto: único que libera o agente

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
  // Chave pessoal do copiloto (para os comandos /rascunhos e /aprendizado no Claude Code de cada um).
  // Mostrada uma única vez; no banco fica só o hash. Gerar de novo invalida a anterior.
  async agente_gerar_chave(_b, s) {
    await agenteUser(s);
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    const chave = "ncp_" + Array.from(bytes, (x) => x.toString(16).padStart(2, "0")).join("");
    await db.from("agente_config").upsert({ username: s!.u, chave_copiloto_hash: await sha256hex(chave), atualizado_em: new Date().toISOString() }, { onConflict: "username" });
    return { chave };
  },
  // ── CRM: sincronização com as abas (Pipeline, Agenda, Imóveis, Vendas) ──
  async agente_sync(_b, s) {
    await agenteUser(s);
    const [cli, prec, rasc] = await Promise.all([
      db.from("agente_clientes").select("telefone,nome,origem,etapa,perfil,empreendimento,renda,entrada,resumo,proximo_followup,passado_humano,atualizado_em,quente,quente_manual").eq("username", s!.u).eq("crm_ignorar", false),
      db.from("agente_precos").select("empreendimento,bairro,tipologia,valor,entrega,bloqueado").eq("username", s!.u),
      db.from("agente_rascunhos").select("id,telefone,acao,motivo,prioridade,status,criado_em").eq("username", s!.u).order("criado_em", { ascending: false }).limit(300),
    ]);
    const prio = new Map<string, number>();
    const tarefas: any[] = [];
    for (const r of rasc.data || []) {
      if (!prio.has(r.telefone) && r.prioridade) prio.set(r.telefone, r.prioridade);
      if (r.acao === "passar_humano" && r.status === "pendente") tarefas.push({ id: r.id, telefone: r.telefone, motivo: r.motivo, em: r.criado_em });
    }
    return { clientes: (cli.data || []).map((c: any) => ({ ...c, prioridade: prio.get(c.telefone) || null, eh_quente: !['vendido', 'perdido'].includes(c.etapa) && (c.quente_manual === true || (c.quente_manual !== false && !!c.quente)) })), precos: prec.data || [], tarefas };
  },
  // O CRM avisa o agente do que aconteceu fora do WhatsApp (venda, perda, visita) → vira aprendizado
  async agente_crm_evento(b, s) {
    await agenteUser(s);
    const telefone = normFone(b.telefone);
    const tipo = ["venda", "perdido", "visita", "removido"].includes(b.tipo) ? b.tipo : null;
    if (!telefone || !tipo) fail(400, "telefone e tipo obrigatórios");
    if (tipo === "removido") { // você apagou o card no CRM: o agente não recria
      await db.from("agente_clientes").update({ crm_ignorar: true }).eq("username", s!.u).eq("telefone", telefone);
      return { ok: true };
    }
    await db.from("agente_eventos").insert({ username: s!.u, telefone, tipo: "crm_" + tipo, dados: b.dados || null });
    const etapa = tipo === "venda" ? "vendido" : tipo === "perdido" ? "perdido" : "visita";
    await db.from("agente_clientes").update({ etapa, atualizado_em: new Date().toISOString() }).eq("username", s!.u).eq("telefone", telefone);
    return { ok: true };
  },
  // ── Painel de Metas: conversas por dia (clientes distintos que escreveram), no horário de Brasília ──
  async agente_conversas_mes(b, s) {
    await agenteUser(s);
    const ano = Number(b.ano), mes = Number(b.mes); // mes 0-11
    if (!(ano > 2000) || !(mes >= 0 && mes <= 11)) fail(400, "Mês inválido");
    const H3 = 3 * 3600e3;
    const ini = new Date(Date.UTC(ano, mes, 1) + H3).toISOString();
    const fim = new Date(Date.UTC(ano, mes + 1, 1) + H3).toISOString();
    const { data } = await db.from("agente_mensagens").select("telefone,em").eq("username", s!.u).eq("de", "cliente").gte("em", ini).lt("em", fim).limit(20000);
    const dias: Record<string, Set<string>> = {};
    for (const m of data || []) {
      const d = new Date(Date.parse(m.em) - H3).toISOString().slice(0, 10);
      (dias[d] ||= new Set()).add(m.telefone);
    }
    const porDia = Object.fromEntries(Object.entries(dias).map(([d, set]) => [d, set.size]));
    const totalMes = new Set((data || []).map((m: any) => m.telefone)).size; // clientes únicos no mês
    return { por_dia: porDia, clientes_unicos_mes: totalMes, meta_dia: 10 };
  },
  // ── 🔥 Quentes: marcados pelo agente (quente ou prioridade ≥ 7) ou por você; sua marcação manda ──
  async agente_quentes(_b, s) {
    await agenteUser(s);
    const { data } = await db.from("agente_clientes")
      .select("telefone,nome,etapa,perfil,empreendimento,resumo,prioridade,quente,quente_manual,ultimo_msg_cliente,ultimo_msg_nosso")
      .eq("username", s!.u).eq("crm_ignorar", false);
    const lista = (data || []).filter((c: any) => !["vendido", "perdido"].includes(c.etapa) && (c.quente_manual === true || (c.quente_manual !== false && c.quente)))
      .map((c: any) => ({ ...c, aguardando: !!c.ultimo_msg_cliente && (!c.ultimo_msg_nosso || c.ultimo_msg_cliente > c.ultimo_msg_nosso) }))
      .sort((a: any, b: any) => (b.prioridade || 0) - (a.prioridade || 0) || String(b.ultimo_msg_cliente || "").localeCompare(String(a.ultimo_msg_cliente || "")));
    return { quentes: lista };
  },
  async agente_quente_marcar(b, s) {
    await agenteUser(s);
    const v = b.quente === true ? true : b.quente === false ? false : null; // null = volta a decisão pro agente
    await db.from("agente_clientes").update({ quente_manual: v }).eq("username", s!.u).eq("telefone", normFone(b.telefone));
    return { ok: true };
  },
  // ── CRM: conversas esquecidas (última mensagem é do cliente e ninguém respondeu) ──
  async agente_sem_resposta(b, s) {
    await agenteUser(s);
    const minimoMin = Math.max(Number(b.minutos) || 30, 5);
    const desde = new Date(Date.now() - 7 * 864e5).toISOString();
    const [msgs, clis, rasc] = await Promise.all([
      db.from("agente_mensagens").select("telefone,de,texto,tipo,em").eq("username", s!.u).gte("em", desde).order("em", { ascending: false }).limit(2000),
      db.from("agente_clientes").select("telefone,nome,sem_resposta_dispensado_em,crm_ignorar").eq("username", s!.u),
      db.from("agente_rascunhos").select("telefone").eq("username", s!.u).eq("status", "pendente"),
    ]);
    const cm = new Map((clis.data || []).map((c: any) => [c.telefone, c]));
    const comSugestao = new Set((rasc.data || []).map((r: any) => r.telefone));
    const ultima = new Map<string, any>();
    for (const m of msgs.data || []) if (!ultima.has(m.telefone)) ultima.set(m.telefone, m);
    // mensagem que não pede resposta: até 4 palavras, todas de agradecimento/confirmação ou emoji
    const PALAVRAS_OK = new Set(["ok", "okk", "okay", "blz", "beleza", "obrigado", "obrigada", "obg", "brigado", "vlw", "valeu", "show", "top", "fechou", "certo", "perfeito", "joia", "jóia", "tá", "ta", "bom", "entendi", "combinado", "tmj"]);
    const trivial = (t: string) => {
      const tk = t.toLowerCase().replace(/[.!,;:]/g, " ").split(/\s+/).filter(Boolean);
      return tk.length > 0 && tk.length <= 4 && tk.every((w) => PALAVRAS_OK.has(w) || /^[\p{Extended_Pictographic}\u{1F3FB}-\u{1F3FF}‍️]+$/u.test(w));
    };
    const agora = Date.now(); const lista: any[] = [];
    for (const [tel, m] of ultima) {
      if (m.de !== "cliente") continue;
      const c: any = cm.get(tel) || {};
      if (c.crm_ignorar) continue;
      if (m.tipo === "texto" && m.texto && trivial(m.texto)) continue;
      if (c.sem_resposta_dispensado_em && Date.parse(c.sem_resposta_dispensado_em) >= Date.parse(m.em)) continue;
      const min = Math.round((agora - Date.parse(m.em)) / 60000);
      if (min < minimoMin) continue;
      lista.push({ telefone: tel, nome: c.nome || null, texto: m.texto ? m.texto.slice(0, 160) : `(${m.tipo})`, em: m.em, minutos: min,
        janela_h: Math.max(0, Math.round((24 * 60 - min) / 6) / 10), tem_sugestao: comSugestao.has(tel) });
    }
    lista.sort((a, b) => b.minutos - a.minutos);
    return { conversas: lista };
  },
  async agente_sem_resposta_dispensar(b, s) {
    await agenteUser(s);
    await db.from("agente_clientes").update({ sem_resposta_dispensado_em: new Date().toISOString() }).eq("username", s!.u).eq("telefone", normFone(b.telefone));
    return { ok: true };
  },
  // ── CRM: placar + movimentações automáticas ──
  async agente_movimentos(_b, s) {
    await agenteUser(s);
    const H3 = 3 * 3600e3;
    const inicioDia = new Date(Math.floor((Date.now() - H3) / 864e5) * 864e5 + H3).toISOString();
    const mes = new Date().toISOString().slice(0, 7);
    const [msgs, rasc, hoje, fila, uso, cfg, db_tam, licP] = await Promise.all([
      db.from("agente_mensagens").select("telefone,de,origem,tipo,texto,em").eq("username", s!.u).order("em", { ascending: false }).limit(40),
      db.from("agente_rascunhos").select("telefone,status,canal,acao,prioridade,criado_em,enviado_em,mensagens,enviado_texto").eq("username", s!.u).order("criado_em", { ascending: false }).limit(40),
      db.from("agente_mensagens").select("telefone").eq("username", s!.u).eq("de", "cliente").gte("em", inicioDia),
      db.from("agente_fila").select("telefone", { count: "exact", head: true }).eq("username", s!.u),
      db.from("agente_uso").select("api_enviadas,alertas").eq("username", s!.u).eq("mes", mes).maybeSingle(),
      db.from("agente_config").select("teto_api_mes").eq("username", s!.u).maybeSingle(),
      db.rpc("agente_db_tamanho"),
      db.from("agente_licoes").select("id", { count: "exact", head: true }).eq("username", s!.u).eq("status", "pendente"),
    ]);
    const tels = new Set<string>();
    for (const m of msgs.data || []) tels.add(m.telefone);
    for (const r of rasc.data || []) tels.add(r.telefone);
    const { data: clis } = tels.size ? await db.from("agente_clientes").select("telefone,nome").eq("username", s!.u).in("telefone", [...tels]) : { data: [] };
    const nome = new Map((clis || []).map((c: any) => [c.telefone, c.nome]));
    const ev: any[] = [];
    for (const m of msgs.data || []) {
      const quem = m.de === "cliente" ? "cliente" : m.origem === "app" ? "voce_app" : m.origem === "copiloto" ? "copiloto" : "nos";
      ev.push({ em: m.em, tipo: quem, telefone: m.telefone, nome: nome.get(m.telefone) || null, texto: m.texto ? m.texto.slice(0, 140) : `(${m.tipo})` });
    }
    for (const r of rasc.data || []) {
      ev.push({ em: r.criado_em, tipo: r.acao === "passar_humano" ? "precisa_voce" : "sugestao", telefone: r.telefone, nome: nome.get(r.telefone) || null, texto: (r.mensagens || [])[0]?.slice(0, 140) || "", prioridade: r.prioridade });
      if (r.enviado_em && r.status !== "pendente") {
        const editada = r.enviado_texto && JSON.stringify(r.enviado_texto) !== JSON.stringify(r.mensagens);
        ev.push({ em: r.enviado_em, tipo: r.status === "descartado" ? "descartada" : editada ? "enviada_editada" : "enviada", canal: r.canal, telefone: r.telefone, nome: nome.get(r.telefone) || null, texto: "" });
      }
    }
    ev.sort((a, b) => Date.parse(b.em) - Date.parse(a.em));
    const agoraBRT = new Date(Date.now() - H3);
    return {
      placar: {
        conversas_hoje: new Set((hoje.data || []).map((m: any) => m.telefone)).size, meta_dia: 10,
        api_usadas: Number(uso.data?.api_enviadas || 0), api_teto: Number(cfg.data?.teto_api_mes || 950), alertas_mes: Number(uso.data?.alertas || 0),
        banco_mb: Math.round(Number(db_tam.data || 0) / 1048576), banco_limite_mb: 500,
        pendentes_sugestao: fila.count || 0, licoes_pendentes: licP.count || 0,
        dia_aprendizado: agoraBRT.getUTCDay() === 1,
      },
      movimentos: ev.slice(0, 60),
    };
  },
  // ── CRM: aprendizado (aprovar/recusar) ──
  async agente_licoes(_b, s) {
    await agenteUser(s);
    const [l, c] = await Promise.all([
      db.from("agente_licoes").select("*").eq("username", s!.u).order("criado_em", { ascending: false }).limit(60),
      db.from("agente_clientes").select("telefone,nome,aprendizados").eq("username", s!.u),
    ]);
    const porCliente = (c.data || []).flatMap((x: any) => (x.aprendizados || []).map((a: any, i: number) => ({ telefone: x.telefone, nome: x.nome, indice: i, ...a })));
    return { licoes: l.data || [], aprendizados_clientes: porCliente.filter((a: any) => !a.aprovado) };
  },
  async agente_licao_decidir(b, s) {
    await agenteUser(s);
    const status = b.status === "aprovada" ? "aprovada" : b.status === "recusada" ? "recusada" : null;
    if (!status) fail(400, "Status inválido");
    const { error } = await db.from("agente_licoes").update({ status, decidido_em: new Date().toISOString() }).eq("id", Number(b.id)).eq("username", s!.u);
    if (error) fail(500, error.message);
    return { ok: true };
  },
  async agente_aprendizado_cliente_decidir(b, s) {
    await agenteUser(s);
    const telefone = normFone(b.telefone);
    const { data } = await db.from("agente_clientes").select("aprendizados").eq("username", s!.u).eq("telefone", telefone).maybeSingle();
    const lista = [...(data?.aprendizados || [])];
    const i = Number(b.indice);
    if (!lista[i]) fail(404, "Aprendizado não encontrado");
    if (b.aprovar) lista[i] = { ...lista[i], aprovado: true }; else lista.splice(i, 1);
    await db.from("agente_clientes").update({ aprendizados: lista }).eq("username", s!.u).eq("telefone", telefone);
    return { ok: true };
  },
  // ── Extensão do WhatsApp Web (copiloto) ──
  async agente_painel(_b, s) {
    await agenteUser(s);
    const mes = new Date().toISOString().slice(0, 7);
    const [fila, rasc, cfg, uso, lic] = await Promise.all([
      db.from("agente_fila").select("telefone", { count: "exact", head: true }).eq("username", s!.u),
      db.from("agente_rascunhos").select("id,telefone,mensagens,acao,motivo,prioridade,criado_em").eq("username", s!.u).eq("status", "pendente").order("prioridade", { ascending: false }).order("criado_em", { ascending: false }).limit(50),
      db.from("agente_config").select("teto_api_mes").eq("username", s!.u).maybeSingle(),
      db.from("agente_uso").select("api_enviadas,alertas").eq("username", s!.u).eq("mes", mes).maybeSingle(),
      db.from("agente_licoes").select("criado_em").eq("username", s!.u).order("criado_em", { ascending: false }).limit(1).maybeSingle(),
    ]);
    // um rascunho por cliente (o mais recente/prioritário)
    const vistos = new Set<string>(); const lista: any[] = [];
    for (const r of rasc.data || []) { if (!vistos.has(r.telefone)) { vistos.add(r.telefone); lista.push(r); } }
    const tels = lista.map((r) => r.telefone);
    const { data: clis } = tels.length ? await db.from("agente_clientes").select("telefone,nome,origem,etapa,perfil,empreendimento,resumo,horas_resposta,msgs_cliente,audios_cliente,ultimo_msg_cliente").eq("username", s!.u).in("telefone", tels) : { data: [] };
    const cm = new Map((clis || []).map((c: any) => [c.telefone, c]));
    const agoraBRT = new Date(Date.now() - 3 * 3600e3);
    const ultimaLicao = lic.data?.criado_em ? Date.parse(lic.data.criado_em) : 0;
    const avisoAprendizado = agoraBRT.getUTCDay() === 1 && Date.now() - ultimaLicao > 5 * 864e5;
    return {
      pendentes_sugestao: fila.count || 0,
      rascunhos: lista.map((r) => ({ ...r, cliente: cm.get(r.telefone) || null })),
      cota: { usadas: Number(uso.data?.api_enviadas || 0), teto: Number(cfg.data?.teto_api_mes || 950) },
      aviso_aprendizado: avisoAprendizado,
      quentes: (await actions.agente_quentes({}, s) as any).quentes.slice(0, 30),
    };
  },
  async agente_rascunho_acao(b, s) {
    await agenteUser(s);
    const { data: r } = await db.from("agente_rascunhos").select("*").eq("id", Number(b.id)).eq("username", s!.u).maybeSingle();
    if (!r) fail(404, "Sugestão não encontrada");
    if (r.status !== "pendente") fail(409, "Essa sugestão já foi tratada");
    const msgs: string[] = (Array.isArray(b.mensagens) ? b.mensagens : r.mensagens).map((m: unknown) => String(m).trim()).filter(Boolean).slice(0, 4);
    const agora = new Date().toISOString();
    if (b.op === "descartar") {
      await db.from("agente_rascunhos").update({ status: "descartado", enviado_em: agora }).eq("id", r.id);
      return { ok: true };
    }
    if (b.op === "marcar_enviado") { // o Well inseriu no WhatsApp e enviou pelo app
      await db.from("agente_rascunhos").update({ status: "enviado", canal: "whatsapp", enviado_texto: msgs, enviado_em: agora }).eq("id", r.id);
      return { ok: true };
    }
    if (b.op !== "enviar_api") fail(400, "Operação inválida");
    if (!msgs.length) fail(400, "Mensagem vazia");
    const [cfgQ, ultQ, usoQ] = await Promise.all([
      db.from("agente_config").select("wa_phone_number_id,teto_api_mes").eq("username", s!.u).maybeSingle(),
      db.from("agente_mensagens").select("em").eq("username", s!.u).eq("telefone", r.telefone).eq("de", "cliente").order("em", { ascending: false }).limit(1).maybeSingle(),
      db.from("agente_uso").select("*").eq("username", s!.u).eq("mes", agora.slice(0, 7)).maybeSingle(),
    ]);
    const cfg = cfgQ.data; const tok = Deno.env.get("WA_SYSTEM_TOKEN");
    if (!cfg?.wa_phone_number_id || !tok) fail(400, "Número do WhatsApp não configurado");
    // janela de 24h: fora dela a API só aceita template (pago) → use "Inserir no WhatsApp"
    if (!ultQ.data?.em || Date.now() - Date.parse(ultQ.data.em) > 23.5 * 3600e3) fail(409, "Janela de 24h fechada: use 'Inserir no WhatsApp' e envie pelo app (grátis)");
    const usadas = Number(usoQ.data?.api_enviadas || 0);
    if (usadas + msgs.length > Number(cfg.teto_api_mes || 950) - 30) fail(409, "Cota grátis do mês no limite: use 'Inserir no WhatsApp'");
    for (let i = 0; i < msgs.length; i++) {
      const resp = await fetch(`https://graph.facebook.com/v21.0/${cfg.wa_phone_number_id}/messages`, {
        method: "POST", headers: { Authorization: `Bearer ${tok}`, "Content-Type": "application/json" },
        body: JSON.stringify({ messaging_product: "whatsapp", to: r.telefone.replace("+", ""), type: "text", text: { body: msgs[i] } }),
      });
      const j = await resp.json();
      if (!resp.ok) fail(502, "WhatsApp recusou: " + (j?.error?.message || resp.status));
      await db.from("agente_mensagens").insert({ username: s!.u, telefone: r.telefone, de: "nos", origem: "copiloto", tipo: "texto", texto: msgs[i], wa_id: j.messages?.[0]?.id, em: new Date().toISOString() });
      if (i < msgs.length - 1) await new Promise((ok) => setTimeout(ok, 1200 + Math.random() * 1500));
    }
    await db.from("agente_uso").upsert({ username: s!.u, mes: agora.slice(0, 7), api_enviadas: usadas + msgs.length, alertas: Number(usoQ.data?.alertas || 0), chamadas_ia: Number(usoQ.data?.chamadas_ia || 0), custo_usd: Number(usoQ.data?.custo_usd || 0) }, { onConflict: "username,mes" });
    await db.from("agente_rascunhos").update({ status: "enviado", canal: "api", enviado_texto: msgs, enviado_em: new Date().toISOString() }).eq("id", r.id);
    await db.from("agente_fila").delete().eq("username", s!.u).eq("telefone", r.telefone);
    return { ok: true, enviadas: msgs.length };
  },
  async agente_preco_excluir(b, s) {
    await agenteUser(s);
    await db.from("agente_precos").delete().eq("id", Number(b.id)).eq("username", s!.u);
    return { ok: true };
  },

  // ── Admin ──
  async admin_users() {
    const { data } = await db.from("nave_users").select("username,name,role,nascimento,agente").order("name");
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
  async admin_set_agente(b, s) {
    // Só o dono do produto liga/desliga o agente (outros admins, se houver, não)
    if (s!.u !== DONO) fail(403, "Só o dono do sistema libera o agente");
    const username = normUser(b.username);
    if (!(await getUser(username))) fail(404, "Usuário não encontrado");
    await db.from("nave_users").update({ agente: !!b.agente }).eq("username", username);
    if (b.agente) await db.from("agente_config").upsert({ username }, { onConflict: "username", ignoreDuplicates: true });
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

  // ── Usado pelos comandos /rascunhos e /aprendizado (Claude Code do Well) ──
  async agente_conhecimento(b) {
    const username = normUser(b.username);
    const [k, p] = await Promise.all([
      db.from("agente_conhecimento").select("chave,conteudo").eq("username", username).order("ordem"),
      db.from("agente_precos").select("empreendimento,bairro,tipologia,valor,entrega,bloqueado,atualizado_em").eq("username", username).order("empreendimento"),
    ]);
    // lições aprovadas pelo Well entram como regra nas próximas sugestões
    const { data: lic } = await db.from("agente_licoes").select("titulo,detalhe").eq("username", username).eq("status", "aprovada").order("criado_em");
    const conhecimento = [...(k.data || [])];
    if (lic?.length) conhecimento.push({ chave: "licoes_aprovadas", conteudo: "Regras aprendidas e aprovadas pelo Well (seguir sempre):\n" + lic.map((l: any) => `- ${l.titulo}${l.detalhe ? ": " + l.detalhe : ""}`).join("\n") });
    return { conhecimento, precos: p.data || [] };
  },
  async agente_pendentes(b) {
    const username = normUser(b.username);
    const { data: fila } = await db.from("agente_fila").select("telefone,responder_apos").eq("username", username).order("responder_apos");
    const out = [];
    for (const f of fila || []) {
      const [cli, msgs] = await Promise.all([
        db.from("agente_clientes").select("nome,origem,origem_detalhe,etapa,perfil,empreendimento,renda,entrada,objecoes,resumo,aprendizados,horas_resposta,msgs_cliente,audios_cliente").eq("username", username).eq("telefone", f.telefone).maybeSingle(),
        db.from("agente_mensagens").select("de,origem,tipo,texto,em").eq("username", username).eq("telefone", f.telefone).order("em", { ascending: false }).limit(20),
      ]);
      const c: any = cli.data || {};
      c.aprendizados = (c.aprendizados || []).filter((a: any) => a.aprovado).map((a: any) => a.texto);
      out.push({ telefone: f.telefone, desde: f.responder_apos, cliente: c, conversa: (msgs.data || []).reverse() });
    }
    return { pendentes: out };
  },
  async agente_rascunho_salvar(b) {
    const username = normUser(b.username), telefone = normFone(b.telefone);
    if (!username || !telefone) fail(400, "username e telefone obrigatórios");
    const acao = ["responder", "passar_humano", "nao_responder"].includes(b.acao) ? b.acao : "responder";
    const mensagens = Array.isArray(b.mensagens) ? b.mensagens.map((m: unknown) => String(m).slice(0, 2000)).slice(0, 4) : [];
    if (acao !== "nao_responder") {
      await db.from("agente_rascunhos").insert({ username, telefone, mensagens, acao, motivo: b.motivo || b.motivo_alerta || null, prioridade: Number(b.prioridade) || null, status: "pendente", modelo: "assinatura" });
    }
    await agentActions.agente_cliente({ username, telefone, campos: { ...(b.perfil || {}), objecoes: b.objecoes || [], passado_humano: acao === "passar_humano" }, aprendizado: b.aprendizado || undefined });
    // 🔥 quente: o agente marca; uma vez quente, só sai se o Well desmarcar (quente_manual=false)
    const pr = Number(b.prioridade) || null;
    const upd: any = { prioridade: pr };
    if (b.quente || (pr && pr >= 7)) upd.quente = true;
    await db.from("agente_clientes").update(upd).eq("username", username).eq("telefone", telefone);
    await db.from("agente_fila").delete().eq("username", username).eq("telefone", telefone);
    let alerta = false;
    if (b.quente || acao === "passar_humano") {
      const { data: cfg } = await db.from("agente_config").select("alerta_numero,alerta_ativo,wa_phone_number_id").eq("username", username).maybeSingle();
      const tok = Deno.env.get("WA_SYSTEM_TOKEN");
      if (cfg?.alerta_ativo && cfg.alerta_numero && cfg.wa_phone_number_id && tok) {
        const { data: cli } = await db.from("agente_clientes").select("nome").eq("username", username).eq("telefone", telefone).maybeSingle();
        const motivo = acao === "passar_humano" ? `precisa de você: ${b.motivo || ""}` : `lead quente: ${b.motivo_alerta || ""}`;
        const r = await fetch(`https://graph.facebook.com/v21.0/${cfg.wa_phone_number_id}/messages`, {
          method: "POST", headers: { Authorization: `Bearer ${tok}`, "Content-Type": "application/json" },
          body: JSON.stringify({ messaging_product: "whatsapp", to: cfg.alerta_numero.replace("+", ""), type: "text", text: { body: `🔔 ${cli?.nome || telefone} (${telefone})\n${motivo}\nAbrir conversa: https://wa.me/${telefone.replace("+", "")}` } }),
        });
        alerta = r.ok;
        if (r.ok) {
          const mes = new Date().toISOString().slice(0, 7);
          const { data: u } = await db.from("agente_uso").select("*").eq("username", username).eq("mes", mes).maybeSingle();
          await db.from("agente_uso").upsert({ username, mes, api_enviadas: Number(u?.api_enviadas || 0) + 1, alertas: Number(u?.alertas || 0) + 1, chamadas_ia: Number(u?.chamadas_ia || 0), custo_usd: Number(u?.custo_usd || 0) }, { onConflict: "username,mes" });
        }
      }
    }
    return { ok: true, alerta };
  },
  // Números do aprendizado (sem IA): o que fez o cliente responder em até 72h.
  async agente_aprendizado_dados(b) {
    const username = normUser(b.username);
    const dias = Math.min(Number(b.dias) || 30, 180);
    const desde = new Date(Date.now() - dias * 864e5).toISOString();
    const [msgsQ, rascQ, cliQ, licQ] = await Promise.all([
      db.from("agente_mensagens").select("telefone,de,origem,tipo,texto,em").eq("username", username).gte("em", desde).order("em"),
      db.from("agente_rascunhos").select("telefone,mensagens,enviado_texto,status,canal,prioridade,criado_em").eq("username", username).gte("criado_em", desde),
      db.from("agente_clientes").select("telefone,etapa,perfil,origem,aprendizados").eq("username", username),
      db.from("agente_licoes").select("titulo,status,semana").eq("username", username).order("criado_em", { ascending: false }).limit(30),
    ]);
    const msgs = msgsQ.data || [];
    const perfilDe = new Map((cliQ.data || []).map((c: any) => [c.telefone, c.perfil || "indefinido"]));
    const porTel = new Map<string, any[]>();
    for (const m of msgs) { if (!porTel.has(m.telefone)) porTel.set(m.telefone, []); porTel.get(m.telefone)!.push(m); }
    const grupos: Record<string, { enviadas: number; respondidas: number; minutos: number[] }> = {};
    const add = (k: string, resp: boolean, min?: number) => {
      const g = grupos[k] ||= { enviadas: 0, respondidas: 0, minutos: [] };
      g.enviadas++; if (resp) { g.respondidas++; if (min != null) g.minutos.push(min); }
    };
    const exemplos: any[] = [];
    for (const [tel, lista] of porTel) {
      for (let i = 0; i < lista.length; i++) {
        const m = lista[i];
        if (m.de !== "nos") continue;
        if (lista[i + 1]?.de === "nos") continue; // conta só a última de uma sequência nossa
        const prox = lista.slice(i + 1).find((x) => x.de === "cliente");
        const min = prox ? (Date.parse(prox.em) - Date.parse(m.em)) / 60000 : null;
        const resp = min != null && min <= 72 * 60;
        const h = (new Date(m.em).getUTCHours() + 21) % 24; // BRT
        const faixa = h < 9 ? "antes 9h" : h < 12 ? "9h-12h" : h < 15 ? "12h-15h" : h < 18 ? "15h-18h" : h < 21 ? "18h-21h" : "depois 21h";
        add(`origem:${m.origem || "?"}`, resp, min ?? undefined);
        add(`tipo:${m.tipo}`, resp, min ?? undefined);
        add(`horario:${faixa}`, resp, min ?? undefined);
        add(`perfil:${perfilDe.get(tel) || "indefinido"}`, resp, min ?? undefined);
        if (exemplos.length < 60 && m.texto) exemplos.push({ texto: m.texto.slice(0, 300), origem: m.origem, respondeu: resp });
      }
    }
    const resumo = Object.fromEntries(Object.entries(grupos).map(([k, g]) => {
      const s = [...g.minutos].sort((a, b) => a - b);
      return [k, { enviadas: g.enviadas, respondidas: g.respondidas, taxa: g.enviadas ? Math.round(g.respondidas / g.enviadas * 100) : 0, mediana_min: s.length ? Math.round(s[Math.floor(s.length / 2)]) : null }];
    }));
    const rasc = rascQ.data || [];
    const edicoes = rasc.filter((r: any) => r.enviado_texto && JSON.stringify(r.enviado_texto) !== JSON.stringify(r.mensagens))
      .slice(0, 30).map((r: any) => ({ sugerido: r.mensagens, enviado: r.enviado_texto }));
    const etapas: Record<string, number> = {};
    for (const c of cliQ.data || []) etapas[c.etapa || "?"] = (etapas[c.etapa || "?"] || 0) + 1;
    return {
      periodo_dias: dias, conversas: porTel.size, resumo, exemplos, edicoes,
      rascunhos: { total: rasc.length, enviados: rasc.filter((r: any) => r.status === "enviado").length, descartados: rasc.filter((r: any) => r.status === "descartado").length },
      etapas, licoes_anteriores: licQ.data || [],
      aprendizados_a_aprovar: (cliQ.data || []).flatMap((c: any) => (c.aprendizados || []).filter((a: any) => !a.aprovado).map((a: any) => ({ telefone: c.telefone, texto: a.texto }))),
    };
  },
  async agente_licoes_salvar(b) {
    const username = normUser(b.username);
    const semana = String(b.semana || new Date().toISOString().slice(0, 10));
    const rows = (Array.isArray(b.licoes) ? b.licoes : []).slice(0, 10).map((l: any) => ({
      username, semana, titulo: String(l.titulo || "").slice(0, 200), detalhe: l.detalhe ? String(l.detalhe).slice(0, 2000) : null,
      evidencia: l.evidencia ? String(l.evidencia).slice(0, 1000) : null, amostra: Number(l.amostra) || null,
    })).filter((r: any) => r.titulo);
    if (rows.length) { const { error } = await db.from("agente_licoes").insert(rows); if (error) fail(500, error.message); }
    return { ok: true, salvas: rows.length };
  },
};
const COPILOTO_ACOES = new Set(["agente_conhecimento", "agente_pendentes", "agente_rascunho_salvar", "agente_aprendizado_dados", "agente_licoes_salvar"]);
async function sha256hex(s: string) {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));
  return Array.from(d, (x) => x.toString(16).padStart(2, "0")).join("");
}
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
      // Comandos do Claude Code de cada corretor: chave pessoal do copiloto → só os dados DELE (username vem da chave).
      const ck = req.headers.get("x-copiloto-key");
      if (ck) {
        if (!COPILOTO_ACOES.has(b.action)) fail(403, "Ação não permitida para a chave do copiloto");
        const hash = await sha256hex(ck);
        const { data: cfg } = await db.from("agente_config").select("username").eq("chave_copiloto_hash", hash).maybeSingle();
        if (!cfg) fail(401, "Chave do copiloto inválida");
        return json(200, await agentActions[b.action]({ ...b, username: cfg!.username }));
      }
      // Chave do servidor (webhook): só as ações internas.
      if (COPILOTO_ACOES.has(b.action)) fail(403, "Use a chave do copiloto");
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
