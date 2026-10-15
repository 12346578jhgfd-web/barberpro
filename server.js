// ============================================================
// BARBERPRO - SERVIDOR (backend)
// O servidor é o "cérebro": guarda os dados no banco, confere
// senhas e decide quem pode fazer o quê. O navegador só pede.
// ============================================================
const express = require('express');          // cria o servidor web
const Database = require('better-sqlite3');  // banco de dados (um arquivo)
const bcrypt = require('bcryptjs');          // embaralha senhas (hash)
const jwt = require('jsonwebtoken');         // cria o "crachá" de login
const cookieParser = require('cookie-parser');
const path = require('path');
const crypto = require('crypto');

// ---------- 1. BANCO DE DADOS ----------
// DB_PATH vem das variáveis de ambiente (no Railway = /data/barberpro.db)
const db = new Database(process.env.DB_PATH || 'barberpro.db');
db.pragma('foreign_keys = ON');

// Cria as tabelas se ainda não existirem (rodar de novo não apaga nada)
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE, password_hash TEXT,
  role TEXT, blocked INTEGER DEFAULT 0, active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS clients(id INTEGER PRIMARY KEY, name TEXT, phone TEXT, active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS professionals(id INTEGER PRIMARY KEY, name TEXT, commission REAL, active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS services(id INTEGER PRIMARY KEY, name TEXT, price REAL, active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS appointments(id INTEGER PRIMARY KEY, client_id INTEGER REFERENCES clients(id),
  professional_id INTEGER REFERENCES professionals(id), service_id INTEGER REFERENCES services(id),
  date TEXT, time TEXT, price REAL, status TEXT DEFAULT 'agendado');
CREATE TABLE IF NOT EXISTS cash_sessions(id INTEGER PRIMARY KEY, opened_at TEXT, closed_at TEXT, opening REAL, closing REAL);
CREATE TABLE IF NOT EXISTS cash(id INTEGER PRIMARY KEY, session_id INTEGER REFERENCES cash_sessions(id),
  type TEXT, description TEXT, amount REAL, created_at TEXT, appointment_id INTEGER);
`);

// Cria o administrador inicial (só se ainda não existir nenhum)
// No Railway, defina ADMIN_EMAIL e ADMIN_PASSWORD nas variáveis!
if (!db.prepare("SELECT 1 FROM users WHERE role='admin'").get()) {
  db.prepare('INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)').run(
    'Administrador',
    process.env.ADMIN_EMAIL || 'admin@projeto.com.br',
    bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'Admin@2026#TCC', 10), // salva só o hash
    'admin');
}

// ---------- 2. FUNÇÕES AUXILIARES ----------
const SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
// Hora do Brasil (o servidor do Railway usa UTC, 3h a mais)
const now = () => new Date(Date.now() - 3 * 3600e3).toISOString().slice(0, 19).replace('T', ' ');
const bad = (res, msg) => res.status(400).json({ erro: msg });
const ROLES = ['admin', 'gerente', 'operador'];

// "wrap" evita o servidor cair se algo der erro e devolve mensagem amigável
const wrap = fn => (req, res) => {
  try { fn(req, res); } catch (e) {
    console.error(e);
    if (String(e.code).startsWith('SQLITE_CONSTRAINT')) return bad(res, 'Dados inválidos ou já cadastrados');
    res.status(500).json({ erro: 'Erro interno' });
  }
};

// ---------- 3. SEGURANÇA: LOGIN E PERMISSÕES ----------
// auth: roda ANTES de toda rota protegida. Confere o crachá (cookie) e
// consulta o banco para ver se o usuário ainda existe e não está bloqueado.
function auth(req, res, next) {
  try {
    const { id } = jwt.verify(req.cookies.token, SECRET);
    const u = db.prepare('SELECT id,name,email,role,blocked,active FROM users WHERE id=?').get(id);
    if (!u || u.blocked || !u.active) throw new Error('inválido');
    req.user = u; next();
  } catch { res.status(401).json({ erro: 'Sessão inválida' }); }
}
// need: só deixa passar quem tem um dos perfis listados (verificação NO SERVIDOR)
const need = (...roles) => (req, res, next) =>
  roles.includes(req.user.role) ? next() : res.status(403).json({ erro: 'Sem permissão' });

const app = express();
app.set('trust proxy', 1);           // necessário atrás do HTTPS do Railway
app.use(express.json(), cookieParser());
app.use(express.static(path.join(__dirname, 'public'))); // entrega o site (pasta public)

// Login: aceita e-mail OU nome de usuário (campo "email")
app.post('/api/login', wrap((req, res) => {
  const { email = '', password = '' } = req.body;
  const u = db.prepare('SELECT * FROM users WHERE lower(email)=lower(?) AND active=1').get(String(email).trim());
  if (!u || !bcrypt.compareSync(String(password), u.password_hash))
    return res.status(401).json({ erro: 'Usuário ou senha incorretos' });
  if (u.blocked) return res.status(403).json({ erro: 'Conta bloqueada. Procure o administrador.' });
  const token = jwt.sign({ id: u.id }, SECRET, { expiresIn: '8h' });
  // httpOnly = o JavaScript do site não consegue roubar o cookie
  res.cookie('token', token, { httpOnly: true, sameSite: 'lax', secure: req.secure, maxAge: 8 * 3600e3 });
  res.json({ ok: 1 });
}));
app.post('/api/logout', (req, res) => { res.clearCookie('token'); res.json({ ok: 1 }); });

app.use('/api', auth); // tudo abaixo desta linha exige login
app.get('/api/me', (req, res) => res.json(req.user));

// ---------- 4. USUÁRIOS (somente administrador) ----------
const U = express.Router();
U.use(need('admin'));
U.get('/', wrap((req, res) => res.json(
  db.prepare('SELECT id,name,email,role,blocked FROM users WHERE active=1 ORDER BY name').all())));
U.post('/', wrap((req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !ROLES.includes(role) || String(password || '').length < 8)
    return bad(res, 'Preencha tudo. A senha precisa ter 8+ caracteres.');
  db.prepare('INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)')
    .run(name.trim(), email.trim(), bcrypt.hashSync(password, 10), role);
  res.json({ ok: 1 });
}));
U.put('/:id', wrap((req, res) => {
  const { name, email, role } = req.body;
  if (!name || !email || !ROLES.includes(role)) return bad(res, 'Dados inválidos');
  if (req.params.id == req.user.id && role !== 'admin') return bad(res, 'Você não pode tirar seu próprio acesso de admin');
  db.prepare('UPDATE users SET name=?,email=?,role=? WHERE id=?').run(name.trim(), email.trim(), role, req.params.id);
  res.json({ ok: 1 });
}));
// Bloquear / desbloquear / excluir (desativar) / redefinir senha
const notSelf = (req, res) => req.params.id == req.user.id && (bad(res, 'Não é possível fazer isso com a própria conta'), true);
U.post('/:id/block', wrap((req, res) => { if (notSelf(req, res)) return;
  db.prepare('UPDATE users SET blocked=1 WHERE id=?').run(req.params.id); res.json({ ok: 1 }); }));
U.post('/:id/unblock', wrap((req, res) => {
  db.prepare('UPDATE users SET blocked=0 WHERE id=?').run(req.params.id); res.json({ ok: 1 }); }));
U.delete('/:id', wrap((req, res) => { if (notSelf(req, res)) return;
  db.prepare('UPDATE users SET active=0, blocked=1 WHERE id=?').run(req.params.id); res.json({ ok: 1 }); }));
// Redefinir: gera senha temporária aleatória (o admin nunca vê a senha ANTIGA)
U.post('/:id/reset', wrap((req, res) => {
  const senha = crypto.randomBytes(5).toString('hex') + 'A1!';
  db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(bcrypt.hashSync(senha, 10), req.params.id);
  res.json({ senha });
}));
app.use('/api/usuarios', U);

// ---------- 5. CADASTROS (clientes, profissionais, serviços) ----------
// Uma função que cria listar/criar/editar/excluir para qualquer tabela.
// "Excluir" só DESATIVA (active=0) para não quebrar o histórico.
function crud(table, fields, writers) {
  const r = express.Router();
  const valid = b => fields.every(f => String(b[f] ?? '').trim() !== '') &&
    (!('price' in b) || Number(b.price) >= 0) &&
    (!('commission' in b) || (Number(b.commission) >= 0 && Number(b.commission) <= 100));
  r.get('/', wrap((req, res) => res.json(  // ?q= faz a pesquisa por nome
    db.prepare(`SELECT * FROM ${table} WHERE active=1 AND name LIKE ? ORDER BY name`).all('%' + (req.query.q || '') + '%'))));
  r.post('/', need(...writers), wrap((req, res) => {
    if (!valid(req.body)) return bad(res, 'Preencha os campos corretamente');
    db.prepare(`INSERT INTO ${table}(${fields}) VALUES(${fields.map(() => '?')})`).run(...fields.map(f => req.body[f]));
    res.json({ ok: 1 });
  }));
  r.put('/:id', need(...writers), wrap((req, res) => {
    if (!valid(req.body)) return bad(res, 'Preencha os campos corretamente');
    db.prepare(`UPDATE ${table} SET ${fields.map(f => f + '=?')} WHERE id=?`).run(...fields.map(f => req.body[f]), req.params.id);
    res.json({ ok: 1 });
  }));
  r.delete('/:id', need(...writers), wrap((req, res) => {
    db.prepare(`UPDATE ${table} SET active=0 WHERE id=?`).run(req.params.id); res.json({ ok: 1 }); }));
  return r;
}
app.use('/api/clientes', crud('clients', ['name', 'phone'], ROLES));
app.use('/api/profissionais', crud('professionals', ['name', 'commission'], ['admin', 'gerente']));
app.use('/api/servicos', crud('services', ['name', 'price'], ['admin', 'gerente']));

// ---------- 6. CAIXA ----------
const openCash = () => db.prepare('SELECT * FROM cash_sessions WHERE closed_at IS NULL').get();
const totals = s => {
  const sum = t => db.prepare("SELECT COALESCE(SUM(amount),0) v FROM cash WHERE session_id=? AND type=?").get(s.id, t).v;
  const receitas = sum('receita'), despesas = sum('despesa');
  return { receitas, despesas, saldo: s.opening + receitas - despesas };
};
const C = express.Router();
C.use(need('admin', 'gerente'));
C.get('/', wrap((req, res) => {
  const s = openCash();
  if (!s) return res.json({ aberto: null });
  res.json({ aberto: s, ...totals(s),
    entries: db.prepare('SELECT * FROM cash WHERE session_id=? ORDER BY id DESC').all(s.id) });
}));
C.post('/abrir', wrap((req, res) => {
  if (openCash()) return bad(res, 'Já existe um caixa aberto');
  const v = Number(req.body.valor);
  if (!(v >= 0)) return bad(res, 'Valor inválido');
  db.prepare('INSERT INTO cash_sessions(opened_at,opening) VALUES(?,?)').run(now(), v);
  res.json({ ok: 1 });
}));
C.post('/despesa', wrap((req, res) => {
  const s = openCash(), v = Number(req.body.amount);
  if (!s) return bad(res, 'Abra o caixa primeiro');
  if (!req.body.description || !(v > 0)) return bad(res, 'Informe descrição e valor maior que zero');
  db.prepare("INSERT INTO cash(session_id,type,description,amount,created_at) VALUES(?,?,?,?,?)")
    .run(s.id, 'despesa', req.body.description.trim(), v, now());
  res.json({ ok: 1 });
}));
C.post('/fechar', wrap((req, res) => {
  const s = openCash();
  if (!s) return bad(res, 'Não há caixa aberto');
  db.prepare('UPDATE cash_sessions SET closed_at=?, closing=? WHERE id=?').run(now(), totals(s).saldo, s.id);
  res.json({ ok: 1 });
}));
app.use('/api/caixa', C);

// ---------- 7. AGENDA ----------
const A = express.Router();
A.get('/', wrap((req, res) => res.json(db.prepare(`
  SELECT a.*, c.name client, p.name professional, s.name service FROM appointments a
  JOIN clients c ON c.id=a.client_id JOIN professionals p ON p.id=a.professional_id
  JOIN services s ON s.id=a.service_id WHERE a.date=? ORDER BY a.time`).all(req.query.date || now().slice(0, 10)))));
A.post('/', wrap((req, res) => {
  const { client_id, professional_id, service_id, date, time } = req.body;
  const s = db.prepare('SELECT price FROM services WHERE id=? AND active=1').get(service_id);
  if (!s || !client_id || !professional_id || !date || !time) return bad(res, 'Dados inválidos');
  // não deixa dois clientes no mesmo horário com o mesmo profissional
  if (db.prepare("SELECT 1 FROM appointments WHERE professional_id=? AND date=? AND time=? AND status!='cancelado'")
    .get(professional_id, date, time)) return res.status(409).json({ erro: 'Profissional já tem agendamento neste horário' });
  db.prepare('INSERT INTO appointments(client_id,professional_id,service_id,date,time,price) VALUES(?,?,?,?,?,?)')
    .run(client_id, professional_id, service_id, date, time, s.price); // guarda o preço da época
  res.json({ ok: 1 });
}));
A.post('/:id/cancelar', wrap((req, res) => {
  db.prepare("UPDATE appointments SET status='cancelado' WHERE id=? AND status='agendado'").run(req.params.id);
  res.json({ ok: 1 });
}));
// Concluir atendimento = marca como feito + lança a RECEITA no caixa (tudo ou nada)
A.post('/:id/concluir', wrap((req, res) => {
  const a = db.prepare('SELECT a.*, s.name sname FROM appointments a JOIN services s ON s.id=a.service_id WHERE a.id=?').get(req.params.id);
  const cx = openCash();
  if (!a || a.status !== 'agendado') return bad(res, 'Agendamento não disponível');
  if (!cx) return bad(res, 'Peça ao gerente para abrir o caixa antes de concluir atendimentos');
  db.transaction(() => {
    db.prepare("UPDATE appointments SET status='concluido' WHERE id=?").run(a.id);
    db.prepare("INSERT INTO cash(session_id,type,description,amount,created_at,appointment_id) VALUES(?,?,?,?,?,?)")
      .run(cx.id, 'receita', a.sname, a.price, now(), a.id);
  })();
  res.json({ ok: 1 });
}));
app.use('/api/agenda', A);

// ---------- 8. PAINEL / RELATÓRIOS ----------
app.get('/api/dashboard', need('admin', 'gerente'), wrap((req, res) => {
  const mes = now().slice(0, 7) + '%', hoje = now().slice(0, 10);
  const soma = t => db.prepare("SELECT COALESCE(SUM(amount),0) v FROM cash WHERE type=? AND created_at LIKE ?").get(t, mes).v;
  res.json({
    hoje: db.prepare("SELECT COUNT(*) n FROM appointments WHERE date=? AND status!='cancelado'").get(hoje).n,
    receita: soma('receita'), despesa: soma('despesa'),
    comissoes: db.prepare(`SELECT p.name, COUNT(*) n, SUM(a.price) total, ROUND(SUM(a.price)*p.commission/100,2) comissao
      FROM appointments a JOIN professionals p ON p.id=a.professional_id
      WHERE a.status='concluido' AND a.date LIKE ? GROUP BY p.id`).all(mes),
    top: db.prepare(`SELECT s.name, COUNT(*) n, SUM(a.price) total FROM appointments a JOIN services s ON s.id=a.service_id
      WHERE a.status='concluido' AND a.date LIKE ? GROUP BY s.id ORDER BY n DESC LIMIT 5`).all(mes),
  });
}));

// ---------- 9. LIGAR O SERVIDOR ----------
app.listen(process.env.PORT || 3000, () => console.log('BarberPro rodando!'));
