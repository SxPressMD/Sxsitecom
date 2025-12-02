require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Setup DB (file: data.db)
const dbFile = process.env.SQLITE_FILE || 'data.db';
const db = new Database(dbFile);

// Create tables if not exists
db.prepare(`CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE,
  password_hash TEXT,
  totp_secret TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
)`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT,
  image TEXT,
  link TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT
)`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  action TEXT,
  when TEXT DEFAULT CURRENT_TIMESTAMP
)`).run();

// Middleware
app.use(helmet());
app.use(cors({ origin: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(path.join(__dirname,'uploads')));

// Rate limiter
const limiter = rateLimit({ windowMs: 60*1000, max: 60 });
app.use(limiter);

// Multer for uploads (local storage)
const uploadDir = path.join(__dirname,'uploads');
if(!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
const storage = multer.diskStorage({
  destination: (req,file,cb)=> cb(null, uploadDir),
  filename: (req,file,cb)=> cb(null, Date.now() + '-' + file.originalname.replace(/\s+/g,'_'))
});
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } });

// Utils
const JWT_SECRET = process.env.JWT_SECRET || 'replace_me_in_env';
const JWT_EXPIRES = process.env.JWT_EXPIRES || '1h';
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || '10');

function logAction(action){
  db.prepare('INSERT INTO audit (action) VALUES (?)').run(action);
}

// Admin creation helper (if ADMIN_INIT env provided)
async function ensureInitialAdmin(){
  const initEmail = process.env.ADMIN_INIT_EMAIL;
  const initPass = process.env.ADMIN_INIT_PASSWORD;
  if(!initEmail || !initPass) return;
  const row = db.prepare('SELECT * FROM admins WHERE email = ?').get(initEmail);
  if(!row){
    const hash = await bcrypt.hash(initPass, BCRYPT_ROUNDS);
    // create admin with disabled TOTP until setup
    db.prepare('INSERT INTO admins (email,password_hash) VALUES (?,?)').run(initEmail, hash);
    console.log('Admin initial created:', initEmail);
    logAction(`Admin inicial criado: ${initEmail}`);
  }
}
ensureInitialAdmin();

// Authentication middleware for admin-protected routes
function authMiddleware(req,res,next){
  const auth = req.headers.authorization;
  if(!auth) return res.status(401).json({message:'Token ausente'});
  const parts = auth.split(' ');
  if(parts.length !== 2) return res.status(401).json({message:'Token inválido'});
  try{
    const payload = jwt.verify(parts[1], JWT_SECRET);
    req.admin = payload;
    next();
  }catch(e){ return res.status(401).json({message:'Token inválido'}); }
}

// Public endpoints
app.get('/products', (req,res)=>{
  const q = req.query.q || '';
  let rows;
  if(q){
    rows = db.prepare('SELECT * FROM products WHERE title LIKE ? ORDER BY id DESC').all(`%${q}%`);
  } else {
    rows = db.prepare('SELECT * FROM products ORDER BY id DESC').all();
  }
  res.json(rows);
});

app.get('/products/:id', (req,res)=>{
  const p = db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id);
  if(!p) return res.status(404).json({message:'Produto não encontrado'});
  res.json(p);
});

// Auth endpoints (login step 1: verify password -> return tempToken)
app.post('/auth/login', async (req,res)=>{
  const { email, password } = req.body || {};
  if(!email || !password) return res.status(400).json({ message: 'Email e senha obrigatórios' });
  const admin = db.prepare('SELECT * FROM admins WHERE email = ?').get(email);
  if(!admin) return res.status(401).json({ message: 'Credenciais inválidas' });
  const ok = await bcrypt.compare(password, admin.password_hash);
  if(!ok) return res.status(401).json({ message: 'Credenciais inválidas' });

  // At this point password ok. If admin has TOTP secret, return tempToken to continue 2FA.
  // tempToken payload contains admin id and a short expiry
  const tempToken = jwt.sign({ adminId: admin.id, step:'2fa' }, JWT_SECRET, { expiresIn: '5m' });
  logAction(`Login iniciado para ${email}`);
  res.json({ tempToken, need2fa: !!admin.totp_secret });
});

// Auth endpoint (2fa verify)
app.post('/auth/2fa-verify', (req,res)=>{
  const { tempToken, code } = req.body || {};
  if(!tempToken || !code) return res.status(400).json({ message: 'tempToken e code necessários' });
  try{
    const payload = jwt.verify(tempToken, JWT_SECRET);
    if(payload.step !== '2fa') throw new Error('Invalid step');
    const admin = db.prepare('SELECT * FROM admins WHERE id = ?').get(payload.adminId);
    if(!admin) return res.status(401).json({ message: 'Admin não encontrado' });

    if(!admin.totp_secret) return res.status(400).json({ message: 'TOTP não configurado para este usuário' });

    const verified = speakeasy.totp.verify({
      secret: admin.totp_secret,
      encoding: 'base32',
      token: code,
      window: 1
    });
    if(!verified) return res.status(401).json({ message: 'Código TOTP inválido' });

    const token = jwt.sign({ adminId: admin.id, email: admin.email, role: 'admin' }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
    logAction(`Login efetuado: ${admin.email}`);
    res.json({ token });
  }catch(e){
    return res.status(401).json({ message: 'tempToken inválido ou expirado' });
  }
});

// Admin route: get totp setup (requires basic auth by password as safety) - for initial setup flow.
// For simplicity we let initial setup be triggered via a protected route that requires admin credentials in body + temp token flow.
// WARNING: Protect this route in production behind other measures (IP whitelist) until TOTP is configured.
app.post('/auth/setup-2fa', async (req,res)=>{
  const { email, password } = req.body || {};
  if(!email || !password) return res.status(400).json({ message: 'Email e senha necessários' });
  const admin = db.prepare('SELECT * FROM admins WHERE email = ?').get(email);
  if(!admin) return res.status(401).json({ message: 'Credenciais inválidas' });
  const ok = await bcrypt.compare(password, admin.password_hash);
  if(!ok) return res.status(401).json({ message: 'Credenciais inválidas' });

  // create secret
  const secret = speakeasy.generateSecret({ name: `MinhaLoja (${email})` });
  // save base32 secret to DB
  db.prepare('UPDATE admins SET totp_secret = ? WHERE id = ?').run(secret.base32, admin.id);
  logAction(`2FA configurado (secret gerado) para ${email}`);

  // Return secret.otpauth_url and base32 for QR generation in user's app
  res.json({ otpauth_url: secret.otpauth_url, base32: secret.base32 });
});

// Protected admin endpoints
app.get('/admin/log', authMiddleware, (req,res)=>{
  const rows = db.prepare('SELECT * FROM audit ORDER BY id DESC LIMIT 200').all();
  res.json({ logs: rows.map(r=> ({ when: r.when, action: r.action }) )});
});

// CRUD products
app.post('/products', authMiddleware, upload.single('file'), (req,res)=>{
  const title = req.body.title;
  const link = req.body.link;
  let image = req.body.image || null;
  if(req.file) {
    image = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
  }
  if(!title || !link) return res.status(400).json({message:'title e link obrigatórios'});
  const info = db.prepare('INSERT INTO products (title,image,link) VALUES (?,?,?)').run(title, image, link);
  logAction(`Produto criado: ${title}`);
  res.status(201).json({ id: info.lastInsertRowid, title, image, link });
});

app.put('/products/:id', authMiddleware, upload.single('file'), (req,res)=>{
  const id = req.params.id;
  const title = req.body.title;
  const link = req.body.link;
  let image = req.body.image || null;
  if(req.file) image = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
  const exists = db.prepare('SELECT * FROM products WHERE id = ?').get(id);
  if(!exists) return res.status(404).json({message:'Produto não encontrado'});
  db.prepare('UPDATE products SET title = ?, image = ?, link = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(title || exists.title, image || exists.image, link || exists.link, id);
  logAction(`Produto editado: ${id}`);
  res.json({ message:'Atualizado' });
});

app.delete('/products/:id', authMiddleware, (req,res)=>{
  const id = req.params.id;
  const row = db.prepare('SELECT * FROM products WHERE id = ?').get(id);
  if(!row) return res.status(404).json({message:'Produto não encontrado'});
  db.prepare('DELETE FROM products WHERE id = ?').run(id);
  logAction(`Produto excluído: ${id} - ${row.title}`);
  res.json({ message:'Excluído' });
});

/* Admin: change password */
app.post('/admin/change-password', authMiddleware, async (req,res)=>{
  const { oldPassword, newPassword } = req.body || {};
  if(!oldPassword || !newPassword) return res.status(400).json({ message:'oldPassword e newPassword obrigatórios' });
  const admin = db.prepare('SELECT * FROM admins WHERE id = ?').get(req.admin.adminId);
  const ok = await bcrypt.compare(oldPassword, admin.password_hash);
  if(!ok) return res.status(401).json({ message:'Senha antiga incorreta' });
  const hash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
  db.prepare('UPDATE admins SET password_hash = ? WHERE id = ?').run(hash, admin.id);
  logAction(`Senha alterada: ${admin.email}`);
  res.json({ message: 'Senha atualizada' });
});

// Health
app.get('/health', (req,res)=> res.json({ ok:true }));

app.listen(PORT, ()=> console.log(`Server started on ${PORT}`));
