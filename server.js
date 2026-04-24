require('dotenv').config();

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

const uploadsDir = path.join(__dirname, 'uploads');
const publicDir = path.join(__dirname, 'public');

if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET || 'segredo-vanilla',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));

app.use('/uploads', express.static(uploadsDir));
app.use(express.static(publicDir));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname || '.jpg');
    cb(null, Date.now() + '-' + Math.random().toString(36).slice(2) + ext);
  }
});

const upload = multer({ storage });

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      is_admin BOOLEAN DEFAULT false,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS logs (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      tipo TEXT NOT NULL,
      conteudo TEXT NOT NULL,
      imagem TEXT,
      data TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  const adminUser = process.env.ADMIN_USER || 'admin';
  const adminPass = process.env.ADMIN_PASSWORD || '123456';

  const adminExists = await pool.query(
    'SELECT id FROM users WHERE username = $1',
    [adminUser]
  );

  if (adminExists.rows.length === 0) {
    const hash = await bcrypt.hash(adminPass, 10);

    await pool.query(
      'INSERT INTO users (username, password, is_admin) VALUES ($1, $2, true)',
      [adminUser, hash]
    );

    console.log('✅ Admin criado:', adminUser);
  }

  console.log('✅ Banco Supabase conectado e tabelas prontas.');
}

function auth(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Não logado.' });
  }

  next();
}

function adminAuth(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Não logado.' });
  }

  if (!req.session.user.is_admin) {
    return res.status(403).json({ error: 'Sem permissão de administrador.' });
  }

  next();
}

app.post('/api/register', async (req, res) => {
  try {
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '').trim();

    if (!username || !password) {
      return res.json({ error: 'Preencha usuário e senha.' });
    }

    const hash = await bcrypt.hash(password, 10);

    await pool.query(
      'INSERT INTO users (username, password, is_admin) VALUES ($1, $2, false)',
      [username, hash]
    );

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.json({ error: 'Usuário já existe ou erro ao cadastrar.' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '').trim();

    if (!username || !password) {
      return res.json({ error: 'Preencha usuário e senha.' });
    }

    const result = await pool.query(
      'SELECT * FROM users WHERE username = $1',
      [username]
    );

    const user = result.rows[0];

    if (!user) {
      return res.json({ error: 'Usuário ou senha inválidos.' });
    }

    const ok = await bcrypt.compare(password, user.password);

    if (!ok) {
      return res.json({ error: 'Usuário ou senha inválidos.' });
    }

    req.session.user = {
      id: user.id,
      username: user.username,
      is_admin: user.is_admin
    };

    res.json({ success: true, user: req.session.user });
  } catch (err) {
    console.error(err);
    res.json({ error: 'Erro ao fazer login.' });
  }
});

app.get('/api/me', (req, res) => {
  res.json(req.session.user || null);
});

app.get('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

app.post('/api/log', auth, async (req, res) => {
  try {
    const tipo = String(req.body.tipo || '').trim();
    const conteudo = String(req.body.conteudo || '').trim();

    if (!tipo || !conteudo) {
      return res.json({ error: 'Dados inválidos.' });
    }

    await pool.query(
      'INSERT INTO logs (user_id, tipo, conteudo) VALUES ($1, $2, $3)',
      [req.session.user.id, tipo, conteudo]
    );

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.json({ error: 'Erro ao salvar registro.' });
  }
});

app.post('/api/farm', auth, upload.single('imagem'), async (req, res) => {
  try {
    const conteudo = String(req.body.conteudo || '').trim();
    const imagem = req.file ? req.file.filename : null;

    if (!conteudo) {
      return res.json({ error: 'Dados inválidos.' });
    }

    await pool.query(
      'INSERT INTO logs (user_id, tipo, conteudo, imagem) VALUES ($1, $2, $3, $4)',
      [req.session.user.id, 'Farm', conteudo, imagem]
    );

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.json({ error: 'Erro ao salvar farm.' });
  }
});

app.get('/api/historico', auth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM logs WHERE user_id = $1 ORDER BY id DESC',
      [req.session.user.id]
    );

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.json([]);
  }
});

app.get('/api/admin/logs', adminAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT logs.*, users.username
      FROM logs
      JOIN users ON logs.user_id = users.id
      ORDER BY logs.id DESC
    `);

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.json([]);
  }
});

app.get('/api/admin/users', adminAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, username, is_admin, created_at
      FROM users
      ORDER BY id DESC
    `);

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.json([]);
  }
});

initDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`🔥 Servidor rodando em http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error('❌ Erro ao iniciar banco:', err);
  });