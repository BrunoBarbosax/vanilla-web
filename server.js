require('dotenv').config();

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

const uploadsDir = path.join(__dirname, 'uploads');
const publicDir = path.join(__dirname, 'public');

if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

const db = new sqlite3.Database('./database.db');

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      is_admin INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      tipo TEXT NOT NULL,
      conteudo TEXT NOT NULL,
      imagem TEXT,
      data DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);
});

async function criarAdmin() {
  const adminUser = process.env.ADMIN_USER || 'admin';
  const adminPass = process.env.ADMIN_PASSWORD || '123456';

  db.get('SELECT * FROM users WHERE username = ?', [adminUser], async (err, row) => {
    if (err) return console.log(err);

    if (!row) {
      const hash = await bcrypt.hash(adminPass, 10);

      db.run(
        'INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)',
        [adminUser, hash],
        (err) => {
          if (err) console.log(err);
          else console.log('✅ Admin criado:', adminUser);
        }
      );
    }
  });
}

criarAdmin();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET || 'segredo-vanilla',
  resave: false,
  saveUninitialized: false
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
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '').trim();

  if (!username || !password) {
    return res.json({ error: 'Preencha usuário e senha.' });
  }

  const hash = await bcrypt.hash(password, 10);

  db.run(
    'INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)',
    [username, hash],
    function(err) {
      if (err) {
        return res.json({ error: 'Usuário já existe.' });
      }

      res.json({ success: true });
    }
  );
});

app.post('/api/login', (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '').trim();

  if (!username || !password) {
    return res.json({ error: 'Preencha usuário e senha.' });
  }

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err || !user) {
      return res.json({ error: 'Usuário ou senha inválidos.' });
    }

    const ok = await bcrypt.compare(password, user.password);

    if (!ok) {
      return res.json({ error: 'Usuário ou senha inválidos.' });
    }

    req.session.user = {
      id: user.id,
      username: user.username,
      is_admin: user.is_admin === 1
    };

    res.json({ success: true, user: req.session.user });
  });
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

app.post('/api/log', auth, (req, res) => {
  const tipo = String(req.body.tipo || '').trim();
  const conteudo = String(req.body.conteudo || '').trim();

  if (!tipo || !conteudo) {
    return res.json({ error: 'Dados inválidos.' });
  }

  db.run(
    'INSERT INTO logs (user_id, tipo, conteudo) VALUES (?, ?, ?)',
    [req.session.user.id, tipo, conteudo],
    function(err) {
      if (err) return res.json({ error: 'Erro ao salvar registro.' });
      res.json({ success: true });
    }
  );
});

app.post('/api/farm', auth, upload.single('imagem'), (req, res) => {
  const conteudo = String(req.body.conteudo || '').trim();
  const imagem = req.file ? req.file.filename : null;

  if (!conteudo) {
    return res.json({ error: 'Dados inválidos.' });
  }

  db.run(
    'INSERT INTO logs (user_id, tipo, conteudo, imagem) VALUES (?, ?, ?, ?)',
    [req.session.user.id, 'Farm', conteudo, imagem],
    function(err) {
      if (err) return res.json({ error: 'Erro ao salvar farm.' });
      res.json({ success: true });
    }
  );
});

app.get('/api/historico', auth, (req, res) => {
  db.all(
    'SELECT * FROM logs WHERE user_id = ? ORDER BY id DESC',
    [req.session.user.id],
    (err, rows) => {
      if (err) return res.json([]);
      res.json(rows);
    }
  );
});

app.get('/api/admin/logs', adminAuth, (req, res) => {
  db.all(`
    SELECT logs.*, users.username
    FROM logs
    JOIN users ON logs.user_id = users.id
    ORDER BY logs.id DESC
  `, [], (err, rows) => {
    if (err) return res.json([]);
    res.json(rows);
  });
});

app.get('/api/admin/users', adminAuth, (req, res) => {
  db.all('SELECT id, username, is_admin, created_at FROM users ORDER BY id DESC', [], (err, rows) => {
    if (err) return res.json([]);
    res.json(rows);
  });
});

app.listen(PORT, () => {
  console.log(`🔥 Servidor rodando em http://localhost:${PORT}`);
});