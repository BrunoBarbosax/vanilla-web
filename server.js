require('dotenv').config();

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const multer = require('multer');
const axios = require('axios');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const cloudinary = require('cloudinary').v2;

const app = express();
const PORT = process.env.PORT || 3000;

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: 'vanilla-farms',
    allowed_formats: ['jpg', 'jpeg', 'png', 'webp']
  }
});

const upload = multer({ storage });

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET || 'vanilla-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));

app.use(express.static('public'));

async function enviarDiscord({ tipo, usuario, conteudo, imagem }) {
  if (!process.env.DISCORD_WEBHOOK_URL) return;

  try {
    await axios.post(process.env.DISCORD_WEBHOOK_URL, {
      username: 'Vanilla Sistema',
      avatar_url: 'https://cdn-icons-png.flaticon.com/512/5968/5968756.png',
      embeds: [
        {
          title: `📌 Novo registro: ${tipo}`,
          color: tipo === 'Farm' ? 0x57f287 : 0xff00b7,
          fields: [
            {
              name: '👤 Usuário',
              value: usuario || 'Desconhecido',
              inline: true
            },
            {
              name: '📂 Tipo',
              value: tipo,
              inline: true
            },
            {
              name: '📋 Detalhes',
              value: '```' + String(conteudo || '').slice(0, 900) + '```'
            }
          ],
          image: imagem ? { url: imagem } : undefined,
          footer: {
            text: 'Vanilla Operações'
          },
          timestamp: new Date().toISOString()
        }
      ]
    });
  } catch (err) {
    console.log('Erro ao enviar Discord:', err.message);
  }
}

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

    res.json({
      success: true,
      user: req.session.user
    });
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

    await enviarDiscord({
      tipo,
      usuario: req.session.user.username,
      conteudo
    });

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.json({ error: 'Erro ao salvar registro.' });
  }
});

app.post('/api/farm', auth, upload.single('imagem'), async (req, res) => {
  try {
    const conteudo = String(req.body.conteudo || '').trim();

    if (!conteudo) {
      return res.json({ error: 'Dados inválidos.' });
    }

    const imagem = req.file ? req.file.path : null;

    await pool.query(
      'INSERT INTO logs (user_id, tipo, conteudo, imagem) VALUES ($1, $2, $3, $4)',
      [req.session.user.id, 'Farm', conteudo, imagem]
    );

    await enviarDiscord({
      tipo: 'Farm',
      usuario: req.session.user.username,
      conteudo,
      imagem
    });

    res.json({
      success: true,
      imagem
    });
  } catch (err) {
    console.error('Erro Cloudinary/Farm:', err);
    res.json({ error: 'Erro ao salvar farm/imagem.' });
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
      console.log('🔥 Rodando em http://localhost:' + PORT);
    });
  })
  .catch((err) => {
    console.error('❌ Erro ao iniciar banco:', err);
  });