const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// PostgreSQL connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// ===== INICIALIZAÇÃO DO BANCO =====
async function initDB() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    await client.query(`
      CREATE TABLE IF NOT EXISTS confirmados_aniversario (
        id SERIAL PRIMARY KEY,
        nome VARCHAR(255) NOT NULL,
        adultos INTEGER NOT NULL DEFAULT 1,
        criancas INTEGER NOT NULL DEFAULT 0,
        observacao TEXT,
        data_confirmacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS admins_aniversario (
        id SERIAL PRIMARY KEY,
        usuario VARCHAR(100) UNIQUE NOT NULL,
        senha_hash VARCHAR(255) NOT NULL,
        criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS admin_tokens_aniversario (
        token VARCHAR(255) PRIMARY KEY,
        admin_id INTEGER REFERENCES admins_aniversario(id) ON DELETE CASCADE,
        criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expira_em TIMESTAMP
      )
    `);

    // Criar admin padrão se não existir
    const adminExists = await client.query('SELECT * FROM admins_aniversario WHERE usuario = $1', ['admin']);
    if (adminExists.rows.length === 0) {
      const senhaHash = await bcrypt.hash('sophia2025', 10);
      await client.query('INSERT INTO admins_aniversario (usuario, senha_hash) VALUES ($1, $2)', ['admin', senhaHash]);
      console.log('✅ Admin padrão criado: admin / sophia2025');
    }

    await client.query('COMMIT');
    console.log('✅ Banco de dados inicializado com sucesso!');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('❌ Erro ao inicializar banco:', err);
    throw err;
  } finally {
    client.release();
  }
}

// ===== MIDDLEWARE ADMIN =====
async function verificarAdmin(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ erro: 'Token não fornecido' });
  }
  try {
    const result = await pool.query(
      'SELECT * FROM admin_tokens_aniversario WHERE token = $1 AND expira_em > NOW()',
      [token]
    );
    if (result.rows.length === 0) {
      return res.status(401).json({ erro: 'Token inválido ou expirado' });
    }
    req.adminId = result.rows[0].admin_id;
    next();
  } catch (err) {
    return res.status(500).json({ erro: 'Erro ao verificar token' });
  }
}

// ===== ROTAS DE AUTENTICAÇÃO =====

// Login admin
app.post('/login', async (req, res) => {
  const { usuario, senha } = req.body;
  if (!usuario || !senha) {
    return res.status(400).json({ sucesso: false, erro: 'Usuário e senha são obrigatórios' });
  }
  try {
    const result = await pool.query('SELECT * FROM admins_aniversario WHERE usuario = $1', [usuario]);
    if (result.rows.length === 0) {
      return res.status(401).json({ sucesso: false, erro: 'Usuário não encontrado' });
    }
    const admin = result.rows[0];
    const senhaValida = await bcrypt.compare(senha, admin.senha_hash);
    if (!senhaValida) {
      return res.status(401).json({ sucesso: false, erro: 'Senha incorreta' });
    }
    const token = crypto.randomBytes(32).toString('hex');
    const expiraEm = new Date(Date.now() + 24 * 60 * 60 * 1000);
    await pool.query('INSERT INTO admin_tokens_aniversario (token, admin_id, expira_em) VALUES ($1, $2, $3)', [token, admin.id, expiraEm]);
    res.json({ sucesso: true, token });
  } catch (err) {
    console.error('Erro no login:', err);
    res.status(500).json({ sucesso: false, erro: 'Erro no servidor' });
  }
});

// Logout admin
app.post('/logout', async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  try {
    await pool.query('DELETE FROM admin_tokens_aniversario WHERE token = $1', [token]);
    res.json({ sucesso: true });
  } catch (err) {
    res.status(500).json({ sucesso: false, erro: 'Erro ao fazer logout' });
  }
});

// Verificar token
app.get('/verificar-token', async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.json({ valido: false });
  try {
    const result = await pool.query(
      'SELECT * FROM admin_tokens_aniversario WHERE token = $1 AND expira_em > NOW()',
      [token]
    );
    res.json({ valido: result.rows.length > 0 });
  } catch (err) {
    res.json({ valido: false });
  }
});

// Trocar senha do admin
app.post('/admin/trocar-senha', verificarAdmin, async (req, res) => {
  const { senha_antiga, senha_nova } = req.body;
  try {
    const admin = await pool.query('SELECT * FROM admins_aniversario WHERE id = $1', [req.adminId]);
    if (admin.rows.length === 0) {
      return res.status(404).json({ erro: 'Admin não encontrado' });
    }
    const senhaValida = await bcrypt.compare(senha_antiga, admin.rows[0].senha_hash);
    if (!senhaValida) {
      return res.status(401).json({ erro: 'Senha antiga incorreta' });
    }
    const novaSenhaHash = await bcrypt.hash(senha_nova, 10);
    await pool.query('UPDATE admins_aniversario SET senha_hash = $1 WHERE id = $2', [novaSenhaHash, req.adminId]);
    res.json({ sucesso: true, mensagem: 'Senha alterada com sucesso!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: 'Erro ao trocar senha' });
  }
});

// ===== ROTAS DE CONFIRMAÇÃO =====

// Confirmar presença
app.post('/confirmar', async (req, res) => {
  const { nome, adultos, criancas, observacao } = req.body;

  if (!nome || nome.trim().length < 2) {
    return res.status(400).json({ erro: 'Nome é obrigatório (mínimo 2 caracteres)' });
  }

  const numAdultos = parseInt(adultos) || 1;
  const numCriancas = parseInt(criancas) || 0;

  if (numAdultos < 1 || numAdultos > 20) {
    return res.status(400).json({ erro: 'Número de adultos inválido (1-20)' });
  }
  if (numCriancas < 0 || numCriancas > 20) {
    return res.status(400).json({ erro: 'Número de crianças inválido (0-20)' });
  }

  try {
    // Verificar se já confirmou (mesmo nome)
    const existente = await pool.query(
      'SELECT * FROM confirmados_aniversario WHERE LOWER(nome) = LOWER($1)',
      [nome.trim()]
    );
    if (existente.rows.length > 0) {
      return res.status(409).json({ erro: 'Este nome já confirmou presença! Entre em contato para alterar.' });
    }

    const result = await pool.query(
      'INSERT INTO confirmados_aniversario (nome, adultos, criancas, observacao) VALUES ($1, $2, $3, $4) RETURNING *',
      [nome.trim(), numAdultos, numCriancas, observacao?.trim() || null]
    );

    console.log(`✅ Confirmação: ${nome.trim()} (${numAdultos} adultos, ${numCriancas} crianças)`);
    res.json({ sucesso: true, confirmado: result.rows[0] });
  } catch (err) {
    console.error('Erro ao confirmar:', err);
    res.status(500).json({ erro: 'Erro ao confirmar presença' });
  }
});

// Listar confirmados (público)
app.get('/confirmados', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, nome, adultos, criancas, data_confirmacao FROM confirmados_aniversario ORDER BY data_confirmacao ASC'
    );
    const total = result.rows.reduce(
      (acc, r) => ({ adultos: acc.adultos + r.adultos, criancas: acc.criancas + r.criancas }),
      { adultos: 0, criancas: 0 }
    );
    res.json({ confirmados: result.rows, total });
  } catch (err) {
    console.error('Erro ao listar:', err);
    res.status(500).json({ erro: 'Erro ao listar confirmados' });
  }
});

// Remover confirmação (admin)
app.delete('/confirmados/:id', verificarAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM confirmados_aniversario WHERE id = $1 RETURNING *', [id]);
    if (result.rowCount === 0) {
      return res.status(404).json({ erro: 'Confirmação não encontrada' });
    }
    res.json({ sucesso: true });
  } catch (err) {
    console.error('Erro ao remover:', err);
    res.status(500).json({ erro: 'Erro ao remover confirmação' });
  }
});

// Listar confirmados com observações (admin)
app.get('/admin/confirmados', verificarAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM confirmados_aniversario ORDER BY data_confirmacao ASC'
    );
    const total = result.rows.reduce(
      (acc, r) => ({ adultos: acc.adultos + r.adultos, criancas: acc.criancas + r.criancas }),
      { adultos: 0, criancas: 0 }
    );
    res.json({ confirmados: result.rows, total });
  } catch (err) {
    console.error('Erro ao listar (admin):', err);
    res.status(500).json({ erro: 'Erro ao listar confirmados' });
  }
});

// Limpar todas as confirmações (admin)
app.delete('/confirmados', verificarAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM confirmados_aniversario');
    res.json({ sucesso: true });
  } catch (err) {
    console.error('Erro ao limpar:', err);
    res.status(500).json({ erro: 'Erro ao limpar lista' });
  }
});

// ===== INICIALIZAÇÃO =====
async function iniciarServidor() {
  try {
    console.log('🔧 Inicializando banco de dados...');
    await initDB();
    app.listen(PORT, () => {
      console.log(`🎉 Servidor do aniversário da Sophia rodando na porta ${PORT}`);
    });
  } catch (err) {
    console.error('❌ Falha crítica:', err);
    process.exit(1);
  }
}

iniciarServidor();
