// =====================================================================
// Backend Express para PWA offline-first de técnicos agrícolas
// Instalar: npm i express pg dotenv helmet cors express-rate-limit bcryptjs jsonwebtoken
// =====================================================================
require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

// --- Validación de configuración: falla rápido si falta algo -----------
for (const k of ['DATABASE_URL', 'JWT_SECRET']) {
  if (!process.env[k]) {
    console.error(`Falta la variable ${k} en el entorno (.env)`);
    process.exit(1);
  }
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }, 
  max: 10,
});

// --- Tablas sincronizables y columnas permitidas (lista blanca) --------
const TABLES = {
  parcelas: ['nombre', 'cultivo', 'superficie_ha', 'latitud', 'longitud', 'notas'],
  visitas: ['parcela_id', 'fecha_visita', 'estado_cultivo', 'plagas_detectadas', 'recomendaciones'],
};

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_ROWS_PER_TABLE = 500;
const PULL_PAGE_SIZE = 500;
const DUMMY_HASH = bcrypt.hashSync('dummy-password', 10); 

// --- App ---------------------------------------------------------------
const app = express();
app.set('trust proxy', 1); 
app.use(helmet());
app.use(
  cors({
    origin: (process.env.CORS_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean),
  })
);
app.use(express.json({ limit: '2mb' }));

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const httpError = (status, message) => Object.assign(new Error(message), { status });

// --- Autenticación -----------------------------------------------------
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20 }); 

app.post(
  '/auth/login',
  loginLimiter,
  wrap(async (req, res) => {
    const { email, password } = req.body || {};
    if (typeof email !== 'string' || typeof password !== 'string') {
      throw httpError(400, 'Datos inválidos');
    }
    const { rows } = await pool.query(
      'select id, nombre, password_hash from public.tecnicos where email = $1 and activo',
      [email.toLowerCase().trim()]
    );
    const tecnico = rows[0];
    const ok = await bcrypt.compare(password, tecnico ? tecnico.password_hash : DUMMY_HASH);
    if (!tecnico || !ok) throw httpError(401, 'Credenciales incorrectas');

    const token = jwt.sign({ sub: tecnico.id }, process.env.JWT_SECRET, {
      algorithm: 'HS256',
      expiresIn: '30d',
    });
    res.json({ token, tecnico: { id: tecnico.id, nombre: tecnico.nombre } });
  })
);

function auth(req, _res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return next(httpError(401, 'Falta el token'));
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
    req.userId = payload.sub; 
    next();
  } catch {
    next(httpError(401, 'Token inválido o vencido'));
  }
}

// --- Sync: PUSH (cliente -> servidor) ----------------------------------
async function upsertRow(client, table, row, userId) {
  const cols = TABLES[table];
  if (!row || typeof row.id !== 'string' || !UUID_RE.test(row.id)) throw httpError(400, 'id inválido');

  const cua = new Date(row.client_updated_at);
  if (Number.isNaN(cua.getTime())) throw httpError(400, 'client_updated_at inválido');

  let deletedAt = null;
  if (row.deleted_at) {
    const d = new Date(row.deleted_at);
    if (Number.isNaN(d.getTime())) throw httpError(400, 'deleted_at inválido');
    deletedAt = d.toISOString();
  }

  const insertCols = ['id', 'tecnico_id', ...cols, 'client_updated_at', 'deleted_at'];
  const values = [
    row.id,
    userId,
    ...cols.map((c) => (row[c] === undefined ? null : row[c])), 
    cua.toISOString(),
    deletedAt,
  ];
  const placeholders = insertCols.map((_, i) => `$${i + 1}`);
  const updates = insertCols
    .filter((c) => c !== 'id' && c !== 'tecnico_id')
    .map((c) => `${c} = excluded.${c}`);

  const sql = `
    insert into public.${table} (${insertCols.join(', ')})
    values (${placeholders.join(', ')})
    on conflict (id) do update set ${updates.join(', ')}
    where ${table}.tecnico_id = excluded.tecnico_id
      and ${table}.client_updated_at <= excluded.client_updated_at
    returning id`;

  const { rowCount } = await client.query(sql, values);
  return rowCount === 1;
}

app.post(
  '/sync/push',
  auth,
  wrap(async (req, res) => {
    const changes = req.body && req.body.changes;
    if (!changes || typeof changes !== 'object') throw httpError(400, 'Falta "changes"');

    const result = { applied: {}, rejected: {}, invalid: [] };
    const client = await pool.connect();
    try {
      await client.query('begin');
      for (const table of Object.keys(TABLES)) {
        result.applied[table] = [];
        result.rejected[table] = [];
        const rows = changes[table];
        if (rows === undefined) continue;
        if (!Array.isArray(rows)) throw httpError(400, `"${table}" debe ser un arreglo`);
        if (rows.length > MAX_ROWS_PER_TABLE) {
          throw httpError(413, `Máximo ${MAX_ROWS_PER_TABLE} filas por tabla; envía en lotes`);
        }

        for (const row of rows) {
          await client.query('savepoint fila');
          try {
            const applied = await upsertRow(client, table, row, req.userId);
            (applied ? result.applied : result.rejected)[table].push(row.id);
            await client.query('release savepoint fila');
          } catch (err) {
            await client.query('rollback to savepoint fila');
            result.invalid.push({ table, id: row && row.id, error: err.message });
          }
        }
      }
      await client.query('commit');
    } catch (err) {
      await client.query('rollback').catch(() => {});
      throw err;
    } finally {
      client.release();
    }
    res.json(result);
  })
);

// --- Sync: PULL (servidor -> cliente) ----------------------------------
const toCursor = (v) => {
  const n = Number(v);
  return Number.isSafeInteger(n) && n > 0 ? n : 0;
};

app.post(
  '/sync/pull',
  auth,
  wrap(async (req, res) => {
    const cursors = (req.body && req.body.cursors) || {};
    const out = {};
    for (const table of Object.keys(TABLES)) {
      const since = toCursor(cursors[table]);
      const { rows } = await pool.query(
        `select * from public.${table}
          where tecnico_id = $1 and server_version > $2
          order by server_version asc
          limit $3`,
        [req.userId, since, PULL_PAGE_SIZE + 1]
      );
      const hasMore = rows.length > PULL_PAGE_SIZE;
      const page = (hasMore ? rows.slice(0, PULL_PAGE_SIZE) : rows).map((r) => ({
        ...r,
        server_version: Number(r.server_version), 
      }));
      out[table] = {
        rows: page,
        cursor: page.length ? page[page.length - 1].server_version : since,
        has_more: hasMore,
      };
    }
    res.json(out);
  })
);

app.get('/health', (_req, res) => res.json({ ok: true }));

// --- Manejo de errores -------------------------------------------------
app.use((err, _req, res, _next) => {
  const status = err.status || 500;
  if (status >= 500) console.error(err); 
  res.status(status).json({ error: status >= 500 ? 'Error interno' : err.message });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API escuchando en el puerto ${PORT}`));