require('dotenv').config();
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function crear() {
  try {
    const hash = await bcrypt.hash("claveSegura123", 10);
    await pool.query(
      `INSERT INTO public.tecnicos (nombre, email, password_hash, activo) 
       VALUES ('Nicolás Aguayo', 'nicolas@inacap.cl', $1, true)
       ON CONFLICT (email) DO UPDATE SET password_hash = $1, activo = true`,
      [hash]
    );
    console.log("¡ÉXITO! Técnico guardado directamente en la base de datos de tu .env");
  } catch (error) {
    console.error("Error al guardar:", error.message);
  } finally {
    process.exit(0);
  }
}

crear();