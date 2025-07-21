import express from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import pg from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const { Pool } = pg;
const app = express();
const port = process.env.PORT;

const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT
});

app.get('/', (req, res) => {
  res.send('✅ Backend funcionando - Tarea U3');
});

app.use(express.json());

app.post('/register', async (req, res) => {
  const { user, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  await pool.query('INSERT INTO users (username, password) VALUES ($1, $2)', [user, hashed]);
  res.send({ message: 'Usuario registrado' });
});

app.post('/login', async (req, res) => {
  const { user, password } = req.body;
  const result = await pool.query('SELECT * FROM users WHERE username = $1', [user]);
  if (result.rows.length === 0) return res.status(401).send({ error: 'Credenciales inválidas' });

  const valid = await bcrypt.compare(password, result.rows[0].password);
  if (!valid) return res.status(401).send({ error: 'Credenciales inválidas' });

  const token = jwt.sign({ user }, process.env.JWT_SECRET);
  res.send({ token });
});

app.get('/protegido', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.sendStatus(401);
  const token = auth.split(' ')[1];

  try {
    jwt.verify(token, process.env.JWT_SECRET);
    res.send({ message: 'Ruta protegida accedida' });
  } catch (err) {
    res.status(401).send({ error: 'Token inválido' });
  }
});

app.listen(port, () => {
  console.log(`App corriendo en http://localhost:${port}`);
});
    
