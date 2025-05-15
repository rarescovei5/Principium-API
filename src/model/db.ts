import mysql from 'mysql2/promise';

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

pool
  .getConnection()
  .then((conn) => {
    console.log('✅ MySQL connection established');
    conn.release();
  })
  .catch((err) => {
    console.error('❌ Unable to connect to MySQL:', err);
  });

process.on('SIGINT', async () => {
  await pool.end(); // closes all active connections
  console.log('🔌 MySQL pool closed');
  process.exit(0);
});

export default pool;
