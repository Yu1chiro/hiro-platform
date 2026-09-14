require('dotenv').config();
const bcrypt = require('bcrypt');
const { Pool } = require('pg');

// Mengambil argumen dari terminal
const args = process.argv.slice(2);
if (args.length < 2) {
    console.log("❌ Cara penggunaan: npm run create-admin <username> <password>");
    process.exit(1);
}

const [username, plainPassword] = args;

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

async function createAdmin() {
    try {
        // OWASP merekomendasikan salt rounds minimal 10 untuk Bcrypt
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(plainPassword, saltRounds);
        
        // Simpan ke DB. Jika username sudah ada, update password barunya (Upsert)
        await pool.query(
            'INSERT INTO admins (username, password_hash) VALUES ($1, $2) ON CONFLICT (username) DO UPDATE SET password_hash = $2',
            [username, hashedPassword]
        );
        
        console.log(`✅ Akun admin '${username}' berhasil dibuat/diupdate!`);
        console.log(`🔒 Password telah di-hash dengan aman di database.`);
    } catch (err) {
        console.error("❌ Gagal membuat admin:", err.message);
    } finally {
        pool.end();
    }
}

createAdmin();