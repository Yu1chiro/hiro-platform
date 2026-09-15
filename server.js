const express = require('express');
const path = require('path');
const session = require('express-session');
const { Pool } = require('pg');
const bcrypt = require('bcrypt'); 
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

const pool = new Pool({
    connectionString: process.env.DATABASE_URL || '',
});

pool.on('connect', (client) => {
    client.query("SET TIME ZONE 'Asia/Makassar'");
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: process.env.SESSION_SECRET || 'hiro-super-secret-key-2026',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false, 
        httpOnly: true, 
        maxAge: 1000 * 60 * 60 * 24 
    }
}));

const requireAuth = (req, res, next) => {
    if (req.session && req.session.user) {
        next();
    } else {
        if (req.path.startsWith('/api/')) {
            res.status(401).json({ success: false, error: 'Unauthorized' });
        } else {
            res.redirect('/signin');
        }
    }
};

app.use('/admin', requireAuth);
app.use(express.static(path.join(__dirname, 'public')));

const formatWITA = (dateString) => {
    if (!dateString) return null;
    const date = new Date(dateString);
    return date.toLocaleString('id-ID', {
        timeZone: 'Asia/Makassar',
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
    }) + ' WITA';
};

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM admins WHERE username = $1', [username]);
        if (result.rows.length === 0) {
            return res.status(401).json({ success: false, message: 'Kredensial tidak valid' });
        }
        const admin = result.rows[0];
        const match = await bcrypt.compare(password, admin.password_hash);
        if (match) {
            req.session.regenerate((err) => {
                if (err) return res.status(500).json({ success: false, message: 'Session error' });
                req.session.user = admin.username;
                res.json({ success: true, redirect: '/admin/dashboard' });
            });
        } else {
            res.status(401).json({ success: false, message: 'Kredensial tidak valid' });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Terjadi kesalahan pada server' });
    }
});

app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

app.get('/api/platforms', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM platforms ORDER BY id DESC');
        const formattedData = result.rows.map(row => ({
            ...row,
            created_at: formatWITA(row.created_at)
        }));
        res.json(formattedData);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/platforms', requireAuth, async (req, res) => {
    try {
        const { title, description, link } = req.body;
        await pool.query('INSERT INTO platforms (title, description, link) VALUES ($1, $2, $3)', [title, description, link]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/platforms/:id', requireAuth, async (req, res) => {
    try {
        const { title, description, link } = req.body;
        await pool.query('UPDATE platforms SET title=$1, description=$2, link=$3 WHERE id=$4', [title, description, link, req.params.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/platforms/:id', requireAuth, async (req, res) => {
    try {
        await pool.query('DELETE FROM platforms WHERE id=$1', [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/notifications', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM notifications ORDER BY id DESC');
        const formattedData = result.rows.map(row => ({
            ...row,
            created_at: formatWITA(row.created_at)
        }));
        res.json(formattedData);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/notifications', requireAuth, async (req, res) => {
    try {
        const { title, broadcast } = req.body;
        await pool.query('INSERT INTO notifications (title, broadcast) VALUES ($1, $2)', [title, broadcast]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/notifications/:id', requireAuth, async (req, res) => {
    try {
        const { title, broadcast } = req.body;
        await pool.query('UPDATE notifications SET title=$1, broadcast=$2 WHERE id=$3', [title, broadcast, req.params.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/notifications/:id', requireAuth, async (req, res) => {
    try {
        await pool.query('DELETE FROM notifications WHERE id=$1', [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/requests', requireAuth, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM resource_requests ORDER BY id DESC');
        const formattedData = result.rows.map(row => ({
            ...row,
            created_at: formatWITA(row.created_at)
        }));
        res.json(formattedData);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/requests', async (req, res) => {
    try {
        const { name, contact, description } = req.body;
        await pool.query('INSERT INTO resource_requests (name, contact, description) VALUES ($1, $2, $3)', [name, contact, description]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/requests/:id', requireAuth, async (req, res) => {
    try {
        await pool.query('DELETE FROM resource_requests WHERE id=$1', [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/admin/dashboard', requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'public','admin', 'dashboard.html')));
app.get('/signin', (req, res) => {
    if (req.session && req.session.user) {
        return res.redirect('/admin/dashboard');
    }
    res.sendFile(path.join(__dirname, 'public','admin', 'signin.html'));
});
app.get('/notification', (req, res) => res.sendFile(path.join(__dirname, 'public', 'notification.html')));

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));