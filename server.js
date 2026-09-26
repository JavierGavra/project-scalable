const http = require('http');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

// ---------------------------------------------------------
// Static file serving sederhana (setara serve HTML/CSS/JS biasa)
// Semua file frontend ditaruh di folder ./public
// ---------------------------------------------------------
const PUBLIC_DIR = __dirname;

const MIME_TYPES = {
    '.html': 'text/html',
    '.css': 'text/css',
    '.js': 'text/javascript',
    '.json': 'application/json',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.svg': 'image/svg+xml',
};

function serveStatic(req, res, pathname) {
    // Default ke index.html kalau akses root "/"
    let filePath = pathname === '/' ? './index.html' : pathname;
    filePath = path.join(PUBLIC_DIR, filePath);

    // Cegah path traversal (../../dst)
    if (!filePath.startsWith(PUBLIC_DIR)) {
        res.writeHead(403);
        return res.end('Forbidden');
    }

    fs.readFile(filePath, (err, content) => {
        if (err) {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            return res.end('File tidak ditemukan');
        }
        const ext = path.extname(filePath);
        res.writeHead(200, { 'Content-Type': MIME_TYPES[ext] || 'application/octet-stream' });
        res.end(content);
    });
}

const DB_FILE = path.join(__dirname, 'database.sqlite');
const db = new Database(DB_FILE);
db.pragma('foreign_keys = ON');

// Setup tabel (setara CREATE TABLE IF NOT EXISTS di PHP)
db.exec(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    nama TEXT,
    no_id TEXT
)`);

db.exec(`CREATE TABLE IF NOT EXISTS puisi (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    judul TEXT,
    tgl_submit TEXT,
    isi TEXT,
    kategori TEXT,
    keyword TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
)`);

// ---------------------------------------------------------
// Session store sederhana (in-memory), setara $_SESSION di PHP
// Key: session_id (dari cookie), Value: { user_id }
// ---------------------------------------------------------
const sessions = new Map();

function getSessionIdFromCookie(req) {
    const cookieHeader = req.headers.cookie || '';
    const match = cookieHeader.match(/(?:^|;\s*)sid=([^;]+)/);
    return match ? match[1] : null;
}

function getSession(req) {
    const sid = getSessionIdFromCookie(req);
    if (sid && sessions.has(sid)) {
        return { sid, data: sessions.get(sid) };
    }
    return null;
}

function createSession(res, data) {
    const sid = crypto.randomBytes(16).toString('hex');
    sessions.set(sid, data);
    // Cookie session sederhana, HttpOnly
    res.setHeader('Set-Cookie', `sid=${sid}; HttpOnly; Path=/`);
    return sid;
}

function destroySession(req, res) {
    const sid = getSessionIdFromCookie(req);
    if (sid) sessions.delete(sid);
    res.setHeader('Set-Cookie', 'sid=; HttpOnly; Path=/; Max-Age=0');
}

// ---------------------------------------------------------
// Hash & verifikasi password pakai crypto.scrypt bawaan Node
// (setara password_hash() / password_verify() di PHP)
// ---------------------------------------------------------
function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');
    return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
    const [salt, hash] = stored.split(':');
    const hashToCheck = crypto.scryptSync(password, salt, 64).toString('hex');
    // Bandingkan pakai timingSafeEqual biar aman dari timing attack
    const a = Buffer.from(hash, 'hex');
    const b = Buffer.from(hashToCheck, 'hex');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
}


function sendJSON(res, statusCode, obj) {
    res.writeHead(statusCode, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(obj));
}

function send405(res) {
    sendJSON(res, 405, { error: 'Method Not Allowed' });
}


// Baca body request
function readBody(req) {
    return new Promise((resolve) => {
        let raw = '';
        req.on('data', (chunk) => {
            raw += chunk;
        });
        req.on('end', () => {
            try {
                resolve(raw ? JSON.parse(raw) : {});
            } catch {
                resolve({});
            }
        });
    });
}


const server = http.createServer(async (req, res) => {
    const parsedUrl = new URL(req.url, `http://${req.headers.host}`);
    const action = parsedUrl.searchParams.get('action') || '';
    const method = req.method;

    // Kalau nggak ada parameter ?action=, anggap ini request file statis
    // (index.html, style.css, dashboard.html, dll)
    if (!parsedUrl.searchParams.has('action')) {
        return serveStatic(req, res, parsedUrl.pathname);
    }

    const input = ['POST', 'PUT'].includes(method) ? await readBody(req) : {};

    switch (action) {
        case 'register': {
            if (method !== 'POST') return send405(res);

            const username = input.username || '';
            const nama = input.nama_lengkap || '';
            const password = input.password || '';
            const no_id = input.no_id || '';

            if (!username || !nama || !password || !no_id) {
                return sendJSON(res, 400, { error: 'Data tidak lengkap' });
            }

            const hashedPassword = hashPassword(password);
            try {
                const stmt = db.prepare(
                    'INSERT INTO users (username, password, nama, no_id) VALUES (?, ?, ?, ?)'
                );
                stmt.run(username, hashedPassword, nama, no_id);
                sendJSON(res, 200, { message: 'Registrasi berhasil' });
            } catch (e) {
                sendJSON(res, 400, { error: 'Username sudah digunakan' });
            }
            break;
        }

        case 'login': {
            if (method !== 'POST') return send405(res);

            const username = input.username || '';
            const password = input.password || '';

            const stmt = db.prepare('SELECT * FROM users WHERE username = ?');
            const user = stmt.get(username);

            if (user && verifyPassword(password, user.password)) {
                createSession(res, { user_id: user.id });
                sendJSON(res, 200, { message: 'Login berhasil' });
            } else {
                sendJSON(res, 401, { error: 'Username atau password salah' });
            }
            break;
        }

        case 'submit_puisi': {
            if (method !== 'POST') return send405(res);

            const session = getSession(req);
            if (!session) {
                return sendJSON(res, 401, { error: 'Unauthorized' });
            }

            const judul = input.judul || '';
            const isi = input.isi || '';
            const tgl_submit = input.tgl_submit || new Date().toISOString().slice(0, 10);
            const kategori = input.kategori || '';
            const keywords = input.keywords || '';
            const user_id = session.data.user_id;

            const stmt = db.prepare(
                'INSERT INTO puisi (user_id, judul, tgl_submit, isi, kategori, keyword) VALUES (?, ?, ?, ?, ?, ?)'
            );
            stmt.run(user_id, judul, tgl_submit, isi, kategori, keywords);
            sendJSON(res, 200, { message: 'Puisi berhasil disubmit' });
            break;
        }

        case 'daftar_puisi': {
            if (method !== 'GET') return send405(res);

            const session = getSession(req);
            if (!session) {
                return sendJSON(res, 401, { error: 'Unauthorized' });
            }

            const stmt = db.prepare('SELECT * FROM puisi ORDER BY id DESC');
            const puisi = stmt.all();
            sendJSON(res, 200, { data: puisi });
            break;
        }

        case 'logout': {
            destroySession(req, res);
            sendJSON(res, 200, { message: 'Logout berhasil' });
            break;
        }

        default:
            sendJSON(res, 404, { error: 'Endpoint tidak ditemukan' });
            break;
    }
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server jalan di http://localhost:${PORT}`);
});