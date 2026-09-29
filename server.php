<?php
// ---------------------------------------------------------
// server.php - API dengan pola /server.php?action=<nama>
// Static file (index.html, css, js) dilayani langsung oleh web server
// (Apache/Nginx/php -S), jadi tidak perlu serveStatic seperti di Node.
// ---------------------------------------------------------

header('Content-Type: application/json; charset=utf-8');

// ---------------------------------------------------------
// Database (SQLite via PDO)
// ---------------------------------------------------------
$dbFile = __DIR__ . '/database.sqlite';
$db = new PDO('sqlite:' . $dbFile);
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
$db->exec('PRAGMA foreign_keys = ON');

$db->exec("CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    nama TEXT,
    no_id TEXT
)");

$db->exec("CREATE TABLE IF NOT EXISTS puisi (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    judul TEXT,
    tgl_submit TEXT,
    isi TEXT,
    kategori TEXT,
    keyword TEXT,
    background TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
)");

// ---------------------------------------------------------
// Session (native PHP, cookie HttpOnly)
// ---------------------------------------------------------
session_set_cookie_params([
    'path'     => '/',
    'httponly' => true,
    'samesite' => 'Lax',
]);
session_start();

// ---------------------------------------------------------
// Helper
// ---------------------------------------------------------
function sendJSON(int $statusCode, array $obj): void
{
    http_response_code($statusCode);
    echo json_encode($obj, JSON_UNESCAPED_UNICODE);
    exit;
}

function send405(): void
{
    sendJSON(405, ['error' => 'Method Not Allowed']);
}

function readBody(): array
{
    $raw = file_get_contents('php://input');
    if (!$raw) return [];
    $data = json_decode($raw, true);
    return is_array($data) ? $data : [];
}

function requireLogin(): int
{
    if (empty($_SESSION['user_id'])) {
        sendJSON(401, ['error' => 'Unauthorized']);
    }
    return (int) $_SESSION['user_id'];
}

// ---------------------------------------------------------
// Router
// ---------------------------------------------------------
$action = $_GET['action'] ?? '';
$method = $_SERVER['REQUEST_METHOD'];
$input  = in_array($method, ['POST', 'PUT'], true) ? readBody() : [];

switch ($action) {
    case 'register':
        if ($method !== 'POST') send405();

        $username = $input['username'] ?? '';
        $nama     = $input['nama_lengkap'] ?? '';
        $password = $input['password'] ?? '';
        $no_id    = $input['no_id'] ?? '';

        if (!$username || !$nama || !$password || !$no_id) {
            sendJSON(400, ['error' => 'Data tidak lengkap']);
        }

        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
        try {
            $stmt = $db->prepare(
                'INSERT INTO users (username, password, nama, no_id) VALUES (?, ?, ?, ?)'
            );
            $stmt->execute([$username, $hashedPassword, $nama, $no_id]);
            sendJSON(200, ['message' => 'Registrasi berhasil']);
        } catch (PDOException $e) {
            sendJSON(400, ['error' => 'Username sudah digunakan']);
        }
        break;

    case 'login':
        if ($method !== 'POST') send405();

        $username = $input['username'] ?? '';
        $password = $input['password'] ?? '';

        $stmt = $db->prepare('SELECT * FROM users WHERE username = ?');
        $stmt->execute([$username]);
        $user = $stmt->fetch();

        if ($user && password_verify($password, $user['password'])) {
            session_regenerate_id(true); // cegah session fixation
            $_SESSION['user_id'] = (int) $user['id'];
            sendJSON(200, ['message' => 'Login berhasil']);
        } else {
            sendJSON(401, ['error' => 'Username atau password salah']);
        }
        break;

    case 'me':
        if ($method !== 'GET') send405();

        $userId = requireLogin();

        $stmt = $db->prepare('SELECT id, username, nama, no_id FROM users WHERE id = ?');
        $stmt->execute([$userId]);
        $user = $stmt->fetch();

        if (!$user) {
            sendJSON(404, ['error' => 'User tidak ditemukan']);
        }
        sendJSON(200, ['data' => $user]);
        break;

    case 'submit_puisi':
        if ($method !== 'POST') send405();

        $userId = requireLogin();

        $judul      = $input['judul'] ?? '';
        $isi        = $input['isi'] ?? '';
        $tgl_submit = $input['tgl_submit'] ?? date('Y-m-d');
        $kategori   = $input['kategori'] ?? '';
        $keywords   = $input['keywords'] ?? '';
        $background = $input['background'] ?? '';

        $stmt = $db->prepare(
            'INSERT INTO puisi (user_id, judul, tgl_submit, isi, kategori, keyword, background)
             VALUES (?, ?, ?, ?, ?, ?, ?)'
        );
        $stmt->execute([$userId, $judul, $tgl_submit, $isi, $kategori, $keywords, $background]);
        sendJSON(200, ['message' => 'Puisi berhasil disubmit']);
        break;

    case 'daftar_puisi':
        if ($method !== 'GET') send405();

        requireLogin();

        $stmt = $db->query('SELECT * FROM puisi ORDER BY id DESC');
        sendJSON(200, ['data' => $stmt->fetchAll()]);
        break;

    case 'logout':
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $p = session_get_cookie_params();
            setcookie(session_name(), '', time() - 3600, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
        }
        session_destroy();
        sendJSON(200, ['message' => 'Logout berhasil']);
        break;

    default:
        sendJSON(404, ['error' => 'Endpoint tidak ditemukan']);
}
