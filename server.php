<?php
session_start();
header('Content-Type: application/json');

$db_file = __DIR__ . '/database.sqlite';
$pdo = new PDO('sqlite:' . $db_file);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$pdo->exec('PRAGMA foreign_keys = ON;');

$pdo->exec("CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    nama TEXT,
    no_id TEXT
)");

$pdo->exec("CREATE TABLE IF NOT EXISTS puisi (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    judul TEXT,
    tgl_submit TEXT,
    isi TEXT,
    kategori TEXT,
    keyword TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
)");

// Menerapkan Single-Path Routing via parameter 'action'
$action = $_GET['action'] ?? '';
$method = $_SERVER['REQUEST_METHOD'];
$input = json_decode(file_get_contents('php://input'), true);

function send405()
{
    http_response_code(405);
    echo json_encode(['error' => 'Method Not Allowed']);
}

switch ($action) {
    case 'register':
        if ($method !== 'POST') {
            send405();
            break;
        }

        $username = $input['username'] ?? '';
        $nama = $input['nama_lengkap'] ?? '';
        $password = $input['password'] ?? '';
        $no_id = $input['no_id'] ?? '';

        if (!$username || !$nama || !$password || !$no_id) {
            http_response_code(400);
            echo json_encode(['error' => 'Data tidak lengkap']);
        }

        $hashed_password = password_hash($password, PASSWORD_DEFAULT);
        try {
            $stmt = $pdo->prepare("INSERT INTO users (username, password, nama, no_id) VALUES (?, ?, ?, ?)");
            $stmt->execute([$username, $hashed_password, $nama, $no_id]);
            echo json_encode(['message' => 'Registrasi berhasil']);
        } catch (PDOException $e) {
            http_response_code(400);
            echo json_encode(['error' => 'Username sudah digunakan']);
        }
        break;

    case 'login':
        if ($method !== 'POST') {
            send405();
            break;
        }
        $username = $input['username'] ?? '';
        $password = $input['password'] ?? '';

        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password'])) {
            $_SESSION['user_id'] = $user['id'];
            echo json_encode(['message' => 'Login berhasil']);
        } else {
            http_response_code(401);
            echo json_encode(['error' => 'Username atau password salah']);
        }
        break;

    case 'submit_puisi':
        if ($method !== 'POST') {
            send405();
            break;
        }
        // Proteksi Sesi
        if (!isset($_SESSION['user_id'])) {
            http_response_code(401);
            echo json_encode(['error' => 'Unauthorized']);
            break;
        }

        $judul = $input['judul'] ?? '';
        $isi = $input['isi'] ?? '';
        $tgl_submit = $input['tgl_submit'] ?? date('Y-m-d');
        $kategori = $input['kategori'] ?? '';
        $keywords = $input['keywords'] ?? '';
        $user_id = $_SESSION['user_id'];

        $stmt = $pdo->prepare("INSERT INTO puisi (user_id, judul, tgl_submit, isi, kategori, keyword) VALUES (?, ?, ?, ?, ?, ?)");
        $stmt->execute([$user_id, $judul, $tgl_submit, $isi, $kategori, $keywords]);
        echo json_encode(['message' => 'Puisi berhasil disubmit']);
        break;

    case 'daftar_puisi':
        if ($method !== 'GET') {
            send405();
            break;
        }

        if (!isset($_SESSION['user_id'])) {
            http_response_code(401);
            echo json_encode(['error' => 'Unauthorized']);
            break;
        }

        $stmt = $pdo->query("SELECT * FROM puisi ORDER BY id DESC");
        $puisi = $stmt->fetchAll(PDO::FETCH_ASSOC);
        echo json_encode(['data' => $puisi]);
        break;

    case 'logout':
        session_destroy();
        echo json_encode(['message' => 'Logout berhasil']);
        break;

    default:
        http_response_code(404);
        echo json_encode(['error' => 'Endpoint tidak ditemukan']);
        break;
}
