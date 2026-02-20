<?php
// public/index.php  –  Front Controller / Router

declare(strict_types=1);

// ── Cabeceras CORS ──
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

// ── Autoload manual ──
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../src/Response.php';
require_once __DIR__ . '/../src/PasswordGenerator.php';
require_once __DIR__ . '/../src/PasswordRepository.php';

// ── Parsear ruta y método ──
$method = strtoupper($_SERVER['REQUEST_METHOD']);
$path   = rtrim(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), '/') ?: '/';

// ── Helpers ──
function getJsonBody(): array {
    $raw = file_get_contents('php://input');
    if (empty($raw)) return [];
    $decoded = json_decode($raw, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        Response::error('El cuerpo de la solicitud no es un JSON válido.', 400);
    }
    return $decoded ?? [];
}

function getServices(): array {
    try {
        $db   = Database::getInstance();
        $repo = new PasswordRepository($db);
        $gen  = PasswordGenerator::getInstance();
        return [$gen, $repo];
    } catch (PDOException $e) {
        Response::error('Error de conexión a la base de datos.', 500);
    }
}

// ══════════════════════════════════════════════════════════════
//  RUTAS
// ══════════════════════════════════════════════════════════════

// ── GET /api/password ─────────────────────────────────────────
if ($path === '/api/password' && $method === 'GET') {

    [$gen, $repo] = getServices();

    try {
        $opts = PasswordOptions::fromArray($_GET);
        $opts->validate();

        $password  = $gen->generate($opts);
        $requestId = $repo->logRequest($opts, 1);
        $repo->savePasswords($requestId, [$password]);

        Response::success([
            'password'   => $password,
            'length'     => strlen($password),
            'request_id' => $requestId,
        ], 'Contraseña generada correctamente.');

    } catch (InvalidArgumentException $e) {
        Response::error($e->getMessage(), 400);
    } catch (Throwable $e) {
        Response::error('Error interno del servidor.', 500);
    }
}

// ── POST /api/passwords ───────────────────────────────────────
elseif ($path === '/api/passwords' && $method === 'POST') {

    [$gen, $repo] = getServices();

    try {
        $body  = getJsonBody();
        $count = isset($body['count']) ? (int)$body['count'] : 1;
        $opts  = PasswordOptions::fromArray($body);
        $opts->validate();

        $passwords = $gen->generateMultiple($count, $opts);
        $requestId = $repo->logRequest($opts, $count);
        $repo->savePasswords($requestId, $passwords);

        Response::success([
            'passwords'  => $passwords,
            'count'      => count($passwords),
            'length'     => $opts->length,
            'request_id' => $requestId,
        ], 'Contraseñas generadas correctamente.', 201);

    } catch (InvalidArgumentException $e) {
        Response::error($e->getMessage(), 400);
    } catch (Throwable $e) {
        Response::error('Error interno del servidor.', 500);
    }
}

// ── POST /api/password/validate ───────────────────────────────
elseif ($path === '/api/password/validate' && $method === 'POST') {

    [$gen, $repo] = getServices();

    try {
        $body     = getJsonBody();
        $password = $body['password'] ?? '';
        $reqs     = $body['requirements'] ?? [];

        if (empty($password)) {
            Response::error("El campo 'password' es obligatorio.", 422);
        }

        $result = $gen->validate($password, $reqs);
        $repo->logValidation($password, $reqs, $result['is_valid']);

        $httpCode = $result['is_valid'] ? 200 : 422;
        Response::success(
            $result,
            $result['is_valid'] ? 'La contraseña cumple los requisitos.' : 'La contraseña NO cumple los requisitos.',
            $httpCode
        );

    } catch (Throwable $e) {
        Response::error('Error interno del servidor.', 500);
    }
}

// ── 404 ───────────────────────────────────────────────────────
else {
    Response::error("Ruta '{$path}' [{$method}] no encontrada.", 404, [
        'endpoints_disponibles' => [
            'GET  /api/password'          => 'Genera una contraseña.',
            'POST /api/passwords'         => 'Genera múltiples contraseñas.',
            'POST /api/password/validate' => 'Valida la fortaleza de una contraseña.',
        ],
    ]);
}