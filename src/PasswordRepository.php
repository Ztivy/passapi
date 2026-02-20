<?php
// src/PasswordRepository.php
// Patron Repository: encapsula todo acceso a la base de datos.

class PasswordRepository {
    private PDO $db;

    public function __construct(PDO $db) {
        $this->db = $db;
    }

    // ─────────────────────────────────────────────────
    // 1. password_requests — log de cada solicitud
    // ─────────────────────────────────────────────────

    /**
     * Registra una solicitud de generacion y devuelve su ID.
     *
     * @param PasswordOptions $opts  Opciones usadas
     * @param int             $count Cantidad de contrasenas generadas
     * @param int|null        $userId Usuario autenticado (opcional)
     */
    public function logRequest(PasswordOptions $opts, int $count, ?int $userId = null): int {
        $stmt = $this->db->prepare(
            "INSERT INTO password_requests
                (user_id, length, include_uppercase, include_lowercase,
                 include_numbers, include_symbols, exclude_ambiguous, count)
             VALUES
                (:user_id, :length, :upper, :lower, :numbers, :symbols, :ambiguous, :count)"
        );

        $stmt->execute([
            ':user_id'   => $userId,
            ':length'    => $opts->length,
            ':upper'     => (int) $opts->upper,
            ':lower'     => (int) $opts->lower,
            ':numbers'   => (int) $opts->digits,
            ':symbols'   => (int) $opts->symbols,
            ':ambiguous' => (int) $opts->avoidAmbiguous,
            ':count'     => $count,
        ]);

        return (int) $this->db->lastInsertId();
    }

    // ─────────────────────────────────────────────────
    // 2. generated_passwords — hash bcrypt + score
    // ─────────────────────────────────────────────────

    /**
     * Guarda el hash bcrypt de cada contrasena generada junto con su score.
     * NUNCA almacena texto plano.
     *
     * @param int   $requestId  ID de la solicitud padre
     * @param array $passwords  Contrasenas en texto plano (solo para hashear)
     */
    public function savePasswords(int $requestId, array $passwords): void {
        $stmt = $this->db->prepare(
            "INSERT INTO generated_passwords (request_id, password_hash, strength_score)
             VALUES (:request_id, :hash, :score)"
        );

        foreach ($passwords as $pw) {
            $score = $this->calculateStrengthScore($pw);
            $stmt->execute([
                ':request_id' => $requestId,
                ':hash'       => password_hash($pw, PASSWORD_BCRYPT),
                ':score'      => $score,
            ]);
        }
    }

    // ─────────────────────────────────────────────────
    // 3. password_validations — log de validaciones
    // ─────────────────────────────────────────────────

    /**
     * Registra el resultado de una validacion de fortaleza.
     * La contrasena se guarda como hash bcrypt.
     *
     * @param string $password     Contrasena evaluada (texto plano, solo para hashear)
     * @param array  $requirements Requisitos enviados por el cliente
     * @param bool   $result       true si paso todos los requisitos
     */
    public function logValidation(string $password, array $requirements, bool $result): void {
        $stmt = $this->db->prepare(
            "INSERT INTO password_validations (password_hash, requirements_json, result)
             VALUES (:hash, :req_json, :result)"
        );

        $stmt->execute([
            ':hash'     => password_hash($password, PASSWORD_BCRYPT),
            ':req_json' => json_encode($requirements, JSON_UNESCAPED_UNICODE),
            ':result'   => (int) $result,
        ]);
    }

    // ─────────────────────────────────────────────────
    // Helper: calcular score de fortaleza (0-100)
    // ─────────────────────────────────────────────────

    private function calculateStrengthScore(string $pw): int {
        $score = 0;
        if (strlen($pw) >= 8)                    $score += 25;
        if (preg_match('/[A-Z]/', $pw))          $score += 25;
        if (preg_match('/[0-9]/', $pw))          $score += 25;
        if (preg_match('/[^a-zA-Z0-9]/', $pw))  $score += 25;
        return $score;
    }
}