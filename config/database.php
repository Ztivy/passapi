<?php
// config/database.php

class Database {
    private static ?PDO $instance = null;

    private static string $host     = 'localhost';
    private static string $dbname   = 'password_api_db';
    private static string $user     = 'db_21030222';
    private static string $password = '21030222';

    public static function getInstance(): PDO {
        if (self::$instance === null) {
            $dsn = "mysql:host=" . self::$host . ";dbname=" . self::$dbname . ";charset=utf8mb4";
            self::$instance = new PDO($dsn, self::$user, self::$password, [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            ]);
        }
        return self::$instance;
    }
}