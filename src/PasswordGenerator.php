<?php

class PasswordOptions {
    public int    $length         = 16;
    public bool   $upper          = true;
    public bool   $lower          = true;
    public bool   $digits         = true;
    public bool   $symbols        = true;
    public bool   $avoidAmbiguous = false;
    public string $exclude        = '';
    public bool   $requireEach    = true;

    public static function fromArray(array $data): self {
        $o = new self();
        if (isset($data['length']))           $o->length         = (int) $data['length'];
        if (isset($data['includeUppercase'])) $o->upper          = filter_var($data['includeUppercase'], FILTER_VALIDATE_BOOLEAN);
        if (isset($data['includeLowercase'])) $o->lower          = filter_var($data['includeLowercase'], FILTER_VALIDATE_BOOLEAN);
        if (isset($data['includeNumbers']))   $o->digits         = filter_var($data['includeNumbers'],   FILTER_VALIDATE_BOOLEAN);
        if (isset($data['includeSymbols']))   $o->symbols        = filter_var($data['includeSymbols'],   FILTER_VALIDATE_BOOLEAN);
        if (isset($data['excludeAmbiguous'])) $o->avoidAmbiguous = filter_var($data['excludeAmbiguous'], FILTER_VALIDATE_BOOLEAN);
        if (isset($data['exclude']))          $o->exclude        = (string) $data['exclude'];
        if (isset($data['requireEach']))      $o->requireEach    = filter_var($data['requireEach'], FILTER_VALIDATE_BOOLEAN);
        return $o;
    }

    public function validate(): void {
        if ($this->length < 4 || $this->length > 128) {
            throw new InvalidArgumentException("La longitud debe estar entre 4 y 128 caracteres.");
        }
        if (!$this->upper && !$this->lower && !$this->digits && !$this->symbols) {
            throw new InvalidArgumentException("Debe activarse al menos una categoría de caracteres.");
        }
    }
}

class PasswordGenerator {

    private const UPPER   = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    private const LOWER   = 'abcdefghijklmnopqrstuvwxyz';
    private const DIGITS  = '0123456789';
    private const SYMBOLS = '!@#$%^&*()-_=+[]{}|;:,.<>?';
    private const AMBIG   = 'Il1O0o';

    private static ?self $instance = null;

    private function __construct() {}

    public static function getInstance(): self {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }


    private function secureRandInt(int $min, int $max): int {
        return random_int($min, $max);
    }

    private function shuffleSecure(string $str): string {
        $arr = preg_split('//u', $str, -1, PREG_SPLIT_NO_EMPTY);
        $n   = count($arr);
        for ($i = $n - 1; $i > 0; $i--) {
            $j       = $this->secureRandInt(0, $i);
            $tmp     = $arr[$i];
            $arr[$i] = $arr[$j];
            $arr[$j] = $tmp;
        }
        return implode('', $arr);
    }


    public function generate(PasswordOptions $opts): string {
        $opts->validate();

        $sets = [];
        if ($opts->upper)   $sets['upper']   = self::UPPER;
        if ($opts->lower)   $sets['lower']   = self::LOWER;
        if ($opts->digits)  $sets['digits']  = self::DIGITS;
        if ($opts->symbols) $sets['symbols'] = self::SYMBOLS;

        $excludeStr = $opts->exclude;
        if ($opts->avoidAmbiguous) $excludeStr .= self::AMBIG;
        $excludeMap = array_flip(
            array_unique(preg_split('//u', $excludeStr, -1, PREG_SPLIT_NO_EMPTY))
        );

        foreach ($sets as $k => $chars) {
            $filtered = implode('', array_filter(
                preg_split('//u', $chars, -1, PREG_SPLIT_NO_EMPTY),
                fn($c) => !isset($excludeMap[$c])
            ));
            if ($filtered === '') {
                throw new InvalidArgumentException("La categoría '{$k}' quedó vacía tras aplicar las exclusiones.");
            }
            $sets[$k] = $filtered;
        }

        $pool  = implode('', array_values($sets));
        $chars = [];

        if ($opts->requireEach) {
            foreach ($sets as $c) {
                $chars[] = $c[$this->secureRandInt(0, strlen($c) - 1)];
            }
        }

        $needed = $opts->length - count($chars);
        for ($i = 0; $i < $needed; $i++) {
            $chars[] = $pool[$this->secureRandInt(0, strlen($pool) - 1)];
        }

        return $this->shuffleSecure(implode('', $chars));
    }

    public function generateMultiple(int $count, PasswordOptions $opts): array {
        if ($count < 1 || $count > 100) {
            throw new InvalidArgumentException("La cantidad debe estar entre 1 y 100.");
        }
        $passwords = [];
        for ($i = 0; $i < $count; $i++) {
            $passwords[] = $this->generate($opts);
        }
        return $passwords;
    }


    public function validate(string $password, array $requirements): array {
        $failures = [];
        $score    = 0;

        $minLength = (int)($requirements['minLength'] ?? 8);
        if (strlen($password) < $minLength) {
            $failures[] = "Longitud mínima de {$minLength} no alcanzada (tiene " . strlen($password) . ").";
        } else {
            $score += 25;
        }

        if (!empty($requirements['requireUppercase'])) {
            if (preg_match('/[A-Z]/', $password)) $score += 25;
            else $failures[] = "Debe contener al menos una letra mayúscula.";
        } else { $score += 25; }

        if (!empty($requirements['requireNumbers'])) {
            if (preg_match('/[0-9]/', $password)) $score += 25;
            else $failures[] = "Debe contener al menos un número.";
        } else { $score += 25; }

        if (!empty($requirements['requireSymbols'])) {
            if (preg_match('/[^a-zA-Z0-9]/', $password)) $score += 25;
            else $failures[] = "Debe contener al menos un símbolo.";
        } else { $score += 25; }

        return [
            'is_valid' => empty($failures),
            'score'    => $score,
            'failures' => $failures,
            'strength' => $this->strengthLabel($score),
        ];
    }

    private function strengthLabel(int $score): string {
        return match (true) {
            $score >= 100 => 'Fuerte',
            $score >= 75  => 'Moderada',
            $score >= 50  => 'Débil',
            default       => 'Muy débil',
        };
    }
}