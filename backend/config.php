<?php
/**
 * @file config.php
 * @brief Configuration file for the forum application
 * @details Contains constants and configuration settings for the forum backend
 * @date 2024-12-19T00:00:00Z
 * @author Forum System
 */

/**
 * @brief Start output buffering to prevent "headers already sent" warnings
 */
ob_start();

/**
 * @brief Start session with HTTP-only cookies for security
 */
session_start([
    'cookie_httponly' => true,
    'cookie_secure' => false, // Set to true if using HTTPS
    'cookie_samesite' => 'Strict'
]);

/**
 * @brief Path to the data directory
 */
define('DATA_DIR', __DIR__ . '/../data/');

/**
 * @brief Path to credentials file
 */
define('CREDENTIALS_FILE', DATA_DIR . 'credentials.json');

/**
 * @brief Path to threads file
 */
define('THREADS_FILE', DATA_DIR . 'threads.json');

/**
 * @brief Load credentials from JSON file
 * @return array Associative array of username => user data
 */
function loadCredentials(): array {
    if (!file_exists(CREDENTIALS_FILE)) {
        return [];
    }
    $content = file_get_contents(CREDENTIALS_FILE);
    return json_decode($content, true) ?: [];
}

/**
 * @brief Save credentials to JSON file
 * @param array $credentials Associative array of username => user data
 * @return bool True on success, false on failure
 */
function saveCredentials(array $credentials): bool {
    return file_put_contents(CREDENTIALS_FILE, json_encode($credentials, JSON_PRETTY_PRINT)) !== false;
}

/**
 * @brief Load threads from JSON file
 * @return array Array of thread objects
 */
function loadThreads(): array {
    if (!file_exists(THREADS_FILE)) {
        return [];
    }
    $content = file_get_contents(THREADS_FILE);
    return json_decode($content, true) ?: [];
}

/**
 * @brief Save threads to JSON file
 * @param array $threads Array of thread objects
 * @return bool True on success, false on failure
 */
function saveThreads(array $threads): bool {
    return file_put_contents(THREADS_FILE, json_encode($threads, JSON_PRETTY_PRINT)) !== false;
}

/**
 * @brief Check if user is logged in
 * @return bool True if user is logged in
 */
function isLoggedIn(): bool {
    return isset($_SESSION['username']);
}

/**
 * @brief Check if current user is administrator
 * @return bool True if user is administrator
 */
function isAdmin(): bool {
    if (!isLoggedIn()) {
        return false;
    }
    $credentials = loadCredentials();
    $username = $_SESSION['username'];
    return isset($credentials[$username]) && $credentials[$username]['isAdmin'] === true;
}

/**
 * @brief Get current username
 * @return string|null Username or null if not logged in
 */
function getCurrentUsername(): ?string {
    return $_SESSION['username'] ?? null;
}

/**
 * @brief Send JSON response
 * @param mixed $data Data to encode as JSON
 * @param int $statusCode HTTP status code
 */
function sendJsonResponse($data, int $statusCode = 200): void {
    http_response_code($statusCode);
    header('Content-Type: application/json');
    echo json_encode($data);
    exit;
}

