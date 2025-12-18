<?php
/**
 * @file router.php
 * @brief Router script for PHP built-in development server
 * @details Handles routing for both backend and frontend files
 * @date 2024-12-19T00:00:00Z
 * @author Forum System
 */

$requestUri = $_SERVER['REQUEST_URI'];
$parsedUrl = parse_url($requestUri);
$path = $parsedUrl['path'];

// Remove leading slash
$path = ltrim($path, '/');

// Route API requests to api.php
if ($path === 'api.php' || strpos($path, 'api.php?') === 0) {
    require __DIR__ . '/api.php';
    return true;
}

// Route frontend JavaScript files (handle both with and without leading slash)
if (preg_match('#^(\.\./)?frontend/dist/(.+)$#', $path, $matches)) {
    $filePath = __DIR__ . '/../frontend/dist/' . $matches[2];
    if (file_exists($filePath)) {
        // Set appropriate content type
        $ext = pathinfo($filePath, PATHINFO_EXTENSION);
        if ($ext === 'js') {
            header('Content-Type: application/javascript');
        } elseif ($ext === 'map') {
            header('Content-Type: application/json');
        }
        readfile($filePath);
        return true;
    }
}

// Serve existing files (PHP files, static files in backend directory)
if ($path === '' || $path === 'index.php') {
    require __DIR__ . '/index.php';
    return true;
}

// Check if file exists in backend directory
$filePath = __DIR__ . '/' . $path;
if (file_exists($filePath) && is_file($filePath)) {
    // Serve static files
    $ext = pathinfo($filePath, PATHINFO_EXTENSION);
    if ($ext === 'php') {
        require $filePath;
    } else {
        // Serve static file with appropriate content type
        $mimeTypes = [
            'css' => 'text/css',
            'js' => 'application/javascript',
            'json' => 'application/json',
            'png' => 'image/png',
            'jpg' => 'image/jpeg',
            'jpeg' => 'image/jpeg',
            'gif' => 'image/gif',
            'svg' => 'image/svg+xml',
            'html' => 'text/html',
            'txt' => 'text/plain'
        ];
        $contentType = $mimeTypes[$ext] ?? 'application/octet-stream';
        header('Content-Type: ' . $contentType);
        readfile($filePath);
    }
    return true;
}

// Default: serve index.php
require __DIR__ . '/index.php';
return true;

