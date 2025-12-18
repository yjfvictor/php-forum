<?php
/**
 * @file init.php
 * @brief Initialization script to create admin account
 * @details Creates the credentials.json file with the admin account
 * @date 2024-12-19T00:00:00Z
 * @author Forum System
 */

require_once __DIR__ . '/config.php';

// Create data directory if it doesn't exist
if (!is_dir(DATA_DIR)) {
    mkdir(DATA_DIR, 0755, true);
}

// Initialize credentials if file doesn't exist
if (!file_exists(CREDENTIALS_FILE)) {
    $credentials = [
        'admin' => [
            'password' => password_hash('admin123', PASSWORD_DEFAULT),
            'isAdmin' => true,
            'createdAt' => time()
        ]
    ];
    saveCredentials($credentials);
    echo "Admin account created successfully!\n";
} else {
    echo "Credentials file already exists.\n";
}

