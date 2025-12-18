<?php
/**
 * @file index.php
 * @brief Main entry point for the forum frontend
 * @details Serves the HTML page for the forum application
 * @date 2025-12-18
 * @author Victor Yeh
 */

require_once __DIR__ . '/config.php';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forum</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/requirejs@2.3.6/require.min.js"></script>
</head>
<body>
    <div id="app"></div>
    <script>
        require.config({
            baseUrl: 'frontend/dist',
            paths: {}
        });
        require(['main'], function() {});
    </script>
</body>
</html>
