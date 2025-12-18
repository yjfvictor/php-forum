<?php
/**
 * @file api.php
 * @brief Main API endpoint for the forum application
 * @details Handles all API requests including authentication, thread management, and user management
 * @date 2025-12-18
 * @author Victor Yeh
 */

require_once __DIR__ . '/config.php';

/**
 * @brief Get the action from request
 */
$action = $_GET['action'] ?? $_POST['action'] ?? '';

/**
 * @brief Route the request to appropriate handler
 */
switch ($action) {
    case 'login':
        handleLogin();
        break;
    case 'logout':
        handleLogout();
        break;
    case 'register':
        handleRegister();
        break;
    case 'getThreads':
        handleGetThreads();
        break;
    case 'createThread':
        handleCreateThread();
        break;
    case 'createPost':
        handleCreatePost();
        break;
    case 'deletePost':
        handleDeletePost();
        break;
    case 'deleteThread':
        handleDeleteThread();
        break;
    case 'getUsers':
        handleGetUsers();
        break;
    case 'deleteUser':
        handleDeleteUser();
        break;
    case 'updatePassword':
        handleUpdatePassword();
        break;
    case 'getCurrentUser':
        handleGetCurrentUser();
        break;
    default:
        sendJsonResponse(['error' => 'Invalid action'], 400);
}

/**
 * @brief Handle user login
 */
function handleLogin(): void {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    
    if (empty($username) || empty($password)) {
        sendJsonResponse(['error' => 'Username and password are required'], 400);
    }
    
    $credentials = loadCredentials();
    
    if (!isset($credentials[$username])) {
        sendJsonResponse(['error' => 'Invalid username or password'], 401);
    }
    
    if (!password_verify($password, $credentials[$username]['password'])) {
        sendJsonResponse(['error' => 'Invalid username or password'], 401);
    }
    
    $_SESSION['username'] = $username;
    sendJsonResponse([
        'success' => true,
        'username' => $username,
        'isAdmin' => $credentials[$username]['isAdmin'] ?? false
    ]);
}

/**
 * @brief Handle user logout
 */
function handleLogout(): void {
    session_destroy();
    sendJsonResponse(['success' => true]);
}

/**
 * @brief Handle user registration
 */
function handleRegister(): void {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    
    if (empty($username) || empty($password)) {
        sendJsonResponse(['error' => 'Username and password are required'], 400);
    }
    
    if (strlen($username) < 3) {
        sendJsonResponse(['error' => 'Username must be at least 3 characters'], 400);
    }
    
    if (strlen($password) < 6) {
        sendJsonResponse(['error' => 'Password must be at least 6 characters'], 400);
    }
    
    $credentials = loadCredentials();
    
    if (isset($credentials[$username])) {
        sendJsonResponse(['error' => 'Username already exists'], 400);
    }
    
    $credentials[$username] = [
        'password' => password_hash($password, PASSWORD_DEFAULT),
        'isAdmin' => false,
        'createdAt' => time()
    ];
    
    if (!saveCredentials($credentials)) {
        sendJsonResponse(['error' => 'Failed to save credentials'], 500);
    }
    
    sendJsonResponse(['success' => true]);
}

/**
 * @brief Handle getting all threads
 */
function handleGetThreads(): void {
    $threads = loadThreads();
    sendJsonResponse(['threads' => $threads]);
}

/**
 * @brief Handle creating a new thread
 */
function handleCreateThread(): void {
    if (!isLoggedIn()) {
        sendJsonResponse(['error' => 'You must be logged in to create a thread'], 401);
    }
    
    $title = $_POST['title'] ?? '';
    $content = $_POST['content'] ?? '';
    
    if (empty($title) || empty($content)) {
        sendJsonResponse(['error' => 'Title and content are required'], 400);
    }
    
    $threads = loadThreads();
    $threadId = count($threads) > 0 ? max(array_column($threads, 'id')) + 1 : 1;
    
    $thread = [
        'id' => $threadId,
        'title' => $title,
        'author' => getCurrentUsername(),
        'createdAt' => time(),
        'posts' => [
            [
                'id' => 1,
                'author' => getCurrentUsername(),
                'content' => $content,
                'createdAt' => time()
            ]
        ]
    ];
    
    $threads[] = $thread;
    
    if (!saveThreads($threads)) {
        sendJsonResponse(['error' => 'Failed to save thread'], 500);
    }
    
    sendJsonResponse(['success' => true, 'thread' => $thread]);
}

/**
 * @brief Handle creating a post in a thread
 */
function handleCreatePost(): void {
    if (!isLoggedIn()) {
        sendJsonResponse(['error' => 'You must be logged in to create a post'], 401);
    }
    
    $threadId = intval($_POST['threadId'] ?? 0);
    $content = $_POST['content'] ?? '';
    
    if ($threadId <= 0 || empty($content)) {
        sendJsonResponse(['error' => 'Thread ID and content are required'], 400);
    }
    
    $threads = loadThreads();
    $threadIndex = null;
    
    foreach ($threads as $index => $thread) {
        if ($thread['id'] === $threadId) {
            $threadIndex = $index;
            break;
        }
    }
    
    if ($threadIndex === null) {
        sendJsonResponse(['error' => 'Thread not found'], 404);
    }
    
    $postId = count($threads[$threadIndex]['posts']) > 0 
        ? max(array_column($threads[$threadIndex]['posts'], 'id')) + 1 
        : 1;
    
    $post = [
        'id' => $postId,
        'author' => getCurrentUsername(),
        'content' => $content,
        'createdAt' => time()
    ];
    
    $threads[$threadIndex]['posts'][] = $post;
    
    if (!saveThreads($threads)) {
        sendJsonResponse(['error' => 'Failed to save post'], 500);
    }
    
    sendJsonResponse(['success' => true, 'post' => $post]);
}

/**
 * @brief Handle deleting a post
 */
function handleDeletePost(): void {
    if (!isLoggedIn()) {
        sendJsonResponse(['error' => 'You must be logged in'], 401);
    }
    
    $threadId = intval($_POST['threadId'] ?? 0);
    $postId = intval($_POST['postId'] ?? 0);
    
    if ($threadId <= 0 || $postId <= 0) {
        sendJsonResponse(['error' => 'Thread ID and Post ID are required'], 400);
    }
    
    $threads = loadThreads();
    $threadIndex = null;
    
    foreach ($threads as $index => $thread) {
        if ($thread['id'] === $threadId) {
            $threadIndex = $index;
            break;
        }
    }
    
    if ($threadIndex === null) {
        sendJsonResponse(['error' => 'Thread not found'], 404);
    }
    
    $postIndex = null;
    foreach ($threads[$threadIndex]['posts'] as $index => $post) {
        if ($post['id'] === $postId) {
            $postIndex = $index;
            break;
        }
    }
    
    if ($postIndex === null) {
        sendJsonResponse(['error' => 'Post not found'], 404);
    }
    
    $username = getCurrentUsername();
    $postAuthor = $threads[$threadIndex]['posts'][$postIndex]['author'];
    
    // Check if user is admin or post author
    if (!isAdmin() && $postAuthor !== $username) {
        sendJsonResponse(['error' => 'You can only delete your own posts'], 403);
    }
    
    array_splice($threads[$threadIndex]['posts'], $postIndex, 1);
    
    // If this was the first post (thread starter), delete the entire thread
    if ($postIndex === 0 && count($threads[$threadIndex]['posts']) === 0) {
        array_splice($threads, $threadIndex, 1);
    }
    
    if (!saveThreads($threads)) {
        sendJsonResponse(['error' => 'Failed to delete post'], 500);
    }
    
    sendJsonResponse(['success' => true]);
}

/**
 * @brief Handle deleting a thread (admin only)
 */
function handleDeleteThread(): void {
    if (!isAdmin()) {
        sendJsonResponse(['error' => 'Admin access required'], 403);
    }
    
    $threadId = intval($_POST['threadId'] ?? 0);
    
    if ($threadId <= 0) {
        sendJsonResponse(['error' => 'Thread ID is required'], 400);
    }
    
    $threads = loadThreads();
    $threadIndex = null;
    
    foreach ($threads as $index => $thread) {
        if ($thread['id'] === $threadId) {
            $threadIndex = $index;
            break;
        }
    }
    
    if ($threadIndex === null) {
        sendJsonResponse(['error' => 'Thread not found'], 404);
    }
    
    // Remove the thread
    array_splice($threads, $threadIndex, 1);
    
    if (!saveThreads($threads)) {
        sendJsonResponse(['error' => 'Failed to delete thread'], 500);
    }
    
    sendJsonResponse(['success' => true]);
}

/**
 * @brief Handle getting all users (admin only)
 */
function handleGetUsers(): void {
    if (!isAdmin()) {
        sendJsonResponse(['error' => 'Admin access required'], 403);
    }
    
    $credentials = loadCredentials();
    $users = [];
    
    foreach ($credentials as $username => $data) {
        $users[] = [
            'username' => $username,
            'isAdmin' => $data['isAdmin'] ?? false,
            'createdAt' => $data['createdAt'] ?? null
        ];
    }
    
    sendJsonResponse(['users' => $users]);
}

/**
 * @brief Handle deleting a user (admin only)
 */
function handleDeleteUser(): void {
    if (!isAdmin()) {
        sendJsonResponse(['error' => 'Admin access required'], 403);
    }
    
    $username = $_POST['username'] ?? '';
    
    if (empty($username)) {
        sendJsonResponse(['error' => 'Username is required'], 400);
    }
    
    $credentials = loadCredentials();
    
    if (!isset($credentials[$username])) {
        sendJsonResponse(['error' => 'User not found'], 404);
    }
    
    // Prevent deleting admin account
    if ($credentials[$username]['isAdmin'] === true) {
        sendJsonResponse(['error' => 'Cannot delete admin account'], 400);
    }
    
    unset($credentials[$username]);
    
    if (!saveCredentials($credentials)) {
        sendJsonResponse(['error' => 'Failed to delete user'], 500);
    }
    
    // Also delete all posts by this user
    $threads = loadThreads();
    foreach ($threads as $threadIndex => $thread) {
        $threads[$threadIndex]['posts'] = array_filter(
            $threads[$threadIndex]['posts'],
            function($post) use ($username) {
                return $post['author'] !== $username;
            }
        );
        $threads[$threadIndex]['posts'] = array_values($threads[$threadIndex]['posts']);
        
        // Remove thread if no posts remain
        if (count($threads[$threadIndex]['posts']) === 0) {
            unset($threads[$threadIndex]);
        }
    }
    $threads = array_values($threads);
    saveThreads($threads);
    
    sendJsonResponse(['success' => true]);
}

/**
 * @brief Handle updating password
 */
function handleUpdatePassword(): void {
    if (!isLoggedIn()) {
        sendJsonResponse(['error' => 'You must be logged in'], 401);
    }
    
    $targetUsername = $_POST['username'] ?? '';
    $newPassword = $_POST['newPassword'] ?? '';
    $currentPassword = $_POST['currentPassword'] ?? '';
    
    if (empty($targetUsername) || empty($newPassword)) {
        sendJsonResponse(['error' => 'Username and new password are required'], 400);
    }
    
    if (strlen($newPassword) < 6) {
        sendJsonResponse(['error' => 'Password must be at least 6 characters'], 400);
    }
    
    $credentials = loadCredentials();
    $currentUsername = getCurrentUsername();
    
    // Check if user is admin or updating their own password
    if (!isAdmin() && $targetUsername !== $currentUsername) {
        sendJsonResponse(['error' => 'You can only update your own password'], 403);
    }
    
    // If updating own password, verify current password
    if (!isAdmin() && $targetUsername === $currentUsername) {
        if (empty($currentPassword)) {
            sendJsonResponse(['error' => 'Current password is required'], 400);
        }
        if (!password_verify($currentPassword, $credentials[$targetUsername]['password'])) {
            sendJsonResponse(['error' => 'Current password is incorrect'], 401);
        }
    }
    
    if (!isset($credentials[$targetUsername])) {
        sendJsonResponse(['error' => 'User not found'], 404);
    }
    
    $credentials[$targetUsername]['password'] = password_hash($newPassword, PASSWORD_DEFAULT);
    
    if (!saveCredentials($credentials)) {
        sendJsonResponse(['error' => 'Failed to update password'], 500);
    }
    
    sendJsonResponse(['success' => true]);
}

/**
 * @brief Handle getting current user info
 */
function handleGetCurrentUser(): void {
    if (!isLoggedIn()) {
        sendJsonResponse(['error' => 'Not logged in'], 401);
    }
    
    $username = getCurrentUsername();
    $credentials = loadCredentials();
    
    sendJsonResponse([
        'username' => $username,
        'isAdmin' => $credentials[$username]['isAdmin'] ?? false
    ]);
}

