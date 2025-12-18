/**
 * @file api.ts
 * @brief API client for communicating with the backend
 * @details Handles all HTTP requests to the PHP backend API
 * @date 2025-12-18
 * @author Victor Yeh
 */

/**
 * @brief Base URL for API endpoints
 */
const API_BASE = 'api.php';

/**
 * @brief User information interface
 */
export interface User {
    username: string;
    isAdmin: boolean;
    createdAt?: number;
}

/**
 * @brief Post information interface
 */
export interface Post {
    id: number;
    author: string;
    content: string;
    createdAt: number;
}

/**
 * @brief Thread information interface
 */
export interface Thread {
    id: number;
    title: string;
    author: string;
    createdAt: number;
    posts: Post[];
}

/**
 * @brief Make API request
 * @param action API action name
 * @param data POST data
 * @return Promise<any> Response data
 */
async function apiRequest(action: string, data?: any): Promise<any> {
    const formData = new FormData();
    formData.append('action', action);
    
    if (data) {
        for (const key in data) {
            if (data.hasOwnProperty(key)) {
                formData.append(key, data[key]);
            }
        }
    }
    
    const response = await fetch(API_BASE, {
        method: 'POST',
        body: formData
    });
    
    const result = await response.json();
    
    if (!response.ok || result.error) {
        throw new Error(result.error || 'Request failed');
    }
    
    return result;
}

/**
 * @brief Login user
 * @param username Username
 * @param password Password
 * @return Promise<User> User information
 */
export async function login(username: string, password: string): Promise<User> {
    const result = await apiRequest('login', { username, password });
    return {
        username: result.username,
        isAdmin: result.isAdmin
    };
}

/**
 * @brief Logout user
 * @return Promise<void>
 */
export async function logout(): Promise<void> {
    await apiRequest('logout');
}

/**
 * @brief Register new user
 * @param username Username
 * @param password Password
 * @return Promise<void>
 */
export async function register(username: string, password: string): Promise<void> {
    await apiRequest('register', { username, password });
}

/**
 * @brief Get all threads
 * @return Promise<Thread[]> Array of threads
 */
export async function getThreads(): Promise<Thread[]> {
    const result = await apiRequest('getThreads');
    return result.threads || [];
}

/**
 * @brief Create a new thread
 * @param title Thread title
 * @param content Thread content
 * @return Promise<Thread> Created thread
 */
export async function createThread(title: string, content: string): Promise<Thread> {
    const result = await apiRequest('createThread', { title, content });
    return result.thread;
}

/**
 * @brief Create a post in a thread
 * @param threadId Thread ID
 * @param content Post content
 * @return Promise<Post> Created post
 */
export async function createPost(threadId: number, content: string): Promise<Post> {
    const result = await apiRequest('createPost', { threadId, content });
    return result.post;
}

/**
 * @brief Delete a post
 * @param threadId Thread ID
 * @param postId Post ID
 * @return Promise<void>
 */
export async function deletePost(threadId: number, postId: number): Promise<void> {
    await apiRequest('deletePost', { threadId, postId });
}

/**
 * @brief Delete a thread (admin only)
 * @param threadId Thread ID
 * @return Promise<void>
 */
export async function deleteThread(threadId: number): Promise<void> {
    await apiRequest('deleteThread', { threadId });
}

/**
 * @brief Get all users (admin only)
 * @return Promise<User[]> Array of users
 */
export async function getUsers(): Promise<User[]> {
    const result = await apiRequest('getUsers');
    return result.users || [];
}

/**
 * @brief Delete a user (admin only)
 * @param username Username to delete
 * @return Promise<void>
 */
export async function deleteUser(username: string): Promise<void> {
    await apiRequest('deleteUser', { username });
}

/**
 * @brief Update user password
 * @param username Username
 * @param newPassword New password
 * @param currentPassword Current password (required if updating own password)
 * @return Promise<void>
 */
export async function updatePassword(username: string, newPassword: string, currentPassword?: string): Promise<void> {
    const data: any = { username, newPassword };
    if (currentPassword) {
        data.currentPassword = currentPassword;
    }
    await apiRequest('updatePassword', data);
}

/**
 * @brief Get current user information
 * @return Promise<User> Current user information
 */
export async function getCurrentUser(): Promise<User> {
    return await apiRequest('getCurrentUser');
}

