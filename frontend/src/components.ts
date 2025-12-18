/**
 * @file components.ts
 * @brief UI components for the forum application
 * @details Contains functions to render various UI components
 * @date 2024-12-19T00:00:00Z
 * @author Forum System
 */

import * as api from './api';
import { formatDate, showAlert, showConfirmModal } from './utils';

/**
 * @brief Current user state
 */
let currentUser: api.User | null = null;

/**
 * @brief Set current user
 * @param user User object or null
 */
export function setCurrentUser(user: api.User | null): void {
    currentUser = user;
}

/**
 * @brief Get current user
 * @return api.User | null Current user or null
 */
export function getCurrentUser(): api.User | null {
    return currentUser;
}

/**
 * @brief Render navigation bar
 * @param container Container element
 */
export function renderNavbar(container: HTMLElement): void {
    const isLoggedIn = currentUser !== null;
    const isAdmin = currentUser?.isAdmin === true;
    
    container.innerHTML = `
        <nav class="navbar navbar-expand-lg navbar-light bg-light mb-4">
            <div class="container-fluid">
                <a class="navbar-brand" href="#" onclick="window.location.reload()">Forum</a>
                <div class="navbar-nav ms-auto">
                    ${!isLoggedIn ? `
                        <a class="btn btn-outline-primary me-2" href="#" id="registerLink">Create Account</a>
                        <a class="btn btn-primary" href="#" id="loginLink">Log In</a>
                    ` : `
                        <a class="btn btn-outline-info me-2" href="#" id="profileLink">Profile</a>
                        ${isAdmin ? `<a class="btn btn-outline-warning me-2" href="#" id="adminLink">Administrator Management</a>` : ''}
                        <a class="btn btn-outline-danger" href="#" id="logoutLink">Log Out</a>
                    `}
                </div>
            </div>
        </nav>
    `;
    
    // Attach event listeners
    if (!isLoggedIn) {
        const registerLink = document.getElementById('registerLink');
        if (registerLink) {
            registerLink.onclick = (e) => {
                e.preventDefault();
                showRegisterModal();
            };
        }
        
        const loginLink = document.getElementById('loginLink');
        if (loginLink) {
            loginLink.onclick = (e) => {
                e.preventDefault();
                showLoginModal();
            };
        }
    } else {
        const profileLink = document.getElementById('profileLink');
        if (profileLink) {
            profileLink.onclick = (e) => {
                e.preventDefault();
                showProfilePage();
            };
        }
        
        if (isAdmin) {
            const adminLink = document.getElementById('adminLink');
            if (adminLink) {
                adminLink.onclick = (e) => {
                    e.preventDefault();
                    showAdminPage();
                };
            }
        }
        
        const logoutLink = document.getElementById('logoutLink');
        if (logoutLink) {
            logoutLink.onclick = (e) => {
                e.preventDefault();
                handleLogout();
            };
        }
    }
}

/**
 * @brief Show login modal
 */
function showLoginModal(): void {
    const modalDiv = document.createElement('div');
    modalDiv.id = 'loginModal';
    modalDiv.className = 'modal fade';
    modalDiv.setAttribute('tabindex', '-1');
    modalDiv.innerHTML = `
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Log In</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <form id="loginForm">
                        <div class="mb-3">
                            <label for="loginUsername" class="form-label">Username</label>
                            <input type="text" class="form-control" id="loginUsername" required>
                        </div>
                        <div class="mb-3">
                            <label for="loginPassword" class="form-label">Password</label>
                            <input type="password" class="form-control" id="loginPassword" required>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" id="loginSubmitBtn">Log In</button>
                </div>
            </div>
        </div>
    `;
    
    document.body.appendChild(modalDiv);
    const modal = new (window as any).bootstrap.Modal(modalDiv);
    modal.show();
    
    const submitBtn = document.getElementById('loginSubmitBtn');
    if (submitBtn) {
        submitBtn.onclick = async () => {
            const username = (document.getElementById('loginUsername') as HTMLInputElement)?.value;
            const password = (document.getElementById('loginPassword') as HTMLInputElement)?.value;
            
            if (!username || !password) {
                showAlert('Please fill in all fields', 'danger', modalDiv.querySelector('.modal-body') as HTMLElement);
                return;
            }
            
            try {
                const user = await api.login(username, password);
                setCurrentUser(user);
                modal.hide();
                modalDiv.remove();
                window.location.reload();
            } catch (error: any) {
                showAlert(error.message || 'Login failed', 'danger', modalDiv.querySelector('.modal-body') as HTMLElement);
            }
        };
    }
    
    modalDiv.addEventListener('hidden.bs.modal', () => {
        modalDiv.remove();
    });
}

/**
 * @brief Show register modal
 */
function showRegisterModal(): void {
    const modalDiv = document.createElement('div');
    modalDiv.id = 'registerModal';
    modalDiv.className = 'modal fade';
    modalDiv.setAttribute('tabindex', '-1');
    modalDiv.innerHTML = `
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Create Account</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <form id="registerForm">
                        <div class="mb-3">
                            <label for="registerUsername" class="form-label">Username</label>
                            <input type="text" class="form-control" id="registerUsername" required>
                        </div>
                        <div class="mb-3">
                            <label for="registerPassword" class="form-label">Password</label>
                            <input type="password" class="form-control" id="registerPassword" required>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" id="registerSubmitBtn">Create Account</button>
                </div>
            </div>
        </div>
    `;
    
    document.body.appendChild(modalDiv);
    const modal = new (window as any).bootstrap.Modal(modalDiv);
    modal.show();
    
    const submitBtn = document.getElementById('registerSubmitBtn');
    if (submitBtn) {
        submitBtn.onclick = async () => {
            const username = (document.getElementById('registerUsername') as HTMLInputElement)?.value;
            const password = (document.getElementById('registerPassword') as HTMLInputElement)?.value;
            
            if (!username || !password) {
                showAlert('Please fill in all fields', 'danger', modalDiv.querySelector('.modal-body') as HTMLElement);
                return;
            }
            
            try {
                await api.register(username, password);
                showAlert('Account created successfully! Please log in.', 'success', modalDiv.querySelector('.modal-body') as HTMLElement);
                setTimeout(() => {
                    modal.hide();
                    modalDiv.remove();
                    showLoginModal();
                }, 1500);
            } catch (error: any) {
                showAlert(error.message || 'Registration failed', 'danger', modalDiv.querySelector('.modal-body') as HTMLElement);
            }
        };
    }
    
    modalDiv.addEventListener('hidden.bs.modal', () => {
        modalDiv.remove();
    });
}

/**
 * @brief Handle logout
 */
async function handleLogout(): Promise<void> {
    try {
        await api.logout();
        setCurrentUser(null);
        window.location.reload();
    } catch (error: any) {
        showAlert(error.message || 'Logout failed', 'danger', document.body);
    }
}

/**
 * @brief Render thread list
 * @param container Container element
 * @param threads Array of threads
 */
export function renderThreadList(container: HTMLElement, threads: api.Thread[]): void {
    if (threads.length === 0) {
        container.innerHTML = '<div class="alert alert-info">No threads yet. Be the first to create one!</div>';
        return;
    }
    
    let html = '<div class="list-group">';
    
    for (let i = 0; i < threads.length; i++) {
        const thread = threads[i];
        const postCount = thread.posts.length;
        html += `
            <a href="#" class="list-group-item list-group-item-action" data-thread-id="${thread.id}">
                <div class="d-flex w-100 justify-content-between">
                    <h5 class="mb-1">${escapeHtml(thread.title)}</h5>
                    <small>${formatDate(thread.createdAt)}</small>
                </div>
                <p class="mb-1">By ${escapeHtml(thread.author)} • ${postCount} ${postCount === 1 ? 'post' : 'posts'}</p>
            </a>
        `;
    }
    
    html += '</div>';
    container.innerHTML = html;
    
    // Attach click handlers
    const threadLinks = container.querySelectorAll('[data-thread-id]');
    for (let i = 0; i < threadLinks.length; i++) {
        const link = threadLinks[i];
        link.addEventListener('click', function(e: Event) {
            e.preventDefault();
            const threadId = parseInt((e.currentTarget as HTMLElement).getAttribute('data-thread-id') || '0');
            showThreadDetail(threadId);
        });
    }
}

/**
 * @brief Show thread detail page
 * @param threadId Thread ID
 */
async function showThreadDetail(threadId: number): Promise<void> {
    try {
        const threads = await api.getThreads();
        let thread: api.Thread | undefined;
        for (let i = 0; i < threads.length; i++) {
            if (threads[i].id === threadId) {
                thread = threads[i];
                break;
            }
        }
        
        if (!thread) {
            showAlert('Thread not found', 'danger', document.body);
            return;
        }
        
        const container = document.getElementById('mainContent');
        if (!container) return;
        
        const isAdmin = currentUser && currentUser.isAdmin;
        let html = `
            <div class="mb-3">
                <button class="btn btn-secondary" id="backBtn">← Back to Threads</button>
                ${isAdmin ? `<button class="btn btn-danger ms-2" id="deleteThreadBtn">Delete Thread</button>` : ''}
            </div>
            <div class="card mb-3">
                <div class="card-header">
                    <h4>${escapeHtml(thread.title)}</h4>
                    <small>Created by ${escapeHtml(thread.author)} on ${formatDate(thread.createdAt)}</small>
                </div>
                <div class="card-body" id="threadPosts">
        `;
        
        for (let i = 0; i < thread.posts.length; i++) {
            const post = thread.posts[i];
            const canDelete = currentUser && (currentUser.isAdmin || post.author === currentUser.username);
            html += `
                <div class="card mb-3" data-post-id="${post.id}">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-start">
                            <div>
                                <h6 class="card-title">${escapeHtml(post.author)}</h6>
                                <p class="card-text">${escapeHtml(post.content)}</p>
                                <small class="text-muted">${formatDate(post.createdAt)}</small>
                            </div>
                            ${canDelete ? `<button class="btn btn-sm btn-danger" data-delete-post="${post.id}">Delete</button>` : ''}
                        </div>
                    </div>
                </div>
            `;
        }
        
        html += `
                </div>
                ${currentUser ? `
                    <div class="card-footer">
                        <form id="replyForm">
                            <div class="mb-3">
                                <textarea class="form-control" id="replyContent" rows="3" placeholder="Write a reply..." required></textarea>
                            </div>
                            <button type="submit" class="btn btn-primary">Post Reply</button>
                        </form>
                    </div>
                ` : '<div class="card-footer"><p class="text-muted">Please log in to reply</p></div>'}
            </div>
        `;
        
        container.innerHTML = html;
        
        // Back button
        const backBtn = document.getElementById('backBtn');
        if (backBtn) {
            backBtn.onclick = function() {
                loadMainPage();
            };
        }
        
        // Delete thread button (admin only)
        if (isAdmin) {
            const deleteThreadBtn = document.getElementById('deleteThreadBtn');
            if (deleteThreadBtn) {
                deleteThreadBtn.onclick = function() {
                    showConfirmModal('Are you sure you want to delete this entire thread? This action cannot be undone.', function() {
                        api.deleteThread(threadId).then(function() {
                            showAlert('Thread deleted successfully', 'success', document.body);
                            loadMainPage();
                        }).catch(function(error: any) {
                            showAlert(error.message || 'Failed to delete thread', 'danger', container);
                        });
                    });
                };
            }
        }
        
        // Delete post buttons
        const deletePostBtns = container.querySelectorAll('[data-delete-post]');
        for (let i = 0; i < deletePostBtns.length; i++) {
            const btn = deletePostBtns[i];
            btn.addEventListener('click', function(e: Event) {
                const postId = parseInt((e.currentTarget as HTMLElement).getAttribute('data-delete-post') || '0');
                showConfirmModal('Are you sure you want to delete this post?', function() {
                    api.deletePost(threadId, postId).then(function() {
                        showThreadDetail(threadId);
                    }).catch(function(error: any) {
                        showAlert(error.message || 'Failed to delete post', 'danger', container);
                    });
                });
            });
        }
        
        // Reply form
        if (currentUser) {
            const replyForm = document.getElementById('replyForm') as HTMLFormElement;
            if (replyForm) {
                replyForm.onsubmit = async (e) => {
                    e.preventDefault();
                    const content = (document.getElementById('replyContent') as HTMLTextAreaElement)?.value;
                    if (!content) return;
                    
                    try {
                        await api.createPost(threadId, content);
                        showThreadDetail(threadId);
                    } catch (error: any) {
                        showAlert(error.message || 'Failed to create post', 'danger', container);
                    }
                };
            }
        }
    } catch (error: any) {
        showAlert(error.message || 'Failed to load thread', 'danger', document.body);
    }
}

/**
 * @brief Show create thread page
 */
function showCreateThreadPage(): void {
    const container = document.getElementById('mainContent');
    if (!container) return;
    
    container.innerHTML = `
        <div class="mb-3">
            <button class="btn btn-secondary" id="backBtn">← Back to Threads</button>
        </div>
        <div class="card">
            <div class="card-header">
                <h4>Create New Thread</h4>
            </div>
            <div class="card-body">
                <form id="createThreadForm">
                    <div class="mb-3">
                        <label for="threadTitle" class="form-label">Title</label>
                        <input type="text" class="form-control" id="threadTitle" required>
                    </div>
                    <div class="mb-3">
                        <label for="threadContent" class="form-label">Content</label>
                        <textarea class="form-control" id="threadContent" rows="5" required></textarea>
                    </div>
                    <button type="submit" class="btn btn-primary">Create Thread</button>
                </form>
            </div>
        </div>
    `;
    
    const backBtn = document.getElementById('backBtn');
    if (backBtn) {
        backBtn.onclick = () => {
            loadMainPage();
        };
    }
    
    const form = document.getElementById('createThreadForm') as HTMLFormElement;
    if (form) {
        form.onsubmit = async (e) => {
            e.preventDefault();
            const title = (document.getElementById('threadTitle') as HTMLInputElement)?.value;
            const content = (document.getElementById('threadContent') as HTMLTextAreaElement)?.value;
            
            if (!title || !content) {
                showAlert('Please fill in all fields', 'danger', container);
                return;
            }
            
            try {
                await api.createThread(title, content);
                loadMainPage();
            } catch (error: any) {
                showAlert(error.message || 'Failed to create thread', 'danger', container);
            }
        };
    }
}

/**
 * @brief Show profile page
 */
function showProfilePage(): void {
    if (!currentUser) return;
    
    const container = document.getElementById('mainContent');
    if (!container) return;
    
    container.innerHTML = `
        <div class="card">
            <div class="card-header">
                <h4>User Profile</h4>
            </div>
            <div class="card-body">
                <h5>Change Password</h5>
                <form id="changePasswordForm">
                    <div class="mb-3">
                        <label for="currentPassword" class="form-label">Current Password</label>
                        <input type="password" class="form-control" id="currentPassword" required>
                    </div>
                    <div class="mb-3">
                        <label for="newPassword" class="form-label">New Password</label>
                        <input type="password" class="form-control" id="newPassword" required>
                    </div>
                    <button type="submit" class="btn btn-primary">Update Password</button>
                </form>
                <hr>
                <h5>My Posts</h5>
                <div id="myPosts"></div>
            </div>
        </div>
    `;
    
    const form = document.getElementById('changePasswordForm') as HTMLFormElement;
    if (form) {
        form.onsubmit = async (e) => {
            e.preventDefault();
            const currentPassword = (document.getElementById('currentPassword') as HTMLInputElement)?.value;
            const newPassword = (document.getElementById('newPassword') as HTMLInputElement)?.value;
            
            if (!currentPassword || !newPassword) {
                showAlert('Please fill in all fields', 'danger', container);
                return;
            }
            
            try {
                await api.updatePassword(currentUser!.username, newPassword, currentPassword);
                showAlert('Password updated successfully', 'success', container);
                form.reset();
            } catch (error: any) {
                showAlert(error.message || 'Failed to update password', 'danger', container);
            }
        };
    }
    
    // Load user's posts
    loadUserPosts(currentUser.username, document.getElementById('myPosts')!);
}

/**
 * @brief Load user's posts
 * @param username Username
 * @param container Container element
 */
async function loadUserPosts(username: string, container: HTMLElement): Promise<void> {
    try {
        const threads = await api.getThreads();
        const userPosts: Array<{thread: api.Thread, post: api.Post}> = [];
        
        for (let i = 0; i < threads.length; i++) {
            const thread = threads[i];
            for (let j = 0; j < thread.posts.length; j++) {
                const post = thread.posts[j];
                if (post.author === username) {
                    userPosts.push({ thread: thread, post: post });
                }
            }
        }
        
        if (userPosts.length === 0) {
            container.innerHTML = '<p class="text-muted">You have not posted anything yet.</p>';
            return;
        }
        
        let html = '<div class="list-group">';
        for (let i = 0; i < userPosts.length; i++) {
            const item = userPosts[i];
            const thread = item.thread;
            const post = item.post;
            html += `
                <div class="list-group-item">
                    <div class="d-flex justify-content-between align-items-start">
                        <div>
                            <h6 class="mb-1"><a href="#" data-thread-id="${thread.id}">${escapeHtml(thread.title)}</a></h6>
                            <p class="mb-1">${escapeHtml(post.content.substring(0, 100))}${post.content.length > 100 ? '...' : ''}</p>
                            <small>${formatDate(post.createdAt)}</small>
                        </div>
                        <button class="btn btn-sm btn-danger" data-delete-post="${post.id}" data-thread-id="${thread.id}">Delete</button>
                    </div>
                </div>
            `;
        }
        html += '</div>';
        
        container.innerHTML = html;
        
        // Attach event handlers
        const userPostLinks = container.querySelectorAll('[data-thread-id]');
        for (let i = 0; i < userPostLinks.length; i++) {
            const link = userPostLinks[i];
            link.addEventListener('click', function(e: Event) {
                e.preventDefault();
                const threadId = parseInt((e.currentTarget as HTMLElement).getAttribute('data-thread-id') || '0');
                showThreadDetail(threadId);
            });
        }
        
        const userDeleteBtns = container.querySelectorAll('[data-delete-post]');
        for (let i = 0; i < userDeleteBtns.length; i++) {
            const btn = userDeleteBtns[i];
            btn.addEventListener('click', function(e: Event) {
                const postId = parseInt((e.currentTarget as HTMLElement).getAttribute('data-delete-post') || '0');
                const threadId = parseInt((e.currentTarget as HTMLElement).getAttribute('data-thread-id') || '0');
                showConfirmModal('Are you sure you want to delete this post?', function() {
                    api.deletePost(threadId, postId).then(function() {
                        loadUserPosts(username, container);
                    }).catch(function(error: any) {
                        showAlert(error.message || 'Failed to delete post', 'danger', container);
                    });
                });
            });
        }
    } catch (error: any) {
        showAlert(error.message || 'Failed to load posts', 'danger', container);
    }
}

/**
 * @brief Show admin management page
 */
async function showAdminPage(): Promise<void> {
    if (!currentUser || !currentUser.isAdmin) {
        showAlert('Admin access required', 'danger', document.body);
        return;
    }
    
    const container = document.getElementById('mainContent');
    if (!container) return;
    
    try {
        const users = await api.getUsers();
        
        container.innerHTML = `
            <div class="card">
                <div class="card-header">
                    <h4>Administrator Management</h4>
                </div>
                <div class="card-body">
                    <h5>Users</h5>
                    <div class="table-responsive">
                        <table class="table table-striped">
                            <thead>
                                <tr>
                                    <th>Username</th>
                                    <th>Role</th>
                                    <th>Created</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody id="usersTableBody">
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        `;
        
        const tbody = document.getElementById('usersTableBody');
        if (!tbody) return;
        
        for (let i = 0; i < users.length; i++) {
            const user = users[i];
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${escapeHtml(user.username)}</td>
                <td>${user.isAdmin ? '<span class="badge bg-warning">Admin</span>' : '<span class="badge bg-secondary">User</span>'}</td>
                <td>${user.createdAt ? formatDate(user.createdAt) : 'N/A'}</td>
                <td>
                    <button class="btn btn-sm btn-primary me-2" data-reset-password="${user.username}">Reset Password</button>
                    ${!user.isAdmin ? `<button class="btn btn-sm btn-danger" data-delete-user="${user.username}">Delete</button>` : ''}
                </td>
            `;
            tbody.appendChild(row);
        }
        
        // Reset password buttons
        const resetPasswordBtns = tbody.querySelectorAll('[data-reset-password]');
        for (let i = 0; i < resetPasswordBtns.length; i++) {
            const btn = resetPasswordBtns[i];
            btn.addEventListener('click', function(e: Event) {
                const username = (e.currentTarget as HTMLElement).getAttribute('data-reset-password');
                if (!username) return;
                
                showResetPasswordModal(username);
            });
        }
        
        // Delete user buttons
        const deleteUserBtns = tbody.querySelectorAll('[data-delete-user]');
        for (let i = 0; i < deleteUserBtns.length; i++) {
            const btn = deleteUserBtns[i];
            btn.addEventListener('click', function(e: Event) {
                const username = (e.currentTarget as HTMLElement).getAttribute('data-delete-user');
                if (!username) return;
                
                showConfirmModal('Are you sure you want to delete user "' + username + '"?', function() {
                    api.deleteUser(username).then(function() {
                        showAdminPage();
                    }).catch(function(error: any) {
                        showAlert(error.message || 'Failed to delete user', 'danger', container);
                    });
                });
            });
        }
    } catch (error: any) {
        showAlert(error.message || 'Failed to load users', 'danger', container);
    }
}

/**
 * @brief Show reset password modal
 * @param username Username
 */
function showResetPasswordModal(username: string): void {
    const modalDiv = document.createElement('div');
    modalDiv.id = 'resetPasswordModal';
    modalDiv.className = 'modal fade';
    modalDiv.setAttribute('tabindex', '-1');
    modalDiv.innerHTML = `
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Reset Password for ${escapeHtml(username)}</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <form id="resetPasswordForm">
                        <div class="mb-3">
                            <label for="resetNewPassword" class="form-label">New Password</label>
                            <input type="password" class="form-control" id="resetNewPassword" required>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" id="resetPasswordSubmitBtn">Reset Password</button>
                </div>
            </div>
        </div>
    `;
    
    document.body.appendChild(modalDiv);
    const modal = new (window as any).bootstrap.Modal(modalDiv);
    modal.show();
    
    const submitBtn = document.getElementById('resetPasswordSubmitBtn');
    if (submitBtn) {
        submitBtn.onclick = async () => {
            const newPassword = (document.getElementById('resetNewPassword') as HTMLInputElement)?.value;
            
            if (!newPassword) {
                showAlert('Please enter a new password', 'danger', modalDiv.querySelector('.modal-body') as HTMLElement);
                return;
            }
            
            try {
                await api.updatePassword(username, newPassword);
                showAlert('Password reset successfully', 'success', modalDiv.querySelector('.modal-body') as HTMLElement);
                setTimeout(() => {
                    modal.hide();
                    modalDiv.remove();
                }, 1500);
            } catch (error: any) {
                showAlert(error.message || 'Failed to reset password', 'danger', modalDiv.querySelector('.modal-body') as HTMLElement);
            }
        };
    }
    
    modalDiv.addEventListener('hidden.bs.modal', () => {
        modalDiv.remove();
    });
}

/**
 * @brief Load main page
 */
export async function loadMainPage(): Promise<void> {
    const container = document.getElementById('mainContent');
    if (!container) return;
    
    try {
        const threads = await api.getThreads();
        
        container.innerHTML = `
            <div class="d-flex justify-content-between align-items-center mb-3">
                <h2>Forum Threads</h2>
                ${currentUser ? '<button class="btn btn-primary" id="createThreadBtn">Create Thread</button>' : ''}
            </div>
            <div id="threadList"></div>
        `;
        
        renderThreadList(document.getElementById('threadList')!, threads);
        
        const createBtn = document.getElementById('createThreadBtn');
        if (createBtn) {
            createBtn.onclick = () => {
                showCreateThreadPage();
            };
        }
    } catch (error: any) {
        showAlert(error.message || 'Failed to load threads', 'danger', container);
    }
}

/**
 * @brief Escape HTML to prevent XSS
 * @param text Text to escape
 * @return string Escaped text
 */
function escapeHtml(text: string): string {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}


