/**
 * @file main.ts
 * @brief Main entry point for the forum frontend application
 * @details Initializes the application and sets up the main UI
 * @date 2025-12-18
 * @author Victor Yeh
 */

import * as api from './api';
import * as components from './components';

/**
 * @brief Initialize the application
 */
async function init(): Promise<void> {
    // Check if user is logged in
    try {
        const user = await api.getCurrentUser();
        components.setCurrentUser(user);
    } catch (error) {
        // User is not logged in
        components.setCurrentUser(null);
    }
    
    // Render navbar
    const navbarContainer = document.createElement('div');
    navbarContainer.id = 'navbar';
    document.body.insertBefore(navbarContainer, document.body.firstChild);
    components.renderNavbar(navbarContainer);
    
    // Render main content
    const mainContainer = document.createElement('div');
    mainContainer.id = 'mainContent';
    mainContainer.className = 'container mt-4';
    document.getElementById('app')!.appendChild(mainContainer);
    
    // Load main page
    await components.loadMainPage();
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}

