// RDP Gateway Web Interface
let userInfo = null;

// Theme handling - SVG logo works for both light and dark modes
function updateLogo() {
    const logoImage = document.getElementById('logoImage');
    if (logoImage) {
        logoImage.src = '/assets/icon.svg';
    }
}

// Configuration
const config = {
    progressAnimationDuration: 2000, // ms for progress bar animation
};

// Get user initials for avatar
function getUserInitials(name) {
    return name.split(' ').map(word => word.charAt(0)).slice(0, 2).join('').toUpperCase() || 'U';
}

// Check if response indicates authentication failure and redirect to login if needed
function handleAuthenticationError(response) {
    if (response.status === 401 || response.status === 403) {
        // Authentication failed - redirect to main page to trigger login
        window.location.href = '/';
        return true;
    }
    return false;
}

// Load user information
async function loadUserInfo() {
    try {
        const response = await fetch('/api/v1/user');
        if (response.ok) {
            userInfo = await response.json();
            document.getElementById('username').textContent = userInfo.username;
            document.getElementById('userAvatar').textContent = getUserInitials(userInfo.username);
        } else if (handleAuthenticationError(response)) {
            // Authentication error handled, no need to show error message
            return;
        } else {
            throw new Error('Failed to load user info');
        }
    } catch (error) {
        showError('Failed to load user information');
    }
}

// Load available servers
async function loadServers() {
    try {
        const response = await fetch('/api/v1/hosts');
        if (response.ok) {
            const servers = await response.json();
            renderServers(servers);
        } else if (handleAuthenticationError(response)) {
            // Authentication error handled, no need to show error message
            return;
        } else {
            throw new Error('Failed to load servers');
        }
    } catch (error) {
        showError('Failed to load available servers');
    }
}

// Render servers in the grid
function renderServers(servers) {
    const grid = document.getElementById('serversGrid');
    grid.innerHTML = '';

    servers.forEach(server => {
        const card = document.createElement('div');
        card.className = 'server-card';

        const connectButton = document.createElement('button');
        connectButton.className = 'server-connect-button';
        connectButton.textContent = `Connect to ${server.name}`;
        connectButton.onclick = (e) => {
            e.stopPropagation();
            connectToServer(server, connectButton);
        };

        card.innerHTML = `
            <div class="server-content">
                <div class="server-icon">
                    <img src="/assets/connect.svg" alt="Connect" />
                </div>
                <div class="server-info">
                    <div class="server-name">${server.name}</div>
                    <div class="server-description">${server.description}</div>
                </div>
            </div>
        `;

        card.appendChild(connectButton);
        grid.appendChild(card);
    });
}


// Show error message
function showError(message) {
    const errorDiv = document.getElementById('error');
    errorDiv.textContent = message;
    errorDiv.style.display = 'block';
    hideSuccess();
}

// Hide error message
function hideError() {
    document.getElementById('error').style.display = 'none';
}

// Show success message
function showSuccess(message) {
    const successDiv = document.getElementById('success');
    successDiv.textContent = message;
    successDiv.style.display = 'block';
    hideError();
}

// Hide success message
function hideSuccess() {
    document.getElementById('success').style.display = 'none';
}

// Animate progress bar
function animateProgress(duration = config.progressAnimationDuration) {
    const progressFill = document.getElementById('progressFill');
    progressFill.style.width = '0%';

    let startTime = null;
    function animate(currentTime) {
        if (!startTime) startTime = currentTime;
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);

        progressFill.style.width = (progress * 100) + '%';

        if (progress < 1) {
            requestAnimationFrame(animate);
        }
    }
    requestAnimationFrame(animate);
}

// Generate filename with user initials and random prefix
function generateFilename() {
    if (!userInfo) return 'connection.rdp';

    const initials = getUserInitials(userInfo.username);
    const randomStr = Math.random().toString(36).substring(2, 8).toUpperCase();
    return `${initials}_${randomStr}.rdp`;
}

// Download RDP file
async function downloadRDPFile(url) {
    // First check if the download URL is accessible to detect authentication errors
    try {
        const checkResponse = await fetch(url, { method: 'HEAD' });
        if (handleAuthenticationError(checkResponse)) {
            return; // Will redirect to login
        }
        if (!checkResponse.ok) {
            throw new Error(`Download failed: ${checkResponse.status}`);
        }
    } catch (error) {
        // If HEAD request fails, still try the download - might be a CORS issue
        console.warn('HEAD request failed, proceeding with download:', error);
    }

    // Proceed with download
    const link = document.createElement('a');
    link.href = url;
    link.download = generateFilename();
    link.style.display = 'none';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// Connect to server
async function connectToServer(server, button) {
    if (!server) return;

    hideError();
    hideSuccess();

    const originalButtonText = button.textContent;
    const loading = document.getElementById('loading');

    // Update UI for loading state
    button.disabled = true;
    button.textContent = 'Downloading...';
    loading.style.display = 'block';

    // Start progress animation
    animateProgress();

    try {
        // Build the RDP download URL
        let url = '/connect';
        if (server.address) {
            url += '?host=' + encodeURIComponent(server.address);
        }

        // Wait a moment for better UX
        await new Promise(resolve => setTimeout(resolve, 500));

        // Download the RDP file
        await downloadRDPFile(url);
        showSuccess('RDP file downloaded. Please open it with your RDP client.');

        // Reset UI after a delay
        setTimeout(() => {
            button.disabled = false;
            button.textContent = originalButtonText;
            loading.style.display = 'none';
        }, 2000);

    } catch (error) {
        console.error('Connection error:', error);
        showError('Failed to download RDP file. Please try again.');

        // Reset UI immediately on error
        button.disabled = false;
        button.textContent = originalButtonText;
        loading.style.display = 'none';
    }
}


// Initialize the application
document.addEventListener('DOMContentLoaded', async () => {
    // Set initial logo based on theme
    updateLogo();

    // Load data
    await loadUserInfo();
    await loadServers();

    // No additional event handlers needed - buttons are handled in renderServers
});

// Handle visibility change (for auto-refresh when tab becomes visible)
document.addEventListener('visibilitychange', () => {
    if (!document.hidden) {
        // Refresh server list when tab becomes visible
        loadServers();
    }
});