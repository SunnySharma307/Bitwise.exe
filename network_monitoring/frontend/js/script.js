// API Configuration
const API_BASE_URL = 'http://localhost:5001/api';

// Check if API is available
async function checkAPIConnection() {
    try {
        const response = await fetch(`${API_BASE_URL.replace('/api', '')}/`);
        return response.ok;
    } catch (error) {
        console.error('API connection check failed:', error);
        return false;
    }
}

// Google Maps is now embedded via iframe - no API needed

// Store blocked IP timers for real-time updates
let blockedIPTimers = {};

// Clear all data on page load (both frontend and backend)
async function clearAllData() {
    console.log('Clearing all previous data on page reload...');
    
    // Clear blocked IP timers
    blockedIPTimers = {};
    
    // Reset statistics to 0
    const statElements = {
        'total-packets': 0,
        'attacks-detected': 0,
        'blocked-ips': 0,
        'active-connections': 0,
        'active-ips-count': 0,
        'total-packets-realtime': 0,
        'suspicious-ips-count': 0
    };
    
    Object.keys(statElements).forEach(id => {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = '0';
        }
    });
    
    // Clear attack logs container
    const logsContainer = document.getElementById('logs-container');
    if (logsContainer) {
        logsContainer.innerHTML = `
            <div class="loading">
                <i class="fas fa-spinner fa-spin"></i>
                <p>Loading attack logs...</p>
            </div>
        `;
    }
    
    // Clear connections table
    const connectionsTableBody = document.getElementById('connections-table-body');
    if (connectionsTableBody) {
        connectionsTableBody.innerHTML = `
            <tr>
                <td colspan="4" class="loading-cell">
                    <i class="fas fa-spinner fa-spin"></i> Loading connections...
                </td>
            </tr>
        `;
    }
    
    // Clear blocked IPs container
    const blockedContainer = document.getElementById('blocked-ips-container');
    if (blockedContainer) {
        blockedContainer.innerHTML = `
            <div class="loading">
                <i class="fas fa-spinner fa-spin"></i>
                <p>Loading blocked IPs...</p>
            </div>
        `;
    }
    
    // Clear real-time IPs container
    const realTimeContainer = document.getElementById('real-time-ips-container');
    if (realTimeContainer) {
        realTimeContainer.innerHTML = `
            <div class="loading">
                <i class="fas fa-spinner fa-spin"></i>
                <p>Loading real-time IP data...</p>
            </div>
        `;
    }
    
    // Clear analysis results
    const analysisResults = document.getElementById('analysis-results');
    if (analysisResults) {
        analysisResults.style.display = 'none';
        analysisResults.innerHTML = '';
    }
    
    // Clear upload progress
    const uploadProgress = document.getElementById('upload-progress');
    if (uploadProgress) {
        uploadProgress.style.display = 'none';
        const progressFill = document.getElementById('progress-fill');
        if (progressFill) {
            progressFill.style.width = '0%';
        }
        const progressText = document.getElementById('progress-text');
        if (progressText) {
            progressText.textContent = 'Analyzing...';
        }
    }
    
    // Clear file input
    const fileInput = document.getElementById('pcap-file');
    if (fileInput) {
        fileInput.value = '';
    }
    
    // Clear API base URL from localStorage (except theme)
    const savedTheme = localStorage.getItem('theme');
    localStorage.clear();
    if (savedTheme) {
        localStorage.setItem('theme', savedTheme);
    }
    
    // Clear server-side data
    try {
        const response = await fetch(`${API_BASE_URL}/clear-data`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            cache: 'no-cache'
        });
        
        if (response.ok) {
            const data = await response.json();
            console.log('Server-side data cleared:', data.message);
        } else {
            console.log('Note: Server-side data clear may have failed (server might not be running)');
        }
    } catch (error) {
        // Server might not be running, that's okay
        console.log('Note: Could not clear server-side data (server might not be running)');
    }
    
    console.log('All data cleared. Page will load fresh data from server.');
}

// Initialize dashboard
document.addEventListener('DOMContentLoaded', async function() {
    // Clear all previous data first
    clearAllData();
    
    // Small delay to ensure UI is cleared before loading new data
    await new Promise(resolve => setTimeout(resolve, 100));
    
    // Initialize theme
    initializeTheme();
    
    // Check API connection first
    const apiAvailable = await checkAPIConnection();
    if (!apiAvailable) {
        showAPIConnectionError();
    }
    
    initializeDashboard();
    
    // Load fresh data from server (with cache-busting)
    loadAttackLogs();
    loadConnections();
    loadBlockedIPs();
    loadRealTimeIPs();
    loadAttackLocations();
    setupFileUpload();
    
    // Setup auto-refresh for real-time monitoring
    setupAutoRefresh();
});

// Show API connection error
function showAPIConnectionError() {
    console.error('Backend API is not available. Please ensure the Flask server is running on port 5001.');
    // You can optionally show a notification to the user
}

// Theme Toggle Functions
function initializeTheme() {
    const themeToggle = document.getElementById('theme-toggle');
    const currentTheme = localStorage.getItem('theme') || 'dark';
    
    // Set initial theme
    document.documentElement.setAttribute('data-theme', currentTheme);
    themeToggle.setAttribute('data-theme', currentTheme);
    
    // Add click event listener
    themeToggle.addEventListener('click', toggleTheme);
}

function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    
    // Update theme
    document.documentElement.setAttribute('data-theme', newTheme);
    document.getElementById('theme-toggle').setAttribute('data-theme', newTheme);
    
    // Save to localStorage
    localStorage.setItem('theme', newTheme);
}

// Initialize Dashboard
function initializeDashboard() {
    // Set up navigation
    const navLinks = document.querySelectorAll('.nav-link');
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            navLinks.forEach(l => l.classList.remove('active'));
            this.classList.add('active');
        });
    });
    
    // Load initial statistics
    updateStatistics();
}

// Update Dashboard Statistics from Upload Results
function updateDashboardFromResults(results) {
    console.log('Updating dashboard from upload results:', results);
    
    // Update Total Packets
    if (results.total_packets !== undefined) {
        animateValue('total-packets', results.total_packets);
    } else if (results.analyzed_packets !== undefined) {
        animateValue('total-packets', results.analyzed_packets);
    }
    
    // Update Attacks Detected
    if (results.attacks_detected !== undefined) {
        animateValue('attacks-detected', results.attacks_detected);
    }
    
    // Update Blocked IPs count
    if (results.blocked_ips !== undefined) {
        const blockedCount = Array.isArray(results.blocked_ips) ? results.blocked_ips.length : 0;
        animateValue('blocked-ips', blockedCount);
    }
    
    // Update Active Connections
    if (results.connections !== undefined) {
        const connectionCount = Array.isArray(results.connections) ? results.connections.length : 0;
        animateValue('active-connections', connectionCount);
    }
    
    // Add visual feedback - highlight updated cards
    const statCards = document.querySelectorAll('.stat-card');
    statCards.forEach((card, index) => {
        // Reset animation
        card.style.animation = 'none';
        // Force reflow
        void card.offsetWidth;
        // Apply pulse animation with slight delay for each card
        setTimeout(() => {
            card.style.animation = 'cardPulse 0.6s ease-in-out';
            setTimeout(() => {
                card.style.animation = '';
            }, 600);
        }, index * 50);
    });
    
    console.log('Dashboard updated with new data');
}

// Update Statistics
function updateStatistics() {
    // Add cache-busting parameter
    const timestamp = new Date().getTime();
    fetch(`${API_BASE_URL}/attack-stats?t=${timestamp}`, {
        method: 'GET',
        cache: 'no-cache',
        headers: {
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache'
        }
    })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                const stats = data.statistics;
                
                // Update stats display
                if (stats.total_attacks !== undefined) {
                    animateValue('total-packets', stats.total_attacks || 0);
                    animateValue('attacks-detected', stats.total_attacks || 0);
                }
                
                // Update active connections from connection data
                fetch(`${API_BASE_URL}/connection-data?t=${timestamp}`, {
                    method: 'GET',
                    cache: 'no-cache',
                    headers: {
                        'Cache-Control': 'no-cache, no-store, must-revalidate',
                        'Pragma': 'no-cache'
                    }
                })
                .then(response => response.json())
                .then(connData => {
                    if (connData.status === 'success' && connData.connections) {
                        animateValue('active-connections', connData.connections.length || 0);
                    }
                })
                .catch(error => {
                    console.error('Error fetching connections:', error);
                });
            }
        })
        .catch(error => {
            console.error('Error fetching statistics:', error);
        });
    
    // Load blocked IPs count
    loadBlockedIPs();
}

// Animate value
function animateValue(elementId, value) {
    const element = document.getElementById(elementId);
    if (!element) {
        console.warn(`Element with id '${elementId}' not found`);
        return;
    }
    
    // Get current value
    const currentValue = parseInt(element.textContent) || 0;
    const targetValue = parseInt(value) || 0;
    
    // If values are the same, no need to animate
    if (currentValue === targetValue) {
        return;
    }
    
    const start = currentValue;
    const duration = 800;
    const difference = targetValue - start;
    const increment = difference / (duration / 16);
    let current = start;
    
    const timer = setInterval(() => {
        current += increment;
        if ((increment > 0 && current >= targetValue) || (increment < 0 && current <= targetValue)) {
            element.textContent = targetValue;
            clearInterval(timer);
        } else {
            element.textContent = Math.floor(current);
        }
    }, 16);
}

// Setup File Upload
function setupFileUpload() {
    const uploadArea = document.getElementById('upload-area');
    const fileInput = document.getElementById('pcap-file');
    
    // Click to upload
    uploadArea.addEventListener('click', function() {
        fileInput.click();
    });
    
    // File input change
    fileInput.addEventListener('change', function(e) {
        const file = e.target.files[0];
        if (file) {
            uploadPCAP(file);
        }
    });
    
    // Drag and drop
    uploadArea.addEventListener('dragover', function(e) {
        e.preventDefault();
        uploadArea.style.borderColor = '#2563eb';
        uploadArea.style.background = 'rgba(37, 99, 235, 0.1)';
    });
    
    uploadArea.addEventListener('dragleave', function(e) {
        e.preventDefault();
        uploadArea.style.borderColor = '#334155';
        uploadArea.style.background = 'transparent';
    });
    
    uploadArea.addEventListener('drop', function(e) {
        e.preventDefault();
        uploadArea.style.borderColor = '#334155';
        uploadArea.style.background = 'transparent';
        
        const file = e.dataTransfer.files[0];
        if (file && file.name.endsWith('.pcap')) {
            uploadPCAP(file);
        } else {
            alert('Please upload a valid .pcap file');
        }
    });
}

// Upload PCAP File
function uploadPCAP(file) {
    const uploadProgress = document.getElementById('upload-progress');
    const progressFill = document.getElementById('progress-fill');
    const progressText = document.getElementById('progress-text');
    const analysisResults = document.getElementById('analysis-results');
    
    // Show progress
    uploadProgress.style.display = 'block';
    analysisResults.style.display = 'none';
    
    const formData = new FormData();
    formData.append('file', file);
    
    // Simulate progress
    let progress = 0;
    const progressInterval = setInterval(() => {
        progress += 10;
        progressFill.style.width = progress + '%';
        if (progress >= 90) {
            clearInterval(progressInterval);
        }
    }, 200);
    
    fetch(`${API_BASE_URL}/upload-pcap`, {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        clearInterval(progressInterval);
        progressFill.style.width = '100%';
        progressText.textContent = 'Analysis Complete!';
        
        if (data.status === 'success') {
            const results = data.results;
            
            // Display analysis results
            displayAnalysisResults(results);
            
            // Update dashboard statistics immediately from results
            updateDashboardFromResults(results);
            
            // Refresh all sections with a small delay to ensure server has processed
            setTimeout(() => {
                updateStatistics();
                loadAttackLogs();
                loadConnections();
                loadBlockedIPs();
                loadRealTimeIPs();
                loadAttackLocations();
            }, 500);
        } else {
            alert('Error analyzing file: ' + data.error);
        }
    })
    .catch(error => {
        clearInterval(progressInterval);
        let errorMessage = error.message;
        if (error.message.includes('NetworkError') || error.message.includes('Failed to fetch')) {
            errorMessage = 'Cannot connect to server. Please ensure the Flask backend is running on port 5001.';
        }
        progressText.textContent = 'Error: ' + errorMessage;
        console.error('Error uploading file:', error);
    });
}

// Display Analysis Results
function displayAnalysisResults(results) {
    const analysisResults = document.getElementById('analysis-results');
    
    const resultsHTML = `
        <div class="result-item">
            <h4><i class="fas fa-chart-bar"></i> Analysis Summary</h4>
            <div class="log-details">
                <div class="log-detail">
                    <label>Total Packets:</label>
                    <span>${results.total_packets || 0}</span>
                </div>
                <div class="log-detail">
                    <label>Analyzed Packets:</label>
                    <span>${results.analyzed_packets || 0}</span>
                </div>
                <div class="log-detail">
                    <label>Attacks Detected:</label>
                    <span class="danger">${results.attacks_detected || 0}</span>
                </div>
                <div class="log-detail">
                    <label>Blocked IPs:</label>
                    <span class="warning">${(results.blocked_ips || []).length}</span>
                </div>
            </div>
        </div>
        
        ${results.blocked_ips && results.blocked_ips.length > 0 ? `
        <div class="result-item danger">
            <h4><i class="fas fa-ban"></i> Blocked IP Addresses</h4>
            <div class="log-details">
                ${results.blocked_ips.map(ip => `
                    <div class="log-detail">
                        <label>Blocked:</label>
                        <span>${ip}</span>
                    </div>
                `).join('')}
            </div>
        </div>
        ` : ''}
        
        ${results.attack_types && Object.keys(results.attack_types).length > 0 ? `
        <div class="result-item warning">
            <h4><i class="fas fa-exclamation-triangle"></i> Attack Types Detected</h4>
            <div class="log-details">
                ${Object.entries(results.attack_types).map(([type, count]) => `
                    <div class="log-detail">
                        <label>${type}:</label>
                        <span>${count} occurrences</span>
                    </div>
                `).join('')}
            </div>
        </div>
        ` : ''}
    `;
    
    analysisResults.innerHTML = resultsHTML;
    analysisResults.style.display = 'block';
}

// Load Attack Logs
function loadAttackLogs() {
    const logsContainer = document.getElementById('logs-container');
    
    // Add cache-busting parameter
    const timestamp = new Date().getTime();
    fetch(`${API_BASE_URL}/attack-logs?limit=20&t=${timestamp}`, {
        method: 'GET',
        cache: 'no-cache',
        headers: {
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache'
        }
    })
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            if (data.status === 'success') {
                if (data.logs && data.logs.length > 0) {
                    displayAttackLogs(data.logs);
                } else {
                    logsContainer.innerHTML = `
                        <div class="loading">
                            <i class="fas fa-check-circle"></i>
                            <p>No attack logs found</p>
                        </div>
                    `;
                }
            } else {
                throw new Error(data.error || 'Unknown error');
            }
        })
        .catch(error => {
            console.error('Error loading attack logs:', error);
            let errorMessage = 'Error loading logs';
            if (error.message.includes('NetworkError') || error.message.includes('Failed to fetch')) {
                errorMessage = 'Cannot connect to server. Please ensure the Flask backend is running on port 5001.';
            } else {
                errorMessage = `Error: ${error.message}`;
            }
            logsContainer.innerHTML = `
                <div class="loading">
                    <i class="fas fa-exclamation-circle"></i>
                    <p>${errorMessage}</p>
                    <p style="font-size: 0.8rem; margin-top: 0.5rem; color: var(--text-secondary);">
                        Start the server with: <code>cd backend && python app.py</code>
                    </p>
                </div>
            `;
        });
}

// Display Attack Logs
function displayAttackLogs(logs) {
    const logsContainer = document.getElementById('logs-container');
    
    const logsHTML = logs.map(log => {
        const attackClass = log.attack_type === 'SYN Flood' ? 'danger' : 'warning';
        
        return `
            <div class="log-entry ${attackClass}">
                <div class="log-header">
                    <span class="log-type">${log.attack_type}</span>
                    <span class="log-timestamp">${formatTimestamp(log.timestamp)}</span>
                </div>
                <div class="log-details">
                    <div class="log-detail">
                        <label>Source:</label>
                        <span>${log.source_ip}</span>
                    </div>
                    <div class="log-detail">
                        <label>Destination:</label>
                        <span>${log.destination_ip || 'N/A'}</span>
                    </div>
                    <div class="log-detail">
                        <label>Classification:</label>
                        <span>${log.classification || 'N/A'}</span>
                    </div>
                    <div class="log-detail">
                        <label>Confidence:</label>
                        <span>${log.confidence || 'N/A'}%</span>
                    </div>
                </div>
                ${log.description ? `
                    <p style="margin-top: 0.5rem; color: var(--text-secondary); font-size: 0.9rem;">
                        ${log.description}
                    </p>
                ` : ''}
            </div>
        `;
    }).join('');
    
    logsContainer.innerHTML = logsHTML;
}

// Load Connections
function loadConnections() {
    const tableBody = document.getElementById('connections-table-body');
    
    // Add cache-busting parameter
    const timestamp = new Date().getTime();
    fetch(`${API_BASE_URL}/connection-data?t=${timestamp}`, {
        method: 'GET',
        cache: 'no-cache',
        headers: {
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache'
        }
    })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success' && data.connections.length > 0) {
                displayConnections(data.connections);
                updateConnectionCount(data.connections.length);
            } else {
                tableBody.innerHTML = `
                    <tr>
                        <td colspan="4" class="loading-cell">
                            <i class="fas fa-check-circle"></i> No connections found
                        </td>
                    </tr>
                `;
            }
        })
        .catch(error => {
            console.error('Error loading connections:', error);
            tableBody.innerHTML = `
                <tr>
                    <td colspan="4" class="loading-cell">
                        <i class="fas fa-exclamation-circle"></i> Error loading connections
                    </td>
                </tr>
            `;
        });
}

// Display Connections
function displayConnections(connections) {
    const tableBody = document.getElementById('connections-table-body');
    
    const connectionsHTML = connections.map(conn => `
        <tr>
            <td>${conn.source}</td>
            <td>${conn.destination}</td>
            <td><span class="protocol-badge">${conn.protocol}</span></td>
            <td>${formatTimestamp(conn.timestamp)}</td>
        </tr>
    `).join('');
    
    tableBody.innerHTML = connectionsHTML;
}

// Update Connection Count
function updateConnectionCount(count) {
    const element = document.getElementById('active-connections');
    if (element) {
        element.textContent = count;
    }
}

// Load Blocked IPs
function loadBlockedIPs() {
    const blockedContainer = document.getElementById('blocked-ips-container');
    
    // Add cache-busting parameter
    const timestamp = new Date().getTime();
    fetch(`${API_BASE_URL}/blocked-ips?t=${timestamp}`, {
        method: 'GET',
        cache: 'no-cache',
        headers: {
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache'
        }
    })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                displayBlockedIPs(data.blocked_ips);
                
                // Update blocked IP count
                const blockedCount = document.getElementById('blocked-ips');
                if (blockedCount) {
                    blockedCount.textContent = data.blocked_ips.length;
                }
            } else {
                blockedContainer.innerHTML = `
                    <div class="loading">
                        <i class="fas fa-check-circle"></i>
                        <p>No blocked IPs</p>
                    </div>
                `;
            }
        })
        .catch(error => {
            console.error('Error loading blocked IPs:', error);
            blockedContainer.innerHTML = `
                <div class="loading">
                    <i class="fas fa-exclamation-circle"></i>
                    <p>Error loading blocked IPs</p>
                </div>
            `;
        });
}


// Display Blocked IPs
function displayBlockedIPs(blockedIPs) {
    const blockedContainer = document.getElementById('blocked-ips-container');
    
    if (blockedIPs.length === 0) {
        blockedContainer.innerHTML = `
            <div class="loading">
                <i class="fas fa-check-circle"></i>
                <p>No blocked IPs</p>
            </div>
        `;
        // Clear timers
        blockedIPTimers = {};
        return;
    }
    
    // Store initial remaining seconds for each IP
    blockedIPs.forEach(ip => {
        if (!blockedIPTimers[ip.ip_address]) {
            blockedIPTimers[ip.ip_address] = {
                remaining_seconds: ip.remaining_seconds,
                last_update: Date.now()
            };
        } else {
            // Update with server value if it's significantly different (sync)
            const timeDiff = (Date.now() - blockedIPTimers[ip.ip_address].last_update) / 1000;
            const expectedRemaining = blockedIPTimers[ip.ip_address].remaining_seconds - timeDiff;
            if (Math.abs(expectedRemaining - ip.remaining_seconds) > 5) {
                // Server value is more than 5 seconds different, sync it
                blockedIPTimers[ip.ip_address].remaining_seconds = ip.remaining_seconds;
            }
            blockedIPTimers[ip.ip_address].last_update = Date.now();
        }
    });
    
    // Remove timers for IPs that are no longer blocked
    const currentIPs = new Set(blockedIPs.map(ip => ip.ip_address));
    Object.keys(blockedIPTimers).forEach(ip => {
        if (!currentIPs.has(ip)) {
            delete blockedIPTimers[ip];
        }
    });
    
    const blockedHTML = blockedIPs.map(ip => {
        const remaining = blockedIPTimers[ip.ip_address]?.remaining_seconds || ip.remaining_seconds;
        return `
        <div class="blocked-ip-card" data-ip="${ip.ip_address}">
            <div class="blocked-ip-header">
                <div class="blocked-ip">${ip.ip_address}</div>
                <button class="unblock-btn" onclick="unblockIP('${ip.ip_address}')">
                    <i class="fas fa-unlock"></i> Unblock
                </button>
            </div>
            <div class="blocked-timer" data-ip="${ip.ip_address}">
                <i class="fas fa-clock"></i>
                Auto-unblock in: <span class="timer-value">${formatTime(remaining)}</span>
            </div>
        </div>
    `;
    }).join('');
    
    blockedContainer.innerHTML = blockedHTML;
}

// Unblock IP
function unblockIP(ipAddress) {
    if (!confirm(`Are you sure you want to unblock ${ipAddress}?`)) {
        return;
    }
    
    // Remove from timers immediately
    delete blockedIPTimers[ipAddress];
    
    fetch(`${API_BASE_URL}/unblock-ip`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ ip_address: ipAddress })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            loadBlockedIPs();
            alert(`Successfully unblocked ${ipAddress}`);
        } else {
            alert('Error unblocking IP: ' + data.error);
            // Reload to sync state
            loadBlockedIPs();
        }
    })
    .catch(error => {
        console.error('Error unblocking IP:', error);
        alert('Error unblocking IP: ' + error.message);
        // Reload to sync state
        loadBlockedIPs();
    });
}

// Format Timestamp
function formatTimestamp(timestamp) {
    try {
        const date = new Date(timestamp);
        return date.toLocaleString();
    } catch {
        return timestamp;
    }
}

// Format Time (seconds to readable format)
function formatTime(seconds) {
    if (seconds < 60) {
        return `${Math.floor(seconds)} seconds`;
    } else if (seconds < 3600) {
        const minutes = Math.floor(seconds / 60);
        const remainingSeconds = Math.floor(seconds % 60);
        return `${minutes}m ${remainingSeconds}s`;
    } else {
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        return `${hours}h ${minutes}m`;
    }
}

// Auto-refresh blocked IPs countdown
setInterval(() => {
    const blockedContainer = document.getElementById('blocked-ips-container');
    if (!blockedContainer) return;
    
    const timerElements = blockedContainer.querySelectorAll('.timer-value');
    const now = Date.now();
    
    timerElements.forEach(element => {
        const ip = element.closest('.blocked-ip-card')?.getAttribute('data-ip');
        if (!ip || !blockedIPTimers[ip]) return;
        
        // Calculate elapsed time since last update
        const elapsed = (now - blockedIPTimers[ip].last_update) / 1000;
        blockedIPTimers[ip].remaining_seconds = Math.max(0, blockedIPTimers[ip].remaining_seconds - elapsed);
        blockedIPTimers[ip].last_update = now;
        
        // Update display
        if (blockedIPTimers[ip].remaining_seconds <= 0) {
            element.textContent = 'Expired';
            // Reload blocked IPs to remove expired ones
            loadBlockedIPs();
        } else {
            element.textContent = formatTime(blockedIPTimers[ip].remaining_seconds);
        }
    });
}, 1000);

// Periodically sync with server (every 30 seconds)
setInterval(() => {
    if (Object.keys(blockedIPTimers).length > 0) {
        loadBlockedIPs();
    }
}, 30000);

// Google Maps is now embedded via iframe - no initialization needed

// Load Real-Time IPs
function loadRealTimeIPs() {
    const container = document.getElementById('real-time-ips-container');
    
    // Add cache-busting parameter
    const timestamp = new Date().getTime();
    fetch(`${API_BASE_URL}/real-time-ips?t=${timestamp}`, {
        method: 'GET',
        cache: 'no-cache',
        headers: {
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache'
        }
    })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                displayRealTimeIPs(data.ips);
                
                // Update stats
                document.getElementById('active-ips-count').textContent = data.total_ips || 0;
                const totalPackets = data.ips.reduce((sum, ip) => sum + ip.packet_count, 0);
                document.getElementById('total-packets-realtime').textContent = totalPackets;
                const suspiciousCount = data.ips.filter(ip => ip.is_attacker || ip.is_blocked).length;
                document.getElementById('suspicious-ips-count').textContent = suspiciousCount;
            } else {
                throw new Error(data.error || 'Unknown error');
            }
        })
        .catch(error => {
            console.error('Error loading real-time IPs:', error);
            container.innerHTML = `
                <div class="loading">
                    <i class="fas fa-exclamation-circle"></i>
                    <p>Error loading real-time IP data</p>
                </div>
            `;
        });
}

// Display Real-Time IPs
function displayRealTimeIPs(ips) {
    const container = document.getElementById('real-time-ips-container');
    
    if (ips.length === 0) {
        container.innerHTML = `
            <div class="loading">
                <i class="fas fa-check-circle"></i>
                <p>No active IPs to monitor</p>
            </div>
        `;
        return;
    }
    
    const ipsHTML = ips.map(ip => {
        const statusClass = ip.is_attacker ? 'danger' : ip.is_blocked ? 'warning' : 'success';
        const statusIcon = ip.is_attacker ? 'fa-exclamation-triangle' : ip.is_blocked ? 'fa-ban' : 'fa-check-circle';
        const statusText = ip.is_attacker ? 'Attacker' : ip.is_blocked ? 'Blocked' : 'Normal';
        
        return `
            <div class="real-time-ip-card ${statusClass}">
                <div class="ip-card-header">
                    <div class="ip-address">
                        <i class="fas fa-network-wired"></i>
                        <span>${ip.ip_address}</span>
                        <span class="ip-status ${statusClass}">
                            <i class="fas ${statusIcon}"></i> ${statusText}
                        </span>
                    </div>
                    <button class="btn-icon" onclick="viewIPOnMap('${ip.ip_address}')" title="View on map">
                        <i class="fas fa-map-marker-alt"></i>
                    </button>
                </div>
                <div class="ip-stats">
                    <div class="ip-stat">
                        <label>Packets:</label>
                        <span>${ip.packet_count}</span>
                    </div>
                    <div class="ip-stat">
                        <label>Connections:</label>
                        <span>${ip.connection_count}</span>
                    </div>
                    <div class="ip-stat">
                        <label>Protocols:</label>
                        <span>${ip.protocols.join(', ')}</span>
                    </div>
                    <div class="ip-stat">
                        <label>Last Seen:</label>
                        <span>${formatTimestamp(ip.last_seen)}</span>
                    </div>
                </div>
            </div>
        `;
    }).join('');
    
    container.innerHTML = `<div class="real-time-ips-grid">${ipsHTML}</div>`;
}

// View IP on Map
function viewIPOnMap(ipAddress) {
    // Get geolocation for this IP
    fetch(`${API_BASE_URL}/ip-geolocation?ips=${ipAddress}`)
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success' && data.geolocations.length > 0) {
                const geo = data.geolocations[0];
                if (geo.lat && geo.lon) {
                    // Open Google Maps in new tab
                    const url = `https://www.google.com/maps?q=${geo.lat},${geo.lon}`;
                    window.open(url, '_blank');
                } else {
                    alert('Location data not available for this IP');
                }
            } else {
                alert('Could not retrieve location for this IP');
            }
        })
        .catch(error => {
            console.error('Error getting IP location:', error);
            alert('Error retrieving IP location');
        });
}

// Load Attack Locations
// Note: Map is now embedded via iframe, so this function is kept for potential future use
function loadAttackLocations() {
    // Map is embedded via iframe, no need to load locations programmatically
    // This function is kept for API compatibility but does nothing
    console.log('Map is embedded via iframe - no action needed');
}

// Setup Auto-Refresh
function setupAutoRefresh() {
    const toggle = document.getElementById('auto-refresh-toggle');
    let refreshInterval = null;
    
    toggle.addEventListener('change', function() {
        if (this.checked) {
            // Refresh every 10 seconds
            refreshInterval = setInterval(() => {
                loadRealTimeIPs();
            }, 10000);
        } else {
            if (refreshInterval) {
                clearInterval(refreshInterval);
            }
        }
    });
    
    // Start auto-refresh if enabled
    if (toggle.checked) {
        refreshInterval = setInterval(() => {
            loadRealTimeIPs();
        }, 10000);
    }
}

// Periodic refresh
setInterval(() => {
    updateStatistics();
}, 30000); // Refresh every 30 seconds

