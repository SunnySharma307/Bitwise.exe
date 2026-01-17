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

// Initialize dashboard
document.addEventListener('DOMContentLoaded', async function() {
    // Initialize theme
    initializeTheme();
    
    // Check API connection first
    const apiAvailable = await checkAPIConnection();
    if (!apiAvailable) {
        showAPIConnectionError();
    }
    
    initializeDashboard();
    loadAttackLogs();
    loadConnections();
    loadBlockedIPs();
    setupFileUpload();
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

// Update Statistics
function updateStatistics() {
    fetch(`${API_BASE_URL}/attack-stats`)
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                const stats = data.statistics;
                
                // Update stats display
                animateValue('total-packets', stats.total_attacks || 0);
                animateValue('attacks-detected', stats.total_attacks || 0);
                animateValue('active-connections', stats.total_attacks || 0);
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
    if (!element) return;
    
    const start = 0;
    const duration = 1000;
    const increment = value / (duration / 16);
    let current = start;
    
    const timer = setInterval(() => {
        current += increment;
        if (current >= value) {
            element.textContent = value;
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
            displayAnalysisResults(data.results);
            updateStatistics();
            loadAttackLogs();
            loadConnections();
            loadBlockedIPs();
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
    
    fetch(`${API_BASE_URL}/attack-logs?limit=20`)
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
    
    fetch(`${API_BASE_URL}/connection-data`)
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
    
    fetch(`${API_BASE_URL}/blocked-ips`)
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
        return;
    }
    
    const blockedHTML = blockedIPs.map(ip => `
        <div class="blocked-ip-card">
            <div class="blocked-ip-header">
                <div class="blocked-ip">${ip.ip_address}</div>
                <button class="unblock-btn" onclick="unblockIP('${ip.ip_address}')">
                    <i class="fas fa-unlock"></i> Unblock
                </button>
            </div>
            <div class="blocked-timer">
                <i class="fas fa-clock"></i>
                Auto-unblock in: ${formatTime(ip.remaining_seconds)}
            </div>
        </div>
    `).join('');
    
    blockedContainer.innerHTML = blockedHTML;
}

// Unblock IP
function unblockIP(ipAddress) {
    if (!confirm(`Are you sure you want to unblock ${ipAddress}?`)) {
        return;
    }
    
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
        }
    })
    .catch(error => {
        console.error('Error unblocking IP:', error);
        alert('Error unblocking IP: ' + error.message);
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
    const blockedCards = blockedContainer.querySelectorAll('.blocked-timer');
    
    blockedCards.forEach(card => {
        // Update countdown timers
        // This would need actual data refresh for accurate countdown
    });
}, 1000);

// Periodic refresh
setInterval(() => {
    updateStatistics();
}, 30000); // Refresh every 30 seconds