class DashboardManager {
    constructor() {
        this.initializeComponents();
        this.setupEventListeners();
        this.loadInitialData();
        this.initializeTheme();
        this.ensureWhitelistFunctionality();
        
        this.errorCount = 0;
        this.maxErrorRetries = 3;
        this.retryDelay = 2000; // ms
    }

    initializeComponents() {
        this.navItems = document.querySelectorAll('.nav-item');
        this.sections = {
            whitelist: document.getElementById('whitelist-section'),
            metrics: document.getElementById('metrics-section'),
            logs: document.getElementById('logs-section')
        };

        this.urlInput = document.getElementById('urlInput');
        this.addButton = document.getElementById('addUrl');
        this.urlList = document.getElementById('urlList');
        this.notification = document.getElementById('notification');

        this.exportButton = document.getElementById('export-logs');

        this.mlMetricsDiv = document.getElementById('ml-metrics');

        this.themeToggle = document.getElementById('themeToggle');
        this.themeText = document.getElementById('themeText');
        this.sunIcon = document.querySelector('.sun-icon');
        this.moonIcon = document.querySelector('.moon-icon');
    }

    initializeTheme() {
        const savedTheme = localStorage.getItem('theme') || 'dark';
        this.setTheme(savedTheme);
    }

    setTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('theme', theme);
        
        if (theme === 'light') {
            this.themeText.textContent = 'Dark Mode';
            this.sunIcon.style.display = 'block';
            this.moonIcon.style.display = 'none';
        } else {
            this.themeText.textContent = 'Light Mode';
            this.sunIcon.style.display = 'none';
            this.moonIcon.style.display = 'block';
        }
    }

    toggleTheme() {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'light' ? 'dark' : 'light';
        this.setTheme(newTheme);
    }

    setupEventListeners() {
        this.navItems.forEach(item => {
            item.addEventListener('click', () => this.switchSection(item.dataset.section));
        });

        this.addButton.addEventListener('click', () => this.addUrl());
        this.urlInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.addUrl();
        });

        this.exportButton.addEventListener('click', () => this.handleExport());

        this.themeToggle.addEventListener('click', () => this.toggleTheme());
    }

    switchSection(sectionId) {
        this.navItems.forEach(item => {
            item.classList.toggle('active', item.dataset.section === sectionId);
        });

        Object.entries(this.sections).forEach(([id, element]) => {
            element.style.display = id === sectionId ? 'block' : 'none';
        });
    }

    async loadInitialData() {
        await this.loadWhitelist();
        this.updateMLMetrics();
        setInterval(() => this.updateMLMetrics(), 5000);
    }

    async loadWhitelist() {
        try {
            const result = await chrome.storage.local.get('whitelist');
            const whitelist = result.whitelist || [];
            this.renderUrlList(whitelist);
            console.log('Current whitelist:', whitelist);
            return whitelist;
        } catch (error) {
            this.showNotification('Error loading whitelist', 'error');
            console.error('Error loading whitelist:', error);
            
            if (this.errorCount < this.maxErrorRetries) {
                this.errorCount++;
                console.log(`Retrying whitelist load (${this.errorCount}/${this.maxErrorRetries})...`);
                setTimeout(() => this.loadWhitelist(), this.retryDelay);
            } else {
                this.showNotification('Failed to load whitelist after multiple attempts', 'error');
            }
            return [];
        }
    }

    async addUrl() {
        const url = this.urlInput.value.trim();
        
        if (!url) {
            this.showNotification('Please enter a URL', 'error');
            return;
        }

        try {
            const urlObj = new URL(url);
            const hostname = urlObj.hostname;

            const result = await chrome.storage.local.get('whitelist');
            const whitelist = result.whitelist || [];

            if (whitelist.includes(hostname)) {
                this.showNotification('This domain is already whitelisted', 'error');
                return;
            }

            whitelist.push(hostname);
            
            if (await this.saveWhitelist(whitelist)) {
                this.renderUrlList(whitelist);
                this.urlInput.value = '';
                this.showNotification('URL added to whitelist', 'success');
            }
        } catch (error) {
            this.showNotification('Please enter a valid URL', 'error');
        }
    }

    async removeUrl(hostname) {
        try {
            const result = await chrome.storage.local.get('whitelist');
            const whitelist = result.whitelist || [];
            const newWhitelist = whitelist.filter(url => url !== hostname);
            
            if (await this.saveWhitelist(newWhitelist)) {
                this.renderUrlList(newWhitelist);
                this.showNotification('URL removed from whitelist', 'success');
            }
        } catch (error) {
            this.showNotification('Error removing URL', 'error');
        }
    }

    async saveWhitelist(whitelist) {
        try {
            await chrome.storage.local.set({ whitelist });
            
            const tabs = await chrome.tabs.query({});
            for (const tab of tabs) {
                try {
                    await chrome.tabs.sendMessage(tab.id, { 
                        action: "whitelistUpdated" 
                    });
                    
                    const tabHostname = new URL(tab.url).hostname;
                    if (whitelist.includes(tabHostname)) {
                        await chrome.tabs.reload(tab.id);
                    }
                } catch (error) {
                    console.debug('Error updating tab:', error);
                }
            }
            
            return true;
        } catch (error) {
            this.showNotification('Error saving whitelist', 'error');
            return false;
        }
    }

    renderUrlList(whitelist) {
        this.urlList.innerHTML = '';
        
        if (whitelist.length === 0) {
            this.urlList.innerHTML = '<p class="empty-list">No URLs whitelisted</p>';
            return;
        }

        whitelist.forEach(hostname => {
            const urlItem = document.createElement('div');
            urlItem.className = 'url-item';
            
            const urlText = document.createElement('span');
            urlText.textContent = hostname;
            
            const removeButton = document.createElement('button');
            removeButton.textContent = 'Remove';
            removeButton.addEventListener('click', () => this.removeUrl(hostname));
            
            urlItem.appendChild(urlText);
            urlItem.appendChild(removeButton);
            this.urlList.appendChild(urlItem);
        });
    }

    async updateMLMetrics() {
        try {
            const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
            
            if (!tab) {
                this.mlMetricsDiv.innerHTML = '<p>No active tab found - metrics only available for active tabs.</p>';
                return;
            }

            if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
                this.mlMetricsDiv.innerHTML = '<p>Metrics not available on this page type.</p>';
                return;
            }

            try {
                const response = await chrome.tabs.sendMessage(tab.id, {
                    action: "getMLMetrics"
                });
                
                if (response?.metrics) {
                    const metrics = response.metrics;
                    this.renderMLMetrics(metrics);
                } else {
                    this.mlMetricsDiv.innerHTML = '<p>No metrics data available for the current page.</p>';
                }
            } catch (error) {
                console.error('Error sending message to tab:', error);
                this.mlMetricsDiv.innerHTML = '<p>Could not communicate with the SmuggleShield content script on this page.</p>';
            }
        } catch (error) {
            console.error('Error updating ML metrics:', error);
            this.mlMetricsDiv.innerHTML = `<p>Error loading ML metrics: ${error.message}</p>`;
        }
    }

    renderMLMetrics(metrics) {
        this.mlMetricsDiv.innerHTML = `
            <div class="metric-card">
                <h3>Model Accuracy</h3>
                <div class="metric-value">${(metrics.accuracy * 100).toFixed(2)}%</div>
            </div>
            <div class="metric-card">
                <h3>Total Detections</h3>
                <div class="metric-value">${metrics.totalDetections}</div>
            </div>
            <div class="metric-card">
                <h3>Average Confidence</h3>
                <div class="metric-value">${(metrics.averageConfidence * 100).toFixed(2)}%</div>
            </div>
            <div class="metric-card">
                <h3>Top Features</h3>
                <ul>
                    ${metrics.topFeatures.map(f => 
                        `<li>${f.feature}: ${(f.importance * 100).toFixed(2)}%</li>`
                    ).join('')}
                </ul>
            </div>
        `;

        const topFeaturesUl = this.mlMetricsDiv.querySelector('.metric-card:last-child ul');
        if (topFeaturesUl) {
            topFeaturesUl.innerHTML = ''; // Clear existing LIs if we are re-rendering
            metrics.topFeatures.forEach(f => {
                const listItem = document.createElement('li');
                listItem.textContent = `${f.feature}: ${(f.importance * 100).toFixed(2)}%`;
                topFeaturesUl.appendChild(listItem);
            });
        }
    }

    async handleExport() {
        try {
            this.exportButton.disabled = true;
            this.exportButton.textContent = 'Exporting...';

            const response = await new Promise((resolve, reject) => {
                chrome.runtime.sendMessage({action: "exportLogs"}, (response) => {
                    if (chrome.runtime.lastError) {
                        reject(chrome.runtime.lastError);
                    } else {
                        resolve(response);
                    }
                });
            });

            if (!response?.logs?.length) {
                this.showNotification('No logs available to export', 'warning');
                return;
            }

            await this.processExport(response.logs);
            this.showNotification('Logs exported successfully!', 'success');
        } catch (error) {
            console.error('Export failed:', error);
            this.showNotification(`Export failed: ${error.message}`, 'error');
        } finally {
            this.exportButton.disabled = false;
            this.exportButton.textContent = 'Export Blocked Content Logs';
        }
    }

    async processExport(logs) {
        const blob = new Blob([JSON.stringify(logs, null, 2)], {
            type: "application/json"
        });
        
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `smuggleshield_logs_${new Date().toISOString()}.json`;
        
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    showNotification(message, type) {
        this.notification.textContent = message;
        this.notification.className = `notification ${type}`;
        this.notification.classList.add('show');
        
        // Log errors for debugging
        if (type === 'error') {
            console.error(`Notification error: ${message}`);
        }
        
        setTimeout(() => {
            this.notification.classList.remove('show');
        }, 3000);
    }

    async ensureWhitelistFunctionality() {
        try {
            const result = await chrome.storage.local.get('whitelist');
            if (!result.whitelist) {
                await chrome.storage.local.set({ whitelist: [] });
                console.log('Initialized empty whitelist');
            }
            
            await this.loadWhitelist();
        } catch (error) {
            console.error('Error ensuring whitelist functionality:', error);
            this.showNotification('Error initializing whitelist', 'error');
            
            setTimeout(() => {
                this.recoveryInitialization();
            }, 3000);
        }
    }
    
    async recoveryInitialization() {
        try {
            console.log('Attempting recovery initialization...');
            // Force reset of whitelist
            await chrome.storage.local.set({ whitelist: [] });
            await this.loadWhitelist();
            this.showNotification('Whitelist has been reset due to initialization error', 'warning');
        } catch (error) {
            console.error('Recovery initialization failed:', error);
            this.showNotification('Critical error with whitelist functionality', 'error');
        }
    }
}

document.addEventListener('DOMContentLoaded', () => {
    new DashboardManager();
}); 
