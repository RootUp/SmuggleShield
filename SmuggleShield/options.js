class WhitelistManager {
    constructor() {
        this.urlInput = document.getElementById('urlInput');
        this.addButton = document.getElementById('addUrl');
        this.urlList = document.getElementById('urlList');
        this.notification = document.getElementById('notification');

        this.setupEventListeners();
        this.loadWhitelist();
    }

    setupEventListeners() {
        this.addButton.addEventListener('click', () => this.addUrl());
        this.urlInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.addUrl();
            }
        });
    }

    async loadWhitelist() {
        try {
            const result = await chrome.storage.local.get('whitelist');
            const whitelist = result.whitelist || [];
            this.renderUrlList(whitelist);
        } catch (error) {
            this.showNotification('Error loading whitelist', 'error');
        }
    }

    async saveWhitelist(whitelist) {
        try {
            await chrome.storage.local.set({ whitelist });
            
            // Get all tabs and update them immediately
            const tabs = await chrome.tabs.query({});
            for (const tab of tabs) {
                try {
                    // First notify the tab
                    await chrome.tabs.sendMessage(tab.id, { 
                        action: "whitelistUpdated" 
                    });
                    
                    // Then reload any tab that matches the whitelist
                    const tabHostname = new URL(tab.url).hostname;
                    if (whitelist.includes(tabHostname)) {
                        await chrome.tabs.reload(tab.id);
                    }
                } catch (error) {
                    console.debug('Error updating tab:', error);
                }
            }
            
            // Show success notification immediately
            this.showNotification('Whitelist updated and applied', 'success');
            return true;
        } catch (error) {
            this.showNotification('Error saving whitelist', 'error');
            return false;
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

    renderUrlList(whitelist) {
        this.urlList.innerHTML = '';
        
        if (whitelist.length === 0) {
            this.urlList.innerHTML = '<p>No URLs whitelisted</p>';
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

    showNotification(message, type) {
        this.notification.textContent = message;
        this.notification.className = `notification ${type}`;
        this.notification.style.display = 'block';
        
        setTimeout(() => {
            this.notification.style.display = 'none';
        }, 3000);
    }
}

// Initialize the whitelist manager when the page loads
document.addEventListener('DOMContentLoaded', () => {
    new WhitelistManager();
}); 