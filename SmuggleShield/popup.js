console.log("Popup script started");

const CacheManager = {
  cache: new Map(),
  maxSize: 100,
  maxAge: 5 * 60 * 1000,

  set(key, value) {
    if (this.cache.size >= this.maxSize) {
      const oldestKey = this.cache.keys().next().value;
      this.cache.delete(oldestKey);
    }
    this.cache.set(key, {
      value,
      timestamp: Date.now()
    });
  },

  get(key) {
    const entry = this.cache.get(key);
    if (!entry) return null;
    
    if (Date.now() - entry.timestamp > this.maxAge) {
      this.cache.delete(key);
      return null;
    }
    
    return entry.value;
  },

  clear() {
    this.cache.clear();
  },

  cleanup() {
    const now = Date.now();
    for (const [key, entry] of this.cache.entries()) {
      if (now - entry.timestamp > this.maxAge) {
        this.cache.delete(key);
      }
    }
  }
};

setInterval(() => CacheManager.cleanup(), 60000);

function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

async function handleExport() {
  const exportButton = document.getElementById('export-logs');
  const originalText = exportButton.textContent;
  
  try {
    if (CacheManager.get("logs")) {
      return processExport(CacheManager.get("logs"));
    }

    exportButton.disabled = true;
    exportButton.textContent = 'Exporting...';

    const response = await new Promise((resolve, reject) => {
      chrome.runtime.sendMessage({action: "exportLogs"}, (response) => {
        if (chrome.runtime.lastError) {
          reject(chrome.runtime.lastError);
        } else {
          resolve(response);
        }
      });
    });

    if (response?.logs) {
      CacheManager.set("logs", response.logs);
    }

    await processExport(response?.logs);
  } catch (error) {
    console.error('Export failed:', error);
    showNotification('error', `Export failed: ${error.message}`);
  } finally {
    exportButton.disabled = false;
    exportButton.textContent = originalText;
  }
}

async function processExport(logs) {
  if (!logs?.length) {
    showNotification('warning', 'No logs available to export.');
    return;
  }

  try {
    const blob = new Blob([JSON.stringify(logs, null, 2)], {
      type: "application/json"
    });
    
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `smuggleshield_logs_${new Date().toISOString()}.json`;
    
    requestAnimationFrame(() => {
      document.body.appendChild(a);
      a.click();
      
      requestAnimationFrame(() => {
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      });
    });

    showNotification('success', 'Logs exported successfully!');
  } catch (error) {
    throw new Error(`Failed to process export: ${error.message}`);
  }
}

function showNotification(type, message) {
  const notification = document.createElement('div');
  notification.className = `notification ${type}`;
  notification.textContent = message;
  
  requestAnimationFrame(() => {
    document.body.appendChild(notification);
    
    notification.offsetHeight;
    notification.classList.add('show');
    
    setTimeout(() => {
      notification.classList.add('fade-out');
      setTimeout(() => {
        if (notification.parentNode) {
          document.body.removeChild(notification);
        }
      }, 300);
    }, 3000);
  });
}

document.addEventListener('DOMContentLoaded', () => {
  const exportButton = document.getElementById('export-logs');
  
  const debouncedExport = debounce(handleExport, 300);
  
  exportButton.addEventListener('click', debouncedExport);
  
  window.addEventListener('unload', () => {
    CacheManager.clear();
  });
});
