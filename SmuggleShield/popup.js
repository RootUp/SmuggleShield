console.log("Popup script started");

const CacheManager = {
  cache: new Map(),
  maxSize: 100,
  maxAge: 5 * 60 * 1000,
  head: null,
  tail: null,

  createNode(key, value) {
    return {
      key,
      value,
      timestamp: Date.now(),
      prev: null,
      next: null
    };
  },

  moveToFront(node) {
    if (node === this.head) return;

    const prev = node.prev;
    const next = node.next;

    if (prev) prev.next = next;
    if (next) next.prev = prev;
    if (this.tail === node) this.tail = prev;

    node.next = this.head;
    node.prev = null;
    if (this.head) this.head.prev = node;
    this.head = node;
    if (!this.tail) this.tail = node;
  },

  set(key, value) {
    let node = this.cache.get(key);
    
    if (node) {
      node.value = value;
      node.timestamp = Date.now();
      this.moveToFront(node);
      return;
    }

    node = this.createNode(key, value);
    
    if (this.cache.size >= this.maxSize) {
      this.cache.delete(this.tail.key);
      this.tail = this.tail.prev;
      if (this.tail) this.tail.next = null;
    }

    this.cache.set(key, node);
    
    if (!this.head) {
      this.head = node;
      this.tail = node;
    } else {
      node.next = this.head;
      this.head.prev = node;
      this.head = node;
    }
  },

  get(key) {
    const node = this.cache.get(key);
    if (!node) return null;

    if (Date.now() - node.timestamp > this.maxAge) {
      this.remove(key);
      return null;
    }

    this.moveToFront(node);
    return node.value;
  },

  remove(key) {
    const node = this.cache.get(key);
    if (!node) return;

    if (node.prev) node.prev.next = node.next;
    if (node.next) node.next.prev = node.prev;
    if (this.head === node) this.head = node.next;
    if (this.tail === node) this.tail = node.prev;

    this.cache.delete(key);
  },

  clear() {
    this.cache.clear();
    this.head = null;
    this.tail = null;
  },

  cleanup() {
    const now = Date.now();
    for (const [key, node] of this.cache) {
      if (now - node.timestamp > this.maxAge) {
        this.remove(key);
      }
    }
  }
};

const cleanupInterval = setInterval(() => CacheManager.cleanup(), 60000);

window.addEventListener('unload', () => {
  clearInterval(cleanupInterval);
  CacheManager.clear();
});

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

setInterval(() => {
  const stats = CacheManager.getStats();
  if (stats.size > stats.maxSize * 0.9) {
    console.debug('Cache nearly full:', stats);
  }
}, 300000);
