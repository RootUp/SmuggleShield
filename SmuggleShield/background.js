const config = {
  suspiciousURLPatterns: [
    /data:application\/octet-stream/i,
    /blob:/i,
    /javascript:/i
  ],
  suspiciousHeaders: ['content-disposition', 'content-type'],
  logRetentionDays: 10,
  cacheDurationMs: 5 * 60 * 1000,
};

class WeakLRUCache {
  constructor(maxSize) {
    this.maxSize = maxSize;
    this.cache = new Map();
    this.keyMap = new WeakMap();
  }

  get(key) {
    const keyObj = this.keyMap.get(key);
    if (!keyObj) return undefined;
    const value = this.cache.get(keyObj);
    if (value) {
      this.cache.delete(keyObj);
      this.cache.set(keyObj, value);
    }
    return value;
  }

  set(key, value) {
    let keyObj = this.keyMap.get(key);
    if (!keyObj) {
      keyObj = { key };
      this.keyMap.set(key, keyObj);
    }
    if (this.cache.has(keyObj)) {
      this.cache.delete(keyObj);
    } else if (this.cache.size >= this.maxSize) {
      const oldestKey = this.cache.keys().next().value;
      this.cache.delete(oldestKey);
    }
    this.cache.set(keyObj, value);
  }

  clear() {
    this.cache.clear();
    this.keyMap = new WeakMap();
  }
}

const urlCache = new WeakLRUCache(1000);

function memoize(fn, resolver) {
  const cache = new WeakLRUCache(1000);
  return (...args) => {
    const key = resolver ? resolver(...args) : args[0];
    let result = cache.get(key);
    if (result === undefined) {
      result = fn(...args);
      cache.set(key, result);
    }
    return result;
  };
}

const checkSuspiciousURL = memoize((url) => {
  return config.suspiciousURLPatterns.some(pattern => pattern.test(url));
}, (url) => url);

function debounce(func, delay) {
  let timeoutId;
  return (...args) => {
    clearTimeout(timeoutId);
    timeoutId = setTimeout(() => func(...args), delay);
  };
}

const debouncedLogBlockedContent = debounce(logBlockedContent, 1000);

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log('Received message:', request);
  switch (request.action) {
    case "logWarning":
      debouncedLogBlockedContent(sender.tab.url, request.patterns, Date.now());
      console.warn(request.message);
      break;
    case "analyzeURL":
      const result = memoizedAnalyzeURL(request.url);
      if (Date.now() - result.timestamp < config.cacheDurationMs) {
        sendResponse({isSuspicious: result.isSuspicious});
      } else {
        const newResult = memoizedAnalyzeURL(request.url);
        sendResponse({isSuspicious: newResult.isSuspicious});
      }
      return true;
    case "exportLogs":
      chrome.storage.local.get(['blockedLogs'], result => {
        sendResponse({ logs: result.blockedLogs || [] });
      });
      return true;
    case "updateConfig":
      updateConfig(request.newConfig);
      sendResponse({success: true});
      return true;
  }
});

function logBlockedContent(url, patterns, timestamp) {
  chrome.storage.local.get(['blockedLogs'], function(result) {
    let logs = result.blockedLogs || [];
    logs.push({ url, patterns, timestamp });
    const retentionDate = Date.now() - (config.logRetentionDays * 24 * 60 * 60 * 1000);
    logs = logs.filter(log => log.timestamp > retentionDate);
    
    chrome.storage.local.set({ blockedLogs: logs }, () => {
      if (chrome.runtime.lastError) {
        console.error('Error saving logs:', chrome.runtime.lastError);
      }
    });
  });
}

function updateConfig(newConfig) {
  Object.assign(config, newConfig);
  urlCache.clear();
}

const checkSuspiciousHeaders = memoize((headers) => {
  return headers.some(header => 
    config.suspiciousHeaders.includes(header.name.toLowerCase()) &&
    /attachment|application\/octet-stream/i.test(header.value)
  );
}, (headers) => JSON.stringify(headers));

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    const hasSuspiciousHeaders = checkSuspiciousHeaders(details.responseHeaders);

    if (hasSuspiciousHeaders) {
      chrome.tabs.sendMessage(details.tabId, {action: "suspiciousHeadersDetected"})
        .catch(error => console.error('Error sending message:', error));
    }

    return {responseHeaders: details.responseHeaders};
  },
  {urls: ["<all_urls>"]},
  ["responseHeaders"]
);

const memoizedAnalyzeURL = memoize((url) => {
  const isSuspicious = checkSuspiciousURL(url);
  return {isSuspicious, timestamp: Date.now()};
}, (url) => url);
