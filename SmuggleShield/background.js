const config = {
  suspiciousURLPatterns: [
    /data:application\/octet-stream/i,
    /data:application\/x-rar-compressed/i,
    /blob:/i,
    /javascript:/i
  ],
  suspiciousHeaders: ['content-disposition', 'content-type'],
  logRetentionDays: 10,
  cacheDurationMs: 5 * 60 * 1000,
  whitelistEnabled: true
};

class WeakLRUCache {
  constructor(maxSize) {
    this.maxSize = maxSize;
    this.cache = new Map();
    this.keyMap = new Map();
  }

  get(key) {
    const keyString = this.getKeyString(key);
    const value = this.cache.get(keyString);
    if (value) {
      this.cache.delete(keyString);
      this.cache.set(keyString, value);
    }
    return value;
  }

  set(key, value) {
    const keyString = this.getKeyString(key);
    if (this.cache.has(keyString)) {
      this.cache.delete(keyString);
    } else if (this.cache.size >= this.maxSize) {
      const oldestKey = this.cache.keys().next().value;
      this.cache.delete(oldestKey);
    }
    this.cache.set(keyString, value);
    this.keyMap.set(keyString, key);
  }

  clear() {
    this.cache.clear();
    this.keyMap.clear();
  }

  getKeyString(key) {
    return typeof key === 'object' ? 
      JSON.stringify(key) : 
      String(key);
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

async function isWhitelisted(url) {
  if (!url || typeof url !== 'string') {
    console.warn('isWhitelisted: Invalid or empty URL provided.');
    return false;
  }
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase(); 
    
    if (!hostname) {
        console.warn(`isWhitelisted: Extracted empty hostname from URL: ${url}`);
        return false;
    }

    const result = await chrome.storage.local.get('whitelist');
    const whitelist = result.whitelist || [];
    return whitelist.map(h => h.toLowerCase()).includes(hostname);
  } catch (error) {
    console.error(`Error checking whitelist for URL "${url}":`, error);
    return false; 
  }
}

async function notifyWhitelistChange() {
  try {
    const tabs = await chrome.tabs.query({});
    console.log(`Notifying ${tabs.length} tabs about whitelist changes`);
    
    for (const tab of tabs) {
      if (!tab.id || !tab.url) continue; // Skip tabs without id or url

      try {
        let tabHostname;
        try {
            const tabUrlObj = new URL(tab.url);
            tabHostname = tabUrlObj.hostname.toLowerCase();
        } catch (e) {
            console.debug(`Skipping tab with invalid URL for whitelist notification: ${tab.url}`, e);
            continue;
        }

        if (tab.url.startsWith('http')) {
          const isWhitelistedUrl = await isWhitelisted(tab.url);
          
          await chrome.tabs.sendMessage(tab.id, { 
            action: "setWhitelisted",
            value: isWhitelistedUrl
          }).catch(error => console.debug(`Tab not ready for "setWhitelisted" message: ${tab.id}, URL: ${tab.url}`, error));
          
          if (isWhitelistedUrl) {
            const currentWhitelistResult = await chrome.storage.local.get('whitelist');
            const currentWhitelist = (currentWhitelistResult.whitelist || []).map(h => h.toLowerCase());

            if (currentWhitelist.includes(tabHostname)) {
                setTimeout(() => {
                    chrome.tabs.reload(tab.id).catch(err => console.debug(`Error reloading tab ${tab.id}: ${err.message}`));
                }, 250);
            }
          }
        }
      } catch (error) {
        console.debug(`Error processing tab ${tab.id} for whitelist notification:`, error);
      }
    }
  } catch (error) {
    console.error('Error notifying tabs about whitelist changes:', error);
  }
}

chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId === 0 && details.url) { 
    const whitelisted = await isWhitelisted(details.url);
    console.log('Navigation detected, sending whitelist status:', details.url, whitelisted);
    if (whitelisted) {
      chrome.tabs.sendMessage(details.tabId, {
        action: "setWhitelisted",
        value: true
      }).catch(error => console.debug(`Tab not ready for "setWhitelisted" (onCommitted): ${details.tabId}, URL: ${details.url}`, error));
    }
  }
});

chrome.webNavigation.onCompleted.addListener(async (details) => {
  if (details.frameId === 0 && details.url) {
    const whitelisted = await isWhitelisted(details.url);
    console.log('Navigation completed, confirming whitelist status:', details.url, whitelisted);
    chrome.tabs.sendMessage(details.tabId, {
      action: "setWhitelisted",
      value: whitelisted
    }).catch(error => console.debug(`Tab not ready for "setWhitelisted" (onCompleted): ${details.tabId}, URL: ${details.url}`, error));
  }
});

chrome.webRequest.onBeforeRequest.addListener(
  async (details) => {
    if (await isWhitelisted(details.url)) {
      console.log('URL is whitelisted, allowing request:', details.url);
      return { cancel: false };
    }

    let isSuspiciousUrl = false;
    if (details.url && typeof details.url === 'string') {
        try {
            isSuspiciousUrl = checkSuspiciousURL(details.url); 
        } catch (e) {
            console.warn(`Error parsing URL in onBeforeRequest for checkSuspiciousURL: ${details.url}`, e);
            isSuspiciousUrl = false; 
        }
    }
    
    if (isSuspiciousUrl) {
      console.log('Suspicious URL detected, blocking request:', details.url);
      return { cancel: true };
    }

    return { cancel: false };
  },
  {urls: ["<all_urls>"]},
  ["blocking"]
);

chrome.webRequest.onHeadersReceived.addListener(
  async (details) => {
    if (await isWhitelisted(details.url)) {
      return { responseHeaders: details.responseHeaders };
    }

    const hasSuspiciousHeaders = checkSuspiciousHeaders(details.responseHeaders);
    if (hasSuspiciousHeaders) {
      if (details.tabId && details.tabId >= 0) { 
        chrome.tabs.sendMessage(details.tabId, {action: "suspiciousHeadersDetected"})
          .catch(error => console.debug(`Error sending "suspiciousHeadersDetected" message to tab ${details.tabId}:`, error));
      } else {
        console.warn("Cannot send suspiciousHeadersDetected message: Invalid tabId.", details);
      }
    }
    return {responseHeaders: details.responseHeaders};
  },
  {urls: ["<all_urls>"]},
  ["responseHeaders"]
);

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log('Received message:', request);
  switch (request.action) {
    case "logWarning":
      let logUrl = "Unknown URL";
      if (sender && sender.tab && sender.tab.url) {
        try {
          logUrl = sender.tab.url; 
        } catch (e) {
          console.warn("Error parsing sender.tab.url for logging:", e);
        }
      }
      debouncedLogBlockedContent(logUrl, request.patterns, Date.now());
      console.warn(request.message);
      break;
    case "analyzeURL":
      isWhitelisted(request.url).then(whitelisted => {
        if (whitelisted) {
          sendResponse({isSuspicious: false, whitelisted: true});
        } else {
          let analysisResult;
          try {
            const result = memoizedAnalyzeURL(request.url); 
            if (Date.now() - result.timestamp < config.cacheDurationMs) {
              analysisResult = {isSuspicious: result.isSuspicious, whitelisted: false};
            } else {
              const newResult = memoizedAnalyzeURL(request.url);
              analysisResult = {isSuspicious: newResult.isSuspicious, whitelisted: false};
            }
          } catch (e) {
            console.warn(`Error analyzing URL "${request.url}":`, e);
            analysisResult = {isSuspicious: false, whitelisted: false, error: "URL analysis failed"}; 
          }
          sendResponse(analysisResult);
        }
      }).catch(error => {
        console.error(`Error in analyzeURL handler for URL "${request.url}":`, error);
        sendResponse({isSuspicious: false, whitelisted: false, error: "Whitelist check failed"});
      });
      return true; 
    case "exportLogs":
      chrome.storage.local.get(['blockedLogs'], (result) => {
        if (chrome.runtime.lastError) {
            console.error("Error retrieving logs for export:", chrome.runtime.lastError);
            sendResponse({ logs: [], error: "Failed to retrieve logs" });
            return;
        }
        sendResponse({ logs: result.blockedLogs || [] });
      });
      return true; 
    case "updateConfig":
      if (request.newConfig && typeof request.newConfig === 'object') {
        updateConfig(request.newConfig);
        sendResponse({success: true});
      } else {
        console.warn("Invalid newConfig received:", request.newConfig);
        sendResponse({success: false, error: "Invalid configuration data"});
      }
      return true;
    case "whitelistUpdated":
      console.log('Whitelist updated message received, notifying tabs');
      notifyWhitelistChange(); 
      sendResponse({success: true});
      return true;
  }
  return false;
});

function logBlockedContent(url, patterns, timestamp) {

  const validatedUrl = (typeof url === 'string' && url.length > 0) ? url : "Invalid or Unspecified URL";
  const validatedPatterns = Array.isArray(patterns) ? patterns : ["Unknown Pattern"];

  chrome.storage.local.get(['blockedLogs'], function(result) {
    if (chrome.runtime.lastError) {
        console.error("Error retrieving logs for logging blocked content:", chrome.runtime.lastError);
        return;
    }
    let logs = result.blockedLogs || [];
    logs.push({ url: validatedUrl, patterns: validatedPatterns, timestamp });
    
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

const memoizedAnalyzeURL = memoize((url) => {
  const isSuspicious = checkSuspiciousURL(url);
  return {isSuspicious, timestamp: Date.now()};
}, (url) => url);

chrome.action.onClicked.addListener((tab) => {
  chrome.tabs.create({
    url: chrome.runtime.getURL('main.html'),
    active: true
  });
});
