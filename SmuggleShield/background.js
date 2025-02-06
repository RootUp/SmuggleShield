const config = {
  suspiciousURLPatterns: [
    /data:application\/octet-stream/i,
    /blob:/i,
    /javascript:/i,
    /data:application\/x-rar-compressed/i
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
  try {
    const hostname = new URL(url).hostname;
    const result = await chrome.storage.local.get('whitelist');
    const whitelist = result.whitelist || [];
    console.log('Background checking whitelist for:', hostname, 'Whitelist:', whitelist);
    return whitelist.includes(hostname);
  } catch (error) {
    console.error('Error checking whitelist:', error);
    return false;
  }
}

chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId === 0) { // Main frame only
    const isWhitelistedUrl = await isWhitelisted(details.url);
    if (isWhitelistedUrl) {
      chrome.tabs.sendMessage(details.tabId, {
        action: "setWhitelisted",
        value: true
      }).catch(error => console.debug('Tab not ready yet:', error));
    }
  }
});

chrome.webRequest.onBeforeRequest.addListener(
  async (details) => {
    if (await isWhitelisted(details.url)) {
      console.log('URL is whitelisted, allowing request:', details.url);
      return { cancel: false };
    }

    const isSuspiciousUrl = checkSuspiciousURL(details.url);
    
    if (isSuspiciousUrl) {
      console.log('Suspicious URL detected:', details.url);
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
      chrome.tabs.sendMessage(details.tabId, {action: "suspiciousHeadersDetected"})
        .catch(error => console.error('Error sending message:', error));
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
      debouncedLogBlockedContent(sender.tab.url, request.patterns, Date.now());
      console.warn(request.message);
      break;
    case "analyzeURL":
      isWhitelisted(request.url).then(whitelisted => {
        if (whitelisted) {
          sendResponse({isSuspicious: false, whitelisted: true});
        } else {
          const result = memoizedAnalyzeURL(request.url);
          if (Date.now() - result.timestamp < config.cacheDurationMs) {
            sendResponse({isSuspicious: result.isSuspicious, whitelisted: false});
          } else {
            const newResult = memoizedAnalyzeURL(request.url);
            sendResponse({isSuspicious: newResult.isSuspicious, whitelisted: false});
          }
        }
      });
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

const memoizedAnalyzeURL = memoize((url) => {
  const isSuspicious = checkSuspiciousURL(url);
  return {isSuspicious, timestamp: Date.now()};
}, (url) => url);

class ContentAnalyzer {
  constructor(config) {
    this.config = config;
    this.analysisQueue = new Set();
    this.isProcessing = false;
    this.lastAnalysis = 0;
    this.minAnalysisInterval = 300; 
  }

  queueForAnalysis(element) {
    this.analysisQueue.add(element);
    this.scheduleProcessing();
  }

  scheduleProcessing() {
    if (this.isProcessing) return;

    const timeSinceLastAnalysis = Date.now() - this.lastAnalysis;
    const delay = Math.max(0, this.minAnalysisInterval - timeSinceLastAnalysis);

    setTimeout(() => this.processQueue(), delay);
  }

  async processQueue() {
    if (this.isProcessing || this.analysisQueue.size === 0) return;

    this.isProcessing = true;
    this.lastAnalysis = Date.now();

    try {
      const elements = Array.from(this.analysisQueue);
      this.analysisQueue.clear();

      for (const element of elements) {
        if (element.isConnected) {
          await this.analyzeElement(element);
        }
      }
    } catch (error) {
      console.error('Analysis error:', error);
    } finally {
      this.isProcessing = false;
      
      if (this.analysisQueue.size > 0) {
        this.scheduleProcessing();
      }
    }
  }

  async analyzeElement(element) {
    if (element.textContent.length < 50) return;

    const htmlContent = element.outerHTML;
    const cacheKey = this.getCacheKey(htmlContent);
    
    const cachedResult = urlCache.get(cacheKey);
    if (cachedResult) {
      if (cachedResult.isSuspicious) {
        this.handleSuspiciousContent(element, cachedResult.patterns);
      }
      return;
    }

    const result = await this.analyzeContent(htmlContent);
    urlCache.set(cacheKey, result);

    if (result.isSuspicious) {
      this.handleSuspiciousContent(element, result.patterns);
    }
  }

  getCacheKey(content) {
    let hash = 0;
    for (let i = 0; i < content.length; i++) {
      hash = ((hash << 5) - hash) + content.charCodeAt(i);
      hash = hash & hash;
    }
    return `${hash}_${content.length}`;
  }

  async analyzeContent(content) {
    const patterns = [];
    let score = 0;

    for (const pattern of this.config.suspiciousPatterns) {
      if (pattern.test(content)) {
        patterns.push(pattern.source);
        score += pattern.weight || 1;

        if (score >= this.config.blockThreshold) {
          break;
        }
      }
    }

    return {
      isSuspicious: score >= this.config.blockThreshold,
      patterns,
      timestamp: Date.now()
    };
  }

  handleSuspiciousContent(element, patterns) {
    chrome.runtime.sendMessage({
      action: "logWarning",
      message: `Suspicious content detected`,
      patterns: patterns,
      url: window.location.href
    });

    if (element.parentNode) {
      element.parentNode.removeChild(element);
    }
  }
}

const contentAnalyzer = new ContentAnalyzer(config);

function setupObserver() {
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      mutation.addedNodes.forEach(node => {
        if (node instanceof HTMLElement) {
          contentAnalyzer.queueForAnalysis(node);
        }
      });

      if (mutation.type === 'attributes' && mutation.target instanceof HTMLElement) {
        contentAnalyzer.queueForAnalysis(mutation.target);
      }
    }
  });

  observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['src', 'href', 'data']
  });

  contentAnalyzer.queueForAnalysis(document.documentElement);
}

chrome.action.onClicked.addListener((tab) => {
  chrome.tabs.create({
    url: chrome.runtime.getURL('main.html'),
    active: true
  });
});


chrome.runtime.onMessage.addListener(async (request, sender, sendResponse) => {
  if (request.action === "whitelistUpdated") {
    const result = await chrome.storage.local.get('whitelist');
    const whitelist = result.whitelist || [];
    console.log('Whitelist updated:', whitelist);
    return true;
  }
});
