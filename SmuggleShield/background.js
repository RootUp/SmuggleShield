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

const urlCache = new Map();

function memoize(fn, resolver) {
  const cache = new Map();
  return (...args) => {
    const key = resolver ? resolver(...args) : args[0];
    if (cache.has(key)) return cache.get(key);
    const result = fn(...args);
    cache.set(key, result);
    if (cache.size > 1000) {
      const oldestKey = cache.keys().next().value;
      cache.delete(oldestKey);
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
      const cachedResult = urlCache.get(request.url);
      if (cachedResult && (Date.now() - cachedResult.timestamp < config.cacheDurationMs)) {
        sendResponse({isSuspicious: cachedResult.isSuspicious});
      } else {
        const isSuspicious = checkSuspiciousURL(request.url);
        urlCache.set(request.url, {isSuspicious, timestamp: Date.now()});
        sendResponse({isSuspicious});
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

setInterval(() => {
  const now = Date.now();
  for (const [url, data] of urlCache) {
    if (now - data.timestamp > config.cacheDurationMs) {
      urlCache.delete(url);
    }
  }
}, config.cacheDurationMs);
