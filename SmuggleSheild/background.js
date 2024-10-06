# sample text
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
        const isSuspicious = config.suspiciousURLPatterns.some(pattern => pattern.test(request.url));
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
  chrome.storage.local.get(['blockedLogs', 'otherData'], function(result) {
    let logs = result.blockedLogs || [];
    logs.push({ url, patterns, timestamp });
    const retentionDate = Date.now() - (config.logRetentionDays * 24 * 60 * 60 * 1000);
    logs = logs.filter(log => log.timestamp > retentionDate);
    
    chrome.storage.local.set({ 
      blockedLogs: logs,
      otherData: result.otherData // Preserve other data
    }, () => {
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

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    const hasSuspiciousHeaders = details.responseHeaders.some(header => 
      config.suspiciousHeaders.includes(header.name.toLowerCase()) &&
      /attachment|application\/octet-stream/i.test(header.value)
    );

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
  for (const [url, data] of urlCache.entries()) {
    if (now - data.timestamp > config.cacheDurationMs) {
      urlCache.delete(url);
    }
  }
}, config.cacheDurationMs);
