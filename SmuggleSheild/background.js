chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log('Received message:', request);
  if (request.action === "logWarning") {
    logBlockedContent(sender.tab.url, request.patterns, Date.now());
    console.warn(request.message);
  } else if (request.action === "analyzeURL") {
    const suspiciousURLPatterns = [
      /data:application\/octet-stream/i,
      /blob:/i,
      /javascript:/i
    ];

    const isSuspicious = suspiciousURLPatterns.some(pattern => pattern.test(request.url));
    sendResponse({isSuspicious: isSuspicious});
    return true;
  } else if (request.action === "exportLogs") {
    chrome.storage.local.get(['blockedLogs'], function(result) {
      sendResponse({ logs: result.blockedLogs || [] });
    });
    return true; 
  }
});

function logBlockedContent(url, patterns, timestamp) {
  chrome.storage.local.get(['blockedLogs'], function(result) {
    let logs = result.blockedLogs || [];
    logs.push({ url, patterns, timestamp });
    const tenDaysAgo = Date.now() - (10 * 24 * 60 * 60 * 1000);
    logs = logs.filter(log => log.timestamp > tenDaysAgo);
    
    chrome.storage.local.set({ blockedLogs: logs });
  });
}
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    const suspiciousHeaders = [
      'Content-Disposition',
      'Content-Type'
    ];

    const hasSuspiciousHeaders = details.responseHeaders.some(header => 
      suspiciousHeaders.includes(header.name.toLowerCase()) &&
      /attachment|application\/octet-stream/i.test(header.value)
    );

    if (hasSuspiciousHeaders) {
      chrome.tabs.sendMessage(details.tabId, {action: "suspiciousHeadersDetected"});
    }

    return {responseHeaders: details.responseHeaders};
  },
  {urls: ["<all_urls>"]},
  ["responseHeaders"]
);
