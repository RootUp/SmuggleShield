class HTMLSmugglingBlocker {
  constructor() {
    this.blocked = false;    
    this.suspiciousPatterns = [
      { pattern: /atob\s*\([^)]+\).*new\s+uint8array/is, weight: 3 },
      { pattern: /atob\s*\(\s*['"]([A-Za-z0-9+/=]{100,})['"].*\)/i, weight: 3 },
      { pattern: /new\s+blob\s*\(\s*\[\s*(?:data|atob\s*\()/i, weight: 3 },
      { pattern: /url\.createobjecturl\s*\(\s*(?:my)?blob\s*\)/i, weight: 3 },
      { pattern: /location(?:\s*\[\s*["']href["']\s*\])?\s*=\s*url/i, weight: 3 },
      { pattern: /url\.revokeobjecturl\s*\(\s*url\s*\)/i, weight: 2 },
      { pattern: /window\s*\[\s*(?:["']\w+["']\s*\+\s*)+["']\w+["']\s*\]/i, weight: 3 },
      { pattern: /document\s*\[\s*(?:["']\w+["']\s*\+\s*)+["']\w+["']\s*\]\s*\(\s*window\s*\[\s*(?:['"]at['"].*['"]o['"].*['"]b['"]\s*\]|\s*(?:["']\w+["']\s*\+\s*)+["']\w+["']\s*\])\s*\(['"][A-Za-z0-9+/=]+['"]\)\s*\)/i, weight: 4 },
      { pattern: /var\s+\w+=\w+;?\s*\(function\(\w+,\w+\)\{.*while\(!!\[\]\)\{try\{.*parseint.*\}catch\(\w+\)\{.*\}\}\}\(.*\)\);?/is, weight: 4 },
      { pattern: /blob\s*\(\s*\[[^\]]+\]\s*,\s*\{\s*type\s*:\s*['"](?:application\/octet-stream|text\/html|octet\/stream)['"](?:\s*,\s*encoding\s*:\s*['"]base64['"])?\s*\}\s*\)/is, weight: 3 },
      { pattern: /\.style\s*=\s*['"]display:\s*none['"].*\.href\s*=.*\.download\s*=/is, weight: 3 },
      { pattern: /\.click\s*\(\s*\).*url\.revokeobjecturl/is, weight: 3 },
      { pattern: /href\s*=\s*["']data:(?:application\/octet-stream|image\/svg\+xml);base64,/i, weight: 3 },
      { pattern: /webassembly\s*\.\s*(?:instantiate(?:streaming)?|instance)/i, weight: 3 },
      { pattern: /navigator\.serviceworker\.register/i, weight: 2 },
      { pattern: /srcdoc\s*=\s*["'][^"']*<script/i, weight: 3 },
      { pattern: /function\s+(?:b64toarray|xor|base64toarraybuffer)\s*\([^)]*\)\s*{[\s\S]*?return\s+(?:bytes\.buffer|result);?}/i, weight: 3 },
      { pattern: /document\.createelement\(['"']embed['"']\)/i, weight: 3 },
      { pattern: /\.setattribute\(['"']src['"']\s*,\s*.*\)/i, weight: 2 },
      { pattern: /window\.navigator\.mssaveoropenblob\s*\(\s*blob\s*,\s*filename\s*\)/i, weight: 3 },
      { pattern: /(?:window\.)?url\.createobjecturl\s*\(\s*(?:blob|[^)]+)\s*\)/i, weight: 2 },
      { pattern: /(?:a|element)\.download\s*=\s*(?:filename|['"][^'"]+['"])/i, weight: 2 },
      { pattern: /string\.fromcharcode\(.*\)/i, weight: 2 },
      { pattern: /\.charcodeat\(.*\)/i, weight: 2 },
      { pattern: /document\.getelementbyid\(['"']passwordid['"']\)\.value/i, weight: 3 },
      { pattern: /import\s*\(\s*url\.createobjecturl\s*\(/i, weight: 3 },
      { pattern: /\w+\s*\(\s*\w+\s*\(\s*['"][A-Za-z0-9+/=]{50,}['"]\s*\)\s*\)/i, weight: 3 },
      { pattern: /(?:window\.)?atob\s*\(/i, weight: 2 },
      { pattern: /uint8[aA]rray\s*\(\s*(?:(?!len)[^)])*\)/i, weight: 2 },
      { pattern: /mssaveoropenblob|mssaveblob/i, weight: 3 },
      { pattern: /base64toarraybuffer/i, weight: 3 },
      { pattern: /wasm[_-]?exec\.js/i, weight: 2 },
      { pattern: /\.wasm/i, weight: 3 },
      { pattern: /new\s+go\s*\(\s*\)/i, weight: 3 },
      { pattern: /go\s*\.\s*run\s*\(/i, weight: 3 },
      { pattern: /<embed[^>]*base64/i, weight: 3 },
      { pattern: /xmlhttprequest\(\).*\.responsetype\s*=\s*['"]arraybuffer['"]/i, weight: 3 },
      { pattern: /new\s+dataview\(.*\).*\.getuint8\(.*\).*\.setuint8\(/i, weight: 3 },
      { pattern: /[^\w](\w+)\s*=\s*(\w+)\s*\^\s*(\w+)/i, weight: 2 },
      { pattern: /\.slice\(\s*\w+\s*-\s*\d+\s*,\s*\w+\s*-\s*\d+\s*\)/i, weight: 2 },
      { pattern: /for\s*\([^)]+\)\s*\{[^}]*string\.fromcharcode\([^)]+\)/i, weight: 3 },
    ];
    this.threshold = 4;
    this.setupListeners();

    this.suspiciousPatterns = this.suspiciousPatterns.map(({pattern, weight}) => ({
      pattern: new RegExp(pattern, 'is'),
      weight
    }));
  }

  setupListeners() {
    this.analyzeContent();

    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
      if (request.action === "analyzeContent") {
        this.analyzeContent();
      } else if (request.action === "getBlockedStatus") {
        sendResponse({blocked: this.blocked});
      } else if (request.action === "suspiciousHeadersDetected") {
        this.handleSuspiciousHeaders();
      }
    });

    this.setupObserver();
  }

  setupObserver() {
    const observer = new MutationObserver(() => {
      this.analyzeContent();
    });

    observer.observe(document.documentElement, {
      childList: true,
      subtree: true
    });
  }

  analyzeContent() {
    console.log("HTML Smuggling Blocker: Analyzing content");
    const htmlContent = document.documentElement.outerHTML;
    
    let score = 0;
    const detectedPatterns = [];

    for (const {pattern, weight} of this.suspiciousPatterns) {
      if (pattern.test(htmlContent)) {
        score += weight;
        detectedPatterns.push(pattern.toString());
        if (score >= this.threshold) break; // Early exit if threshold is reached
      }
    }

    if (score >= this.threshold) {
      console.log("HTML Smuggling Blocker: Suspicious content detected");
      this.blocked = true;
      
      const elementsRemoved = this.removeSuspiciousElements();
      const scriptsDisabled = this.disableInlineScripts();
      const svgScriptsNeutralized = this.neutralizeSVGScripts();
      const embedElementsRemoved = this.removeEmbedElements();

      if (elementsRemoved > 0 || scriptsDisabled > 0 || svgScriptsNeutralized > 0 || embedElementsRemoved > 0) {
        this.logWarning(elementsRemoved, scriptsDisabled, svgScriptsNeutralized, embedElementsRemoved, detectedPatterns);
      }
    } else {
      console.log("HTML Smuggling Blocker: No suspicious content detected");
      this.blocked = false;
      this.allowContent();
    }
  }

  removeSuspiciousElements() {
    const suspiciousElements = document.querySelectorAll(
      'a[download][href^="data:"], a[download][href^="blob:"]'
    );
    console.log(`HTML Smuggling Blocker: Removed ${suspiciousElements.length} suspicious elements`);
    suspiciousElements.forEach(el => this.removeElement(el));
    return suspiciousElements.length;
  }

  disableInlineScripts() {
    const inlineScripts = document.querySelectorAll('script:not([src])');
    console.log(`HTML Smuggling Blocker: Analyzing ${inlineScripts.length} inline scripts`);
    let disabledCount = 0;
    inlineScripts.forEach(script => {
      if (this.isSuspiciousScript(script.textContent)) {
        this.removeElement(script);
        disabledCount++;
      }
    });
    return disabledCount;
  }

  isSuspiciousScript(scriptContent) {
    return this.suspiciousPatterns.some(({pattern}) => pattern.test(scriptContent));
  }

  neutralizeSVGScripts() {
    const svgScripts = document.querySelectorAll('svg script');
    console.log(`HTML Smuggling Blocker: Neutralized ${svgScripts.length} SVG scripts`);
    svgScripts.forEach(el => this.removeElement(el));
    return svgScripts.length;
  }

  removeEmbedElements() {
    const embedElements = document.querySelectorAll('embed');
    console.log(`HTML Smuggling Blocker: Removed ${embedElements.length} embed elements`);
    embedElements.forEach(el => this.removeElement(el));
    return embedElements.length;
  }

  logWarning(elementsRemoved, scriptsDisabled, svgScriptsNeutralized, embedElementsRemoved, detectedPatterns) {
    const message = `HTML Smuggling attempt blocked: ${elementsRemoved} elements removed, ${scriptsDisabled} scripts disabled, ${svgScriptsNeutralized} SVG scripts neutralized, ${embedElementsRemoved} embed elements removed. Detected patterns: ${detectedPatterns.join(', ')}`;
    console.warn(message);
    chrome.runtime.sendMessage({
      action: "logWarning", 
      message: message,
      patterns: detectedPatterns
    });
  }

  removeElement(element) {
    if (element && element.parentNode) {
      element.parentNode.removeChild(element);
    }
  }

  allowContent() {
    document.documentElement.style.display = '';
    console.log("HTML Smuggling Blocker: Content allowed");
  }

  handleSuspiciousHeaders() {
    console.log("Suspicious headers detected");
  }
}

new HTMLSmugglingBlocker();
