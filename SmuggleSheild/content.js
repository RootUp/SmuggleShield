class HTMLSmugglingBlocker {
  constructor() {
    this.blocked = false;
    this.suspiciousPatterns = [
      { pattern: /[aA][tT][oO][bB]\s*\([^)]+\).*new\s+[uU]int8[aA]rray/is, weight: 3 },
      { pattern: /[bB]lob\s*\(\s*\[[^\]]+\]\s*,\s*\{\s*type\s*:\s*['"]application\/octet-stream['"]\s*\}\s*\)/is, weight: 3 },
      { pattern: /[uU][rR][lL]\.create[oO]bject[uU][rR][lL]\s*\(\s*[^)]+\)/is, weight: 2 },
      { pattern: /\.style\s*=\s*['"]display:\s*none['"].*\.href\s*=.*\.download\s*=/is, weight: 3 },
      { pattern: /\.click\s*\(\s*\).*[uU][rR][lL]\.revoke[oO]bject[uU][rR][lL]/is, weight: 3 },
      { pattern: /href\s*=\s*["']data:application\/octet-stream;base64,/i, weight: 3 },
      { pattern: /[wW]eb[aA]ssembly\.[iI]nstantiate/i, weight: 2 },
      { pattern: /navigator\.[sS]ervice[wW]orker\.register/i, weight: 2 },
      { pattern: /srcdoc\s*=\s*["'][^"']*<script/i, weight: 3 },
      { pattern: /function\s+(?:[bB]64[tT]o[aA]rray|[xX][oO][rR])\s*\([^)]*\)\s*{[\s\S]*?return\s+(?:bytes\.buffer|result);?}/i, weight: 3 },
      { pattern: /document\.create[eE]lement\(['"']embed['"']\)/i, weight: 3 },
      { pattern: /\.set[aA]ttribute\(['"']src['"']\s*,\s*.*\)/i, weight: 2 },
      { pattern: /[sS]tring\.from[cC]har[cC]ode\(.*\)/i, weight: 2 },
      { pattern: /\.char[cC]ode[aA]t\(.*\)/i, weight: 2 },
      { pattern: /document\.get[eE]lement[bB]y[iI]d\(['"']passwordid['"']\)\.value/i, weight: 3 },
      { pattern: /[aA][tT][oO][bB]\s*\(\s*['"]([A-Za-z0-9+/=]{100,})['"].*\)/i, weight: 3 },
      { pattern: /new\s+[bB]lob\s*\(\s*\[\s*[aA][tT][oO][bB]\s*\(/i, weight: 3 },
      { pattern: /import\s*\(\s*[uU][rR][lL]\.create[oO]bject[uU][rR][lL]\s*\(/i, weight: 3 },
      { pattern: /[wW]eb[aA]ssembly\.[iI]nstance/i, weight: 2 },
      { pattern: /\w+\s*\(\s*\w+\s*\(\s*['"][A-Za-z0-9+/=]{50,}['"]\s*\)\s*\)/i, weight: 3 },
      { pattern: /[uU][rR][lL]\.create[oO]bject[uU][rR][lL]\s*\(\s*new\s+[bB]lob/i, weight: 3 },
      { pattern: /\.download\s*=\s*['"][^'"]+['"]/i, weight: 2 },
      { pattern: /window\.[aA][tT][oO][bB]\s*\(/i, weight: 2 },
      { pattern: /[uU]int8[aA]rray\s*\(\s*[^)]+\)/i, weight: 2 },
      { pattern: /ms[sS]ave[oO]r[oO]pen[bB]lob|ms[sS]ave[bB]lob/i, weight: 3 },
      { pattern: /\.click\(\s*\)\s*;\s*window\.[uU][rR][lL]\.revoke[oO]bject[uU][rR][lL]/i, weight: 3 },
      { pattern: /base64[tT]o[aA]rray[bB]uffer/i, weight: 3 },
      { pattern: /new\s+[uU]int8[aA]rray\s*\(\s*len\s*\)/i, weight: 3 },
      { pattern: /window\.[uU][rR][lL]\.create[oO]bject[uU][rR][lL]\s*\(\s*blob\s*\)/i, weight: 3 },
      { pattern: /a\.download\s*=\s*file[nN]ame/i, weight: 3 },
      { pattern: /window\.[uU][rR][lL]\.revoke[oO]bject[uU][rR][lL]\s*\(\s*url\s*\)/i, weight: 3 },
      { pattern: /[dD][aA][tT][aA]\s*:\s*[aA][pP][pP][lL][iI][cC][aA][tT][iI][oO][nN]\/[oO][cC][tT][eE][tT]-[sS][tT][rR][eE][aA][mM]\s*;\s*[bB][aA][sS][eE]64\s*,/i, weight: 3 },
      { pattern: /wasm[_-]?exec\.js/i, weight: 2 },
      { pattern: /\.wasm/i, weight: 3 },
      { pattern: /[wW]eb[aA]ssembly\s*\.\s*(instantiate(?:[sS]treaming)?|[iI]nstance)/i, weight: 3 },
      { pattern: /new\s+[gG]o\s*\(\s*\)/i, weight: 3 },
      { pattern: /go\s*\.\s*run\s*\(/i, weight: 3 },
      { pattern: /<embed[^>]*base64/i, weight: 3 },
      { pattern: /[dD][aA][tT][aA]\s*:\s*[iI][mM][aA][gG][eE]\/[sS][vV][gG]\+[xX][mM][lL]\s*;\s*[bB][aA][sS][eE]64\s*,/i, weight: 3 },
      { pattern: /xmlhttprequest\(\).*\.responsetype\s*=\s*['"]arraybuffer['"]/i, weight: 3 },
      { pattern: /new\s+dataview\(.*\).*\.getuint8\(.*\).*\.setuint8\(/i, weight: 3 },
      { pattern: /[^\w](\w+)\s*=\s*(\w+)\s*\^\s*(\w+)/i, weight: 2 },
      { pattern: /window\.url\.createobjecturl\(.*\).*window\.url\.revokeobjecturl\(/i, weight: 3 },
      { pattern: /\.slice\(\s*\w+\s*-\s*\d+\s*,\s*\w+\s*-\s*\d+\s*\)/i, weight: 2 },
      { pattern: /for\s*\([^)]+\)\s*\{[^}]*string\.fromcharcode\([^)]+\)/i, weight: 3 },
      { pattern: /new\s+blob\(\s*\[[^\]]+\]\s*,\s*\{\s*type\s*:\s*['"]application\/octet-stream['"]\s*\}\s*\)/i, weight: 3 },
    ];
    this.threshold = 4;
    this.setupListeners();
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

    this.suspiciousPatterns.forEach(({pattern, weight}) => {
      if (pattern.test(htmlContent)) {
        score += weight;
        detectedPatterns.push(pattern.toString());
      }
    });

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
    this.showBlockedMessage();
  }
}

new HTMLSmugglingBlocker();
