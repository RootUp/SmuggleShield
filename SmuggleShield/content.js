class HTMLSmugglingBlocker {
  constructor() {
    this.blocked = false;    
    this.suspiciousPatterns = [
      { pattern: /atob\s*\([^)]+\).*new\s+uint8array/is, weight: 3 },
      { pattern: /atob\s*\(\s*['"]([A-Za-z0-9+/=]{100,})['"].*\)/i, weight: 3 },
      { pattern: /new\s+blob\s*\(\s*\[\s*(?:data|atob\s*\()/i, weight: 3 },
      { pattern: /let\s+arrayBuffer\s*=\s*\['0x[0-9a-f]{2}'(?:\s*,\s*'0x[0-9a-f]{2}')+\]/i, weight: 4 },
      { pattern: /\["edoCrahCmorf"(?:\s*\[\s*"split"\s*\]\s*\(\s*""\s*\)\s*\[\s*"reverse"\s*\]\s*\(\s*\)\s*\[\s*"join"\s*\]\s*\(\s*""\s*\))/i, weight: 4 },
      { pattern: /setTimeout\s*\(\s*\[.*?\]\.map\s*\(\s*.*?=>.*?(?:fromCharCode|edoCrahCmorf).*?\/\s*\d+\s*\)/is, weight: 4 },
      { pattern: /String\s*\[\s*(?:"edoCrahCmorf"|['"][^'"]+['"]\.split\(['"]['"]\)\.reverse\(\)\.join\(['"]['"]\))\s*\]/i, weight: 3 },
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
      { pattern: /\$wnd\s*=\s*window;\s*\$doc\s*=\s*\$wnd\.document/i, weight: 4 },
      { pattern: /__gwt_(?:isKnownPropertyValue|getMetaProperty|marker|stylesLoaded|scriptsLoaded)/i, weight: 4 },
      { pattern: /\$strongName\s*=\s*['"][0-9A-F]{32}['"]/i, weight: 3 },
      { pattern: /\$gwt_version\s*=\s*['"][0-9.]+['"]/i, weight: 3 },
      { pattern: /(?:function|var)\s+[a-zA-Z$_]+\s*=\s*\{\s*[a-zA-Z$_]+:\s*window,\s*[a-zA-Z$_]+:\s*document\s*\}/i, weight: 4 },
      { pattern: /\b(?:gwtOnLoad|__gwtStatsEvent|gwtOnLoadFunc)\b/i, weight: 3 },
      { pattern: /\.setAttribute\(['"]__gwt_property['"]/i, weight: 3 },
      { pattern: /document\.createElement\(['"]script['"]\).*?\.src\s*=.*?\.cache\.js/i, weight: 4 }
    ];
    this.threshold = 4;
    this.cache = new Map();
    this.metrics = {
      analysisTime: [],
      matchCount: 0,
      cacheHits: 0,
      cacheMisses: 0
    };

    this.suspiciousPatterns = this.suspiciousPatterns.map(({pattern, weight}) => ({
      pattern: new RegExp(pattern, 'is'),
      weight,
      category: this.categorizePattern(pattern)
    }));

    this.patternsByWeight = this.groupPatternsByWeight();
    this.setupListeners();
  }

  categorizePattern(pattern) {
    if (pattern.source.includes('blob') || pattern.source.includes('createobjecturl')) {
      return 'blob';
    } else if (pattern.source.includes('base64') || pattern.source.includes('atob')) {
      return 'encoding';
    }
    return 'other';
  }

  groupPatternsByWeight() {
    return this.suspiciousPatterns.reduce((acc, pattern) => {
      acc[pattern.weight] = acc[pattern.weight] || [];
      acc[pattern.weight].push(pattern);
      return acc;
    }, {});
  }

  getCacheKey(content) {
    let hash = 0;
    const len = Math.min(content.length, 500);
    for (let i = 0; i < len; i++) {
      hash = ((hash << 5) - hash) + content.charCodeAt(i);
      hash = hash & hash;
    }
    return `${hash}_${content.length}`;
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
    const observer = new MutationObserver((mutations) => {
      if (mutations.some(mutation => mutation.addedNodes.length > 0)) {
        this.analyzeContent();
      }
    });

    observer.observe(document.documentElement, {
      childList: true,
      subtree: true
    });
  }

  analyzeContent() {
    const startTime = performance.now();
    const htmlContent = document.documentElement.outerHTML;
    const cacheKey = this.getCacheKey(htmlContent);
    
    const cachedResult = this.cache.get(cacheKey);
    if (cachedResult) {
      this.metrics.cacheHits++;
      if (cachedResult.score >= this.threshold) {
        this.handleSuspiciousContent(cachedResult.detectedPatterns);
      }
      return;
    }
    
    this.metrics.cacheMisses++;
    let score = 0;
    const detectedPatterns = [];

    const weights = Object.keys(this.patternsByWeight).sort((a, b) => b - a);
    
    let shouldTerminate = false;

    for (const weight of weights) {
      if (shouldTerminate || score >= this.threshold) {
        break;
      }

      const patterns = this.patternsByWeight[weight];
      for (const {pattern, weight: patternWeight} of patterns) {
        if (pattern.test(htmlContent)) {
          score += patternWeight;
          detectedPatterns.push(pattern.toString());
          this.metrics.matchCount++;
          
          if (score >= this.threshold) {
            shouldTerminate = true;
            break;
          }
        }
      }
    }

    this.cache.set(cacheKey, { score, detectedPatterns });
    
    if (this.cache.size > 1000) {
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }

    const analysisTime = performance.now() - startTime;
    this.metrics.analysisTime.push(analysisTime);

    if (score >= this.threshold) {
      this.handleSuspiciousContent(detectedPatterns);
      console.debug(`Content blocked after checking ${this.metrics.matchCount} patterns. Analysis time: ${analysisTime.toFixed(2)}ms`);
    } else {
      this.blocked = false;
      this.allowContent();
    }

    if (this.metrics.analysisTime.length % 100 === 0) {
      this.logPerformanceMetrics();
    }
  }

  handleSuspiciousContent(detectedPatterns) {
    this.blocked = true;
    const elementsRemoved = this.removeSuspiciousElements();
    const scriptsDisabled = this.disableInlineScripts();
    const svgScriptsNeutralized = this.neutralizeSVGScripts();
    const embedElementsRemoved = this.removeEmbedElements();

    if (elementsRemoved > 0 || scriptsDisabled > 0 || 
        svgScriptsNeutralized > 0 || embedElementsRemoved > 0) {
      this.logWarning(
        elementsRemoved, 
        scriptsDisabled, 
        svgScriptsNeutralized, 
        embedElementsRemoved, 
        detectedPatterns
      );
    }
  }

  logPerformanceMetrics() {
    const avgAnalysisTime = this.metrics.analysisTime.reduce((a, b) => a + b, 0) / 
                           this.metrics.analysisTime.length;
    console.debug('Performance Metrics:', {
      averageAnalysisTime: `${avgAnalysisTime.toFixed(2)}ms`,
      cacheHitRate: `${(this.metrics.cacheHits / 
                       (this.metrics.cacheHits + this.metrics.cacheMisses) * 100).toFixed(2)}%`,
      totalMatches: this.metrics.matchCount,
      patternsChecked: this.metrics.matchCount,
      earlyTerminations: this.metrics.earlyTerminations || 0
    });
  }

  removeSuspiciousElements() {
    const suspiciousElements = document.querySelectorAll(
      'a[download][href^="data:"], a[download][href^="blob:"]'
    );
    console.log(`HTML Smuggling Blocker: Removed ${suspiciousElements.length} suspicious elements`);
    return this.removeElements(suspiciousElements);
  }

  disableInlineScripts() {
    const inlineScripts = document.querySelectorAll('script:not([src])');
    console.log(`HTML Smuggling Blocker: Analyzing ${inlineScripts.length} inline scripts`);
    return this.removeElements(inlineScripts, (script) => this.isSuspiciousScript(script.textContent));
  }

  isSuspiciousScript(scriptContent) {
    return this.suspiciousPatterns.some(({pattern}) => pattern.test(scriptContent));
  }

  neutralizeSVGScripts() {
    const svgScripts = document.querySelectorAll('svg script');
    console.log(`HTML Smuggling Blocker: Neutralized ${svgScripts.length} SVG scripts`);
    return this.removeElements(svgScripts);
  }

  removeEmbedElements() {
    const embedElements = document.querySelectorAll('embed');
    console.log(`HTML Smuggling Blocker: Removed ${embedElements.length} embed elements`);
    return this.removeElements(embedElements);
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

  removeElements(elements, condition = () => true) {
    let count = 0;
    elements.forEach(el => {
      if (condition(el)) {
        this.removeElement(el);
        count++;
      }
    });
    return count;
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
    this.analyzeContent();
  }

  debugPatternMatch(pattern, content, weight) {
    if (this.debugMode) {
      console.debug(`Pattern match [weight: ${weight}]:`, {
        pattern: pattern.toString(),
        contentPreview: content.substring(0, 100) + '...',
        timestamp: new Date().toISOString()
      });
    }
  }
}

new HTMLSmugglingBlocker();
