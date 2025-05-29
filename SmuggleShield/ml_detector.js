class MLDetector {
  constructor() {
    this.monitor = new MLMonitor();
    this.features = {
      patterns: new Map(),
      contextual: new Map(),
      weights: new Map()
    };
    
    this.threshold = 0.75;
    this.learningRate = 0.1;
    this.minSamples = 5;
    
    this.loadModel();
    
    this.lastDetectionTime = 0;
    this.detectionThrottleMs = 1000; 
    
    this.featureCache = new Map();
    this.maxCacheSize = 1000;
    
    this.lastModelSave = Date.now();
    this.saveThrottleMs = 30000; // 30 seconds
    this.pendingSave = false;
    this.learningCount = 0;
  }

  async loadModel() {
    try {
      const data = await new Promise(resolve => {
        chrome.storage.local.get(['mlModel'], result => resolve(result.mlModel));
      });
      
      if (data?.mlModel) {
        this.features = this.deserializeModel(data.mlModel);
      }
    } catch (error) {
      console.error('Error loading ML model:', error);
    }
  }

  async saveModel() {
    try {
      const now = Date.now();
      if (now - this.lastModelSave < this.saveThrottleMs) {
        // If we're saving too frequently, schedule a save for later
        if (!this.pendingSave) {
          this.pendingSave = true;
          setTimeout(() => {
            this.actualSaveModel();
            this.pendingSave = false;
          }, this.saveThrottleMs - (now - this.lastModelSave));
        }
        return;
      }
      
      await this.actualSaveModel();
    } catch (error) {
      console.error('Error saving ML model:', error);
    }
  }
  
  async actualSaveModel() {
    try {
      await chrome.storage.local.set({
        mlModel: this.serializeModel()
      });
      this.lastModelSave = Date.now();
      this.learningCount = 0;
    } catch (error) {
      console.error('Error in actualSaveModel:', error);
    }
  }

  serializeModel() {
    return {
      patterns: Array.from(this.features.patterns.entries()),
      contextual: Array.from(this.features.contextual.entries()),
      weights: Array.from(this.features.weights.entries())
    };
  }

  deserializeModel(data) {
    return {
      patterns: new Map(data.patterns),
      contextual: new Map(data.contextual),
      weights: new Map(data.weights)
    };
  }

  extractFeatures(content) {
    const cacheKey = this.hashContent(content);
    if (this.featureCache.has(cacheKey)) {
      return this.featureCache.get(cacheKey);
    }

    const features = new Map();
    
    // 1. Large String Handling: Keep existing limitedContent strategy.
    // It's a balance between processing scope and performance for very large inputs.
    const limitedContent = content.length > 50000 ? 
      content.substring(0, 25000) + content.substring(content.length - 25000) : 
      content;
    const limitedContentLength = limitedContent.length; // For density calculations

    const patternCounts = {
      base64Blocks: 0,
      totalBase64Chars: 0,
      blob: 0,
      download: 0,
      scriptTags: 0, 
      encodingCalls: 0,
      binaryConstructs: 0,
      jsKeywords: 0,
      sensitiveKeywords: 0,
      suspiciousAssignments: 0,
      atobCalls: 0,
      dynamicAtobArgs: 0,
      nonAsciiChars: 0,
      whitespaceChars: 0,
      lineCount: 1, // Start with 1 to avoid division by zero for single-line content
      maxDepth: 0,
    };
    
    // Iterate once for character-level metrics
    let currentDepth = 0;
    for (let i = 0; i < limitedContentLength; i++) {
        const char = limitedContent[i];
        if (char === '{' || char === '(' || char === '[') {
            currentDepth++;
            if (currentDepth > patternCounts.maxDepth) {
                patternCounts.maxDepth = currentDepth;
            }
        } else if (char === '}' || char === ')' || char === ']') {
            currentDepth--;
        }
        if (char === '\n') {
            patternCounts.lineCount++;
        }
        if (char.charCodeAt(0) > 127) {
            patternCounts.nonAsciiChars++;
        }
        if (/\s/.test(char)) {
            patternCounts.whitespaceChars++;
        }
    }
    
    // 2. Regex & Feature Engineering: base64
    const base64Matches = limitedContent.match(/[A-Za-z0-9+/=]{100,}/g) || [];
    patternCounts.base64Blocks = base64Matches.length;
    for (const match of base64Matches) {
      patternCounts.totalBase64Chars += match.length;
    }
    
    features.set('base64BlockCount', patternCounts.base64Blocks);
    features.set('totalBase64Chars', patternCounts.totalBase64Chars);
    if (limitedContentLength > 0) {
      features.set('base64ContentRatio', patternCounts.totalBase64Chars / limitedContentLength);
      features.set('avgBase64BlockLength', patternCounts.base64Blocks > 0 ? patternCounts.totalBase64Chars / patternCounts.base64Blocks : 0);
    } else {
      features.set('base64ContentRatio', 0);
      features.set('avgBase64BlockLength', 0);
    }

    // 3. Regex & Feature Engineering: Other patterns
    patternCounts.blob = (limitedContent.match(/new\s+blob/gi) || []).length;
    patternCounts.download = (limitedContent.match(/download\s*=\s*["'][^"']*["']/gi) || []).length;
    
    // Optimized script tag counting
    let scriptTagCount = 0;
    let scriptPos = limitedContent.indexOf('<script');
    while (scriptPos > -1) {
        scriptTagCount++;
        scriptPos = limitedContent.indexOf('<script', scriptPos + 7); // Move past '<script'
    }
    patternCounts.scriptTags = scriptTagCount;
    
    patternCounts.encodingCalls = (limitedContent.match(/atob|btoa|encodeURIComponent|decodeURIComponent|escape|unescape/gi) || []).length;
    patternCounts.binaryConstructs = (limitedContent.match(/ArrayBuffer|Uint8Array|DataView|BlobBuilder/gi) || []).length;

    // JS Keywords frequency
    const jsKeywordsRegex = /eval|fromCharCode|Function\(|constructor|prototype|__proto__|setTimeout\(|setInterval\(|document\.write/gi;
    patternCounts.jsKeywords = (limitedContent.match(jsKeywordsRegex) || []).length;

    features.set('blobUsageCount', patternCounts.blob);
    features.set('downloadAttrCount', patternCounts.download);

    if (limitedContentLength > 0) {
      features.set('scriptTagDensity', patternCounts.scriptTags / (limitedContentLength / 1000));
      features.set('jsKeywordDensity', patternCounts.jsKeywords / (limitedContentLength / 1000));
    } else {
      features.set('scriptTagDensity', 0);
      features.set('jsKeywordDensity', 0);
    }
    features.set('encodingCallCount', patternCounts.encodingCalls);
    features.set('binaryConstructCount', patternCounts.binaryConstructs);

    // New Contextual Features
    const sensitiveKeywordsRegex = /eval\(|document\.write\(|innerHTML\s*=|setAttribute\s*\(|createElement\s*\(|appendChild\s*\(|Function\s*\(|crypto\.subtle|navigator\.sendBeacon/gi;
    patternCounts.sensitiveKeywords = (limitedContent.match(sensitiveKeywordsRegex) || []).length;
    features.set('sensitiveKeywordCount', patternCounts.sensitiveKeywords);

    const suspiciousAssignmentsRegex = /(?:var|let|const)\s+\w+\s*=\s*(['"]([A-Za-z0-9+/=]{50,})['"]|['"][\w\s]+['"]\s*\+[\s\S]{1,100}?['"][\w\s]+['"]);/gi;
    patternCounts.suspiciousAssignments = (limitedContent.match(suspiciousAssignmentsRegex) || []).length;
    features.set('suspiciousStringAssignmentCount', patternCounts.suspiciousAssignments);
    
    patternCounts.atobCalls = (limitedContent.match(/(?:window\.)?atob\s*\(/gi) || []).length;
    patternCounts.dynamicAtobArgs = (limitedContent.match(/(?:window\.)?atob\s*\(\s*(?![ \t]*['"])/gi) || []).length;
    if (patternCounts.atobCalls > 0) {
        features.set('dynamicAtobArgsRatio', patternCounts.dynamicAtobArgs / patternCounts.atobCalls);
    } else {
        features.set('dynamicAtobArgsRatio', 0);
    }
    features.set('atobCallCount', patternCounts.atobCalls);


    if (limitedContentLength > 0) {
        features.set('avgLineLength', limitedContentLength / patternCounts.lineCount);
        features.set('nonAsciiCharRatio', patternCounts.nonAsciiChars / limitedContentLength);
        features.set('whitespaceRatio', patternCounts.whitespaceChars / limitedContentLength);
    } else {
        features.set('avgLineLength', 0);
        features.set('nonAsciiCharRatio', 0);
        features.set('whitespaceRatio', 0);
    }
    features.set('maxNestingDepth', patternCounts.maxDepth);
    features.set('contentLength', limitedContentLength); // Explicitly add contentLength

    // Boolean flags (using .test for efficiency) - Existing
    features.set('hasDataUri', /data:(?:application|text)\/[^;]+;base64,/i.test(limitedContent) ? 1 : 0);
    features.set('hasBlobUri', /blob:[^"']+/i.test(limitedContent) ? 1 : 0);
    // Refined file creation pattern: looks for common download link patterns
    features.set('hasFileCreationPattern', /\.href\s*=\s*.*?\.download\s*=\s*.*?\.click\(\)/i.test(limitedContent) ? 1 : 0);
    
    if (this.featureCache.size >= this.maxCacheSize) {
      const firstKey = this.featureCache.keys().next().value;
      this.featureCache.delete(firstKey);
    }
    this.featureCache.set(cacheKey, features);
    
    return features;
  }

  hashContent(content) {
    let hash = 0;
    const start = content.substring(0, 1000);
    const end = content.length > 2000 ? 
      content.substring(content.length - 1000) : 
      '';
    const toHash = start + end;
    
    for (let i = 0; i < toHash.length; i++) {
      hash = ((hash << 5) - hash) + toHash.charCodeAt(i);
      hash = hash & hash;
    }
    return hash + '_' + content.length;
  }

  calculateScore(features) {
    let score = 0;
    let totalWeight = 0;
    
    for (const [feature, value] of features) {
      const weight = this.features.weights.get(feature) || 1;
      const threshold = this.features.patterns.get(feature) || 0;
      
      if (value > threshold) {
        score += weight;
      }
      totalWeight += weight;
    }
    
    return totalWeight > 0 ? score / totalWeight : 0;
  }

  async learn(content, isSmuggling) {
    const features = this.extractFeatures(content);
    
    for (const [feature, value] of features) {

      const currentThreshold = this.features.patterns.get(feature) || 0;
      const samples = this.features.contextual.get(feature) || 0;
      
      const newThreshold = (currentThreshold * samples + value) / (samples + 1);
      this.features.patterns.set(feature, newThreshold);
      this.features.contextual.set(feature, samples + 1);
      
      if (samples >= this.minSamples) {
        const currentWeight = this.features.weights.get(feature) || 1;
        const correlation = isSmuggling ? 1 : -1;
        const newWeight = Math.max(0.1, currentWeight + (this.learningRate * correlation));
        this.features.weights.set(feature, newWeight);
      }
    }
    
    this.monitor.recordValidation(isSmuggling);
    this.monitor.recordLearningProgress({
      features: this.features,
      threshold: this.threshold
    });
    
    
    this.learningCount++;
    if (this.learningCount >= 10 || Date.now() - this.lastModelSave >= this.saveThrottleMs) {
      await this.saveModel();
    }
  }

  detect(content) {
    const now = Date.now();
    if (now - this.lastDetectionTime < this.detectionThrottleMs) {
      return null;
    }
    this.lastDetectionTime = now;

    const features = this.extractFeatures(content);
    const score = this.calculateScore(features);
    const prediction = {
      isSmuggling: score >= this.threshold,
      confidence: score,
      features: Object.fromEntries(features)
    };
    
    if (score > 0.3) { 
      this.monitor.recordPrediction(prediction, Object.fromEntries(features));
    }
    
    return prediction;
  }
} 
