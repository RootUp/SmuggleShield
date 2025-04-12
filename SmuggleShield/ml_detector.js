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
    
    const limitedContent = content.length > 50000 ? 
      content.substring(0, 25000) + content.substring(content.length - 25000) : 
      content;
    
    
    const patternCounts = {
      base64: 0,
      blob: 0,
      download: 0,
      script: 0, 
      encoding: 0,
      binary: 0
    };
    
    
    const base64Matches = limitedContent.match(/[A-Za-z0-9+/=]{100,}/g) || [];
    patternCounts.base64 = base64Matches.length;
    
    patternCounts.blob = (limitedContent.match(/new\s+blob/gi) || []).length;
    
    patternCounts.download = (limitedContent.match(/download\s*=\s*["'][^"']*["']/gi) || []).length;
    
    patternCounts.script = (limitedContent.match(/<script[^>]*>[^<]*<\/script>/gi) || []).length;
    
    patternCounts.encoding = (limitedContent.match(/atob|btoa|encode|decode/gi) || []).length;
    
    patternCounts.binary = (limitedContent.match(/ArrayBuffer|Uint8Array|DataView/gi) || []).length;
    
    features.set('base64Length', patternCounts.base64);
    features.set('blobUsage', patternCounts.blob);
    features.set('downloadAttr', patternCounts.download);
    features.set('scriptDensity', patternCounts.script / (limitedContent.length / 1000));
    features.set('encodingFunctions', patternCounts.encoding);
    features.set('binaryManipulation', patternCounts.binary);
    
    const hasDataUri = /data:application\/[^;]+;base64,/i.test(limitedContent);
    const hasBlobUri = /blob:[^"']+/i.test(limitedContent);
    const hasFileCreation = /\.click\(\s*\)[^}]*(?:revoke|remove)/i.test(limitedContent);
    
    features.set('hasDataUri', hasDataUri ? 1 : 0);
    features.set('hasBlobUri', hasBlobUri ? 1 : 0);
    features.set('hasFileCreation', hasFileCreation ? 1 : 0);
    
    if (this.featureCache.size >= this.maxCacheSize) {
      const firstKey = this.featureCache.keys().next().value;
      this.featureCache.delete(firstKey);
    }
    this.featureCache.set(cacheKey, features);
    
    return features;
  }

  categorizeMatch(match) {
    if (match.length >= 100 && /^[A-Za-z0-9+/=]+$/.test(match)) return 'base64';
    if (/new\s+blob/i.test(match)) return 'blob';
    if (/download=["'][^"']*["']/i.test(match)) return 'download';
    if (/script/i.test(match)) return 'script';
    if (/atob|btoa|encode|decode/i.test(match)) return 'encoding';
    if (/ArrayBuffer|Uint8Array|DataView/i.test(match)) return 'binary';
    return 'other';
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
