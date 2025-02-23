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
      await chrome.storage.local.set({
        mlModel: this.serializeModel()
      });
    } catch (error) {
      console.error('Error saving ML model:', error);
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
    
    const combinedPattern = /(?:[A-Za-z0-9+/=]{100,})|(?:new\s+blob)|(?:download=["'][^"']*["'])|(?:script)|(?:atob|btoa|encode|decode)|(?:ArrayBuffer|Uint8Array|DataView)/gi;
    
    const matches = content.match(combinedPattern) || [];
    const counts = new Map();
    
    matches.forEach(match => {
      const type = this.categorizeMatch(match);
      counts.set(type, (counts.get(type) || 0) + 1);
    });
    
    features.set('base64Length', counts.get('base64') || 0);
    features.set('blobUsage', counts.get('blob') || 0);
    features.set('downloadAttr', counts.get('download') || 0);
    features.set('scriptDensity', (counts.get('script') || 0) / content.length);
    features.set('encodingFunctions', counts.get('encoding') || 0);
    features.set('binaryManipulation', counts.get('binary') || 0);
    
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
    const len = Math.min(content.length, 1000);
    for (let i = 0; i < len; i++) {
      hash = ((hash << 5) - hash) + content.charCodeAt(i);
      hash = hash & hash;
    }
    return hash;
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
    
    await this.saveModel();
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
