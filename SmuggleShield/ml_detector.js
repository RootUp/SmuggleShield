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
    const features = new Map();
    
    features.set('base64Length', (content.match(/[A-Za-z0-9+/=]{100,}/g) || []).length);
    features.set('blobUsage', (content.match(/new\s+blob/gi) || []).length);
    features.set('downloadAttr', (content.match(/download=["'][^"']*["']/gi) || []).length);
    
    features.set('scriptDensity', content.split('script').length / content.length);
    features.set('encodingFunctions', (content.match(/atob|btoa|encode|decode/gi) || []).length);
    features.set('binaryManipulation', (content.match(/ArrayBuffer|Uint8Array|DataView/gi) || []).length);
    
    return features;
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
    const features = this.extractFeatures(content);
    const score = this.calculateScore(features);
    const prediction = {
      isSmuggling: score >= this.threshold,
      confidence: score,
      features: Object.fromEntries(features)
    };
    this.monitor.recordPrediction(prediction, Object.fromEntries(features));
    return prediction;
  }
} 