class MLMonitor {
  constructor() {
    this.metrics = {
      totalDetections: 0,
      truePositives: 0,
      falsePositives: 0,
      modelAccuracy: 0,
      confidenceScores: [],
      featureImportance: new Map([
        ['base64Length', { totalImpact: 0, occurrences: 0 }],
        ['blobUsage', { totalImpact: 0, occurrences: 0 }],
        ['downloadAttr', { totalImpact: 0, occurrences: 0 }],
        ['scriptDensity', { totalImpact: 0, occurrences: 0 }],
        ['encodingFunctions', { totalImpact: 0, occurrences: 0 }],
        ['binaryManipulation', { totalImpact: 0, occurrences: 0 }]
      ]),
      learningProgress: []
    };
    
    this.metrics.learningProgress.push({
      timestamp: Date.now(),
      accuracy: 0,
      featuresLearned: 0,
      threshold: 0.75
    });
    
    this.loadMetrics();
    
    this.debouncedSave = this.debounce(this.saveMetrics.bind(this), 5000);
  }

  async loadMetrics() {
    try {
      const data = await new Promise(resolve => {
        chrome.storage.local.get(['mlMetrics'], result => resolve(result.mlMetrics));
      });
      if (data?.mlMetrics) {
        this.metrics = {...this.metrics, ...data.mlMetrics};
      }
    } catch (error) {
      console.error('Error loading ML metrics:', error);
    }
  }

  async saveMetrics() {
    try {
      await chrome.storage.local.set({
        mlMetrics: this.metrics
      });
    } catch (error) {
      console.error('Error saving ML metrics:', error);
    }
  }

  recordPrediction(prediction, features) {
    if (Math.abs(prediction.confidence - this.getAverageConfidence()) > 0.1) {
      this.metrics.totalDetections++;
      this.metrics.confidenceScores.push(prediction.confidence);
      
      const updates = new Map();
      for (const [feature, value] of Object.entries(features)) {
        if (value > 0.1) {
          const current = this.metrics.featureImportance.get(feature) || {
            totalImpact: 0,
            occurrences: 0
          };
          updates.set(feature, {
            totalImpact: current.totalImpact + (value * prediction.confidence),
            occurrences: current.occurrences + 1
          });
        }
      }
      
      updates.forEach((value, key) => {
        this.metrics.featureImportance.set(key, value);
      });

      if (this.metrics.confidenceScores.length > 1000) {
        this.metrics.confidenceScores = this.metrics.confidenceScores.slice(-1000);
      }

      this.debouncedSave();
    }
  }

  recordValidation(wasCorrect) {
    if (wasCorrect) {
      this.metrics.truePositives++;
    } else {
      this.metrics.falsePositives++;
    }
    
    this.updateAccuracy();
    this.saveMetrics();
  }

  updateAccuracy() {
    const total = this.metrics.truePositives + this.metrics.falsePositives;
    this.metrics.modelAccuracy = total > 0 ? 
      this.metrics.truePositives / total : 0;
  }

  recordLearningProgress(modelState) {
    const lastProgress = this.metrics.learningProgress[this.metrics.learningProgress.length - 1];
    
    if (!lastProgress || 
        Math.abs(this.metrics.modelAccuracy - lastProgress.accuracy) > 0.05 ||
        Math.abs(modelState.features.patterns.size - lastProgress.featuresLearned) > 5) {
        
        this.metrics.learningProgress.push({
            timestamp: Date.now(),
            accuracy: this.metrics.modelAccuracy,
            featuresLearned: modelState.features.patterns.size,
            threshold: modelState.threshold
        });

        if (this.metrics.learningProgress.length > 100) {
            this.metrics.learningProgress = this.metrics.learningProgress.slice(-100);
        }

        this.debouncedSave();
    }
  }

  getPerformanceReport() {
    return {
      accuracy: this.metrics.modelAccuracy,
      totalDetections: this.metrics.totalDetections,
      averageConfidence: this.getAverageConfidence(),
      topFeatures: this.getTopFeatures(5),
      learningProgress: this.metrics.learningProgress,
      recentPerformance: this.getRecentPerformance()
    };
  }

  getAverageConfidence() {
    return this.metrics.confidenceScores.length > 0 ?
      this.metrics.confidenceScores.reduce((a, b) => a + b, 0) / 
      this.metrics.confidenceScores.length : 0;
  }

  getTopFeatures(n) {
    return Array.from(this.metrics.featureImportance.entries())
      .map(([feature, {totalImpact, occurrences}]) => ({
        feature,
        importance: totalImpact / occurrences
      }))
      .sort((a, b) => b.importance - a.importance)
      .slice(0, n);
  }

  getRecentPerformance() {
    const recent = this.metrics.learningProgress.slice(-10);
    return {
      accuracyTrend: recent.map(p => p.accuracy),
      featureGrowth: recent.map(p => p.featuresLearned)
    };
  }

  debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
  }
} 
