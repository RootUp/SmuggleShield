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
    this.metrics.totalDetections++;
    this.metrics.confidenceScores.push(prediction.confidence);
    
    for (const [feature, value] of Object.entries(features)) {
      const current = this.metrics.featureImportance.get(feature) || {
        totalImpact: 0,
        occurrences: 0
      };
      current.totalImpact += value * prediction.confidence;
      current.occurrences++;
      this.metrics.featureImportance.set(feature, current);
    }

    if (this.metrics.confidenceScores.length > 1000) {
      this.metrics.confidenceScores.shift();
    }

    this.saveMetrics();
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
    this.metrics.learningProgress.push({
      timestamp: Date.now(),
      accuracy: this.metrics.modelAccuracy,
      featuresLearned: modelState.features.patterns.size,
      threshold: modelState.threshold
    });

    if (this.metrics.learningProgress.length > 100) {
      this.metrics.learningProgress.shift();
    }

    this.saveMetrics();
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
} 