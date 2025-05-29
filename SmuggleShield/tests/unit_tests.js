// SmuggleShield Unit Tests
// ========================
//
// How to Run These Tests:
//
// 1. Browser Developer Console (Recommended for tests involving browser APIs or extension context):
//    - Open the extension's background page console or a relevant extension page (like main.html).
//    - Copy the relevant class definitions (e.g., WeakLRUCache, MLDetector) from their respective
//      source files (`background.js`, `ml_detector.js`) and paste them into the console if they
//      are not already globally accessible. This might require temporarily modifying the original
//      files to make classes/functions global for testing, e.g., `window.WeakLRUCache = WeakLRUCache;`.
//    - Copy the specific test functions you want to run (or all of them) from this file.
//    - Paste them into the console.
//    - Execute the test runner function (e.g., `runAllBackgroundTests()`, `runAllMLDetectorTests()`)
//      or individual test functions (e.g., `testWeakLRUCache_SetAndGet()`).
//    - Check the console for "Test Passed" messages or "Test Failed" assertions.
//
// 2. Node.js (For non-browser-specific logic):
//    - Some utility functions (e.g., `hashContent`, `calculateScore` from MLDetector, or parts of WeakLRUCache
//      if browser APIs like `chrome.storage` are mocked or not used by the specific function) can be
//      tested in Node.js.
//    - You would need to `require` or import the necessary functions/classes. This might involve
//      refactoring the original files to use module exports (`module.exports = ...` or ES6 modules).
//    - Create a Node.js script, import the test functions and the functions/classes to be tested.
//    - Run the script using `node your_test_script.js`.
//
// Note: For complex classes like MLDetector, which interacts with `chrome.storage` and `MLMonitor`,
// full testing in Node.js would require significant mocking. Browser console testing is more
// straightforward for those. The tests below are designed with console execution in mind first.

// --- Test Runner Functions ---
function runAllTests() {
    console.log("Running All SmuggleShield Unit Tests...");
    runAllBackgroundTests();
    runAllMLDetectorTests();
    console.log("All SmuggleShield Unit Tests Completed.");
}

function runAllBackgroundTests() {
    console.log("\n--- Running background.js Tests ---");
    testWeakLRUCache_SetAndGet();
    testWeakLRUCache_Eviction();
    testWeakLRUCache_GetKeyString();
    // Add calls to other background.js tests here
    console.log("--- background.js Tests Completed ---");
}

function runAllMLDetectorTests() {
    console.log("\n--- Running ml_detector.js Tests ---");
    testMLDetector_HashContent();
    testMLDetector_ExtractFeatures_BasicCounts();
    testMLDetector_ExtractFeatures_ScriptTagDensity();
    testMLDetector_ExtractFeatures_Base64Features();
    testMLDetector_ExtractFeatures_JsKeywordDensity();
    testMLDetector_CalculateScore();
    testMLDetector_ModelSerialization();
    // Add calls to other ml_detector.js tests here
    console.log("--- ml_detector.js Tests Completed ---");
}

// Helper for comparing objects/arrays in assertions
function deepCompare(a, b) {
    return JSON.stringify(a) === JSON.stringify(b);
}

// --- Tests for background.js ---

// Mocking chrome.storage.local for WeakLRUCache tests if it were to use it directly.
// For the provided WeakLRUCache, it's self-contained, so no chrome API mocking needed for it.

// If WeakLRUCache is not globally available, you need to paste its definition first.
// Example: Paste the WeakLRUCache class definition here if running standalone.
/*
class WeakLRUCache { ... } // Paste from background.js
*/


function testWeakLRUCache_SetAndGet() {
    console.log("Test: WeakLRUCache - Set and Get");
    const cache = new WeakLRUCache(3);
    cache.set("key1", "value1");
    cache.set("key2", { data: "value2" });

    let val1 = cache.get("key1");
    console.assert(val1 === "value1", "Test Failed: WeakLRUCache_SetAndGet - Value for key1");
    if (val1 === "value1") console.log("  Passed: Get key1");

    let val2 = cache.get("key2");
    console.assert(deepCompare(val2, { data: "value2" }), "Test Failed: WeakLRUCache_SetAndGet - Value for key2");
    if (deepCompare(val2, { data: "value2" })) console.log("  Passed: Get key2 (object)");
    
    let val3 = cache.get("nonexistent");
    console.assert(val3 === undefined, "Test Failed: WeakLRUCache_SetAndGet - Value for nonexistent key");
    if (val3 === undefined) console.log("  Passed: Get nonexistent key");
}

function testWeakLRUCache_Eviction() {
    console.log("Test: WeakLRUCache - Eviction");
    const cache = new WeakLRUCache(2);
    cache.set("a", 1);
    cache.set("b", 2);
    cache.set("c", 3); // Should evict "a"

    let valA = cache.get("a");
    console.assert(valA === undefined, "Test Failed: WeakLRUCache_Eviction - 'a' should be evicted");
    if (valA === undefined) console.log("  Passed: 'a' evicted");

    let valB = cache.get("b");
    console.assert(valB === 2, "Test Failed: WeakLRUCache_Eviction - 'b' should still exist");
    if (valB === 2) console.log("  Passed: 'b' exists");
    
    cache.set("d", 4); // Should evict "c" because "b" was accessed more recently
    let valC = cache.get("c");
    console.assert(valC === undefined, "Test Failed: WeakLRUCache_Eviction - 'c' should be evicted");
     if (valC === undefined) console.log("  Passed: 'c' evicted after 'b' access");
}

function testWeakLRUCache_GetKeyString() {
    console.log("Test: WeakLRUCache - getKeyString");
    const cache = new WeakLRUCache(1); // Size doesn't matter for this test
    
    const keyStr = "myKey";
    const keyObj = { id: 1, name: "test" };
    const keyArr = [1, 2, 3];

    let strResult = cache.getKeyString(keyStr);
    console.assert(strResult === "myKey", "Test Failed: getKeyString - string input");
    if (strResult === "myKey") console.log("  Passed: string key");

    let objResult = cache.getKeyString(keyObj);
    console.assert(objResult === JSON.stringify(keyObj), "Test Failed: getKeyString - object input");
    if (objResult === JSON.stringify(keyObj)) console.log("  Passed: object key");
    
    let arrResult = cache.getKeyString(keyArr);
    console.assert(arrResult === JSON.stringify(keyArr), "Test Failed: getKeyString - array input");
    if (arrResult === JSON.stringify(keyArr)) console.log("  Passed: array key");
}


// --- Tests for ml_detector.js ---

// For MLDetector tests, its class definition, and potentially MLMonitor, would need to be
// available globally or pasted here. MLDetector also uses chrome.storage.local,
// which would need mocking for full Node.js testing. These tests assume a browser-like
// environment or that `chrome.storage.local` calls in `loadModel`/`saveModel` won't break
// the specific function being tested (e.g., `hashContent`, `extractFeatures`, `calculateScore`).

/*
class MLMonitor { constructor() { this.data = []; } recordValidation() {} recordLearningProgress() {} getPerformanceReport() { return { accuracy: 0, totalDetections: 0, averageConfidence: 0, topFeatures: [], recentPerformance: []}; } }
class MLDetector { ... } // Paste from ml_detector.js. Ensure MLMonitor is defined if not pasting.
*/

// Mock chrome.storage.local for MLDetector tests
const mockChromeStorage = {
    local: {
        get: (keys, callback) => {
            // console.log('Mock chrome.storage.local.get called with keys:', keys);
            if (typeof keys === 'string' && keys === 'mlModel') {
                callback({ mlModel: MLDetector.mockModelStorage || null });
            } else if (Array.isArray(keys) && keys.includes('mlModel')) {
                 callback({ mlModel: MLDetector.mockModelStorage || null });
            } else {
                callback({});
            }
        },
        set: (items, callback) => {
            // console.log('Mock chrome.storage.local.set called with items:', items);
            if (items.mlModel) {
                MLDetector.mockModelStorage = items.mlModel;
            }
            if (callback) callback();
        },
        clear: (callback) => {
            MLDetector.mockModelStorage = null;
            if (callback) callback();
        }
    }
};

// Use this mock if running in an environment where 'chrome' is not defined
if (typeof chrome === 'undefined' || !chrome.storage) {
    // console.log("Mocking chrome.storage.local for MLDetector tests.");
    // @ts-ignore
    globalThis.chrome = { ...globalThis.chrome, storage: mockChromeStorage };
}
// Static property on MLDetector to hold the mock model data for tests
// MLDetector.mockModelStorage = null; // Will be initialized before tests needing it


function testMLDetector_HashContent() {
    console.log("Test: MLDetector - hashContent");
    // Assuming MLDetector class is available
    const detector = new MLDetector(); // Constructor might try to loadModel

    const content1 = "Hello World";
    const content2 = "Hello World!";
    const content3 = "Hello World"; // Same as content1

    const hash1 = detector.hashContent(content1);
    const hash2 = detector.hashContent(content2);
    const hash3 = detector.hashContent(content3);

    console.assert(typeof hash1 === 'string' && hash1.length > 0, "Test Failed: hashContent - hash1 type/empty");
    console.assert(hash1 === hash3, "Test Failed: hashContent - hash1 and hash3 should be equal");
    if (hash1 === hash3) console.log("  Passed: Same content yields same hash");
    
    console.assert(hash1 !== hash2, "Test Failed: hashContent - hash1 and hash2 should be different");
    if (hash1 !== hash2) console.log("  Passed: Different content yields different hash");

    // Test with long content to ensure substring logic works
    const longContentPrefix = "start".repeat(300); // 1500 chars
    const longContentSuffix = "end".repeat(300);   // 1500 chars
    const longContentMiddle = "middle".repeat(100); // 600 chars
    const longContent = longContentPrefix + longContentMiddle + longContentSuffix; // 3600 chars
    const hashLong = detector.hashContent(longContent);
    
    // Hash of content with same prefix & suffix but different middle (if middle is not part of hash)
    // The current hashContent uses start 1000 and end 1000.
    // So, if prefix > 1000 and suffix > 1000, middle part won't affect the hash.
    const longContentSameHash = longContentPrefix + "different_middle".repeat(50) + longContentSuffix;
    const hashLongSame = detector.hashContent(longContentSameHash);
    console.assert(hashLong === hashLongSame, "Test Failed: hashContent - long content hashing consistency");
    if (hashLong === hashLongSame) console.log("  Passed: Long content with same start/end (that are part of hash) yields same hash");
}

function testMLDetector_ExtractFeatures_BasicCounts() {
    console.log("Test: MLDetector - extractFeatures (Basic Counts)");
    const detector = new MLDetector();
    
    const content = "new blob download='file.txt' atob('test') ArrayBuffer <script>alert(1)</script>";
    const features = detector.extractFeatures(content);

    console.assert(features.get('blobUsageCount') === 1, "Test Failed: extractFeatures - blobUsageCount");
    if (features.get('blobUsageCount') === 1) console.log("  Passed: blobUsageCount");

    console.assert(features.get('downloadAttrCount') === 1, "Test Failed: extractFeatures - downloadAttrCount");
    if (features.get('downloadAttrCount') === 1) console.log("  Passed: downloadAttrCount");
    
    console.assert(features.get('encodingCallCount') >= 1, "Test Failed: extractFeatures - encodingCallCount (atob)");
    if (features.get('encodingCallCount') >= 1) console.log("  Passed: encodingCallCount (atob)");

    console.assert(features.get('binaryConstructCount') === 1, "Test Failed: extractFeatures - binaryConstructCount");
    if (features.get('binaryConstructCount') === 1) console.log("  Passed: binaryConstructCount");
}

function testMLDetector_ExtractFeatures_ScriptTagDensity() {
    console.log("Test: MLDetector - extractFeatures (Script Tag Density)");
    const detector = new MLDetector();

    // Content length approx 2000 chars, 2 script tags
    const exampleHtmlWithScripts = `
        <html><head></head><body>
        <p>Some text here to make content longer.</p>
        <script>var x = 1; console.log('script 1');</script>
        <p>More text and elements.</p>
        <div><script type="text/javascript">function foo() { return 'bar'; }</script></div>
        <p>Even more text to ensure length is substantial.</p>
        ${" ".repeat(1500)}
        </body></html>
    `;
    const features = detector.extractFeatures(exampleHtmlWithScripts);
    const expectedDensity = 2 / (exampleHtmlWithScripts.length / 1000);
    
    console.assert(features.get('scriptTagCount') === 2, "Test Failed: extractFeatures - scriptTagCount");
    if (features.get('scriptTagCount') === 2) console.log("  Passed: scriptTagCount");

    // Using a tolerance for floating point comparison
    const density = features.get('scriptTagDensity');
    console.assert(Math.abs(density - expectedDensity) < 0.001, 
        `Test Failed: extractFeatures - scriptTagDensity. Expected ~${expectedDensity.toFixed(3)}, Got ${density.toFixed(3)}`);
    if (Math.abs(density - expectedDensity) < 0.001) console.log("  Passed: scriptTagDensity");

    const noScriptContent = "<html><body><p>No scripts here.</p></body></html>";
    const noScriptFeatures = detector.extractFeatures(noScriptContent);
    console.assert(noScriptFeatures.get('scriptTagCount') === 0, "Test Failed: extractFeatures - no scriptTagCount");
    if (noScriptFeatures.get('scriptTagCount') === 0) console.log("  Passed: no scriptTagCount");
    console.assert(noScriptFeatures.get('scriptTagDensity') === 0, "Test Failed: extractFeatures - no scriptTagDensity");
    if (noScriptFeatures.get('scriptTagDensity') === 0) console.log("  Passed: no scriptTagDensity");
}

function testMLDetector_ExtractFeatures_Base64Features() {
    console.log("Test: MLDetector - extractFeatures (Base64 Features)");
    const detector = new MLDetector();

    const str100 = "A".repeat(100); // Length 100
    const str150 = "B".repeat(150); // Length 150
    const contentWithBase64 = `Some text ${str100} and more text ${str150}. Not base64: ${"C".repeat(50)}`;
    
    const features = detector.extractFeatures(contentWithBase64);

    console.assert(features.get('base64BlockCount') === 2, "Test Failed: extractFeatures - base64BlockCount");
    if (features.get('base64BlockCount') === 2) console.log("  Passed: base64BlockCount");

    const expectedTotalChars = 100 + 150;
    console.assert(features.get('totalBase64Chars') === expectedTotalChars, "Test Failed: extractFeatures - totalBase64Chars");
    if (features.get('totalBase64Chars') === expectedTotalChars) console.log("  Passed: totalBase64Chars");

    const expectedRatio = expectedTotalChars / contentWithBase64.length;
    console.assert(Math.abs(features.get('base64ContentRatio') - expectedRatio) < 0.001, "Test Failed: extractFeatures - base64ContentRatio");
    if (Math.abs(features.get('base64ContentRatio') - expectedRatio) < 0.001) console.log("  Passed: base64ContentRatio");
    
    const expectedAvgLength = expectedTotalChars / 2;
    console.assert(features.get('avgBase64BlockLength') === expectedAvgLength, "Test Failed: extractFeatures - avgBase64BlockLength");
    if (features.get('avgBase64BlockLength') === expectedAvgLength) console.log("  Passed: avgBase64BlockLength");
}

function testMLDetector_ExtractFeatures_JsKeywordDensity() {
    console.log("Test: MLDetector - extractFeatures (JS Keyword Density)");
    const detector = new MLDetector();
    // eval, fromCharCode, Function, constructor, prototype, __proto__, setTimeout, setInterval, document.write
    const contentWithKeywords = `
        var x = eval('danger'); 
        var y = String.fromCharCode(65); 
        var z = new Function('return 1'); 
        var p = obj.constructor;
        ${" ".repeat(500)} 
    `; // 4 keywords
    const features = detector.extractFeatures(contentWithKeywords);
    const expectedKeywordCount = 4;
    const expectedDensity = expectedKeywordCount / (contentWithKeywords.length / 1000);

    console.assert(features.get('jsKeywordCount') === expectedKeywordCount, 
        `Test Failed: extractFeatures - jsKeywordCount. Expected ${expectedKeywordCount}, Got ${features.get('jsKeywordCount')}`);
    if (features.get('jsKeywordCount') === expectedKeywordCount) console.log("  Passed: jsKeywordCount");
    
    const density = features.get('jsKeywordDensity');
    console.assert(Math.abs(density - expectedDensity) < 0.001, 
        `Test Failed: extractFeatures - jsKeywordDensity. Expected ~${expectedDensity.toFixed(3)}, Got ${density.toFixed(3)}`);
    if (Math.abs(density - expectedDensity) < 0.001) console.log("  Passed: jsKeywordDensity");
}


function testMLDetector_CalculateScore() {
    console.log("Test: MLDetector - calculateScore");
    const detector = new MLDetector(); // MLDetector instance needed for context if `this` is used, or make it static

    // Mock features and model weights/thresholds for testing calculateScore directly
    // This bypasses extractFeatures and loadModel for this specific unit test.
    detector.features.weights = new Map([
        ['feature1', 2.0],
        ['feature2', 1.0],
        ['feature3', 0.5]
    ]);
    detector.features.patterns = new Map([ // These are thresholds for features
        ['feature1', 5],  // feature1 value > 5 contributes to score
        ['feature2', 0],  // feature2 value > 0 contributes to score (e.g. boolean flags)
        ['feature3', 10]  // feature3 value > 10 contributes to score
    ]);

    const inputFeatures1 = new Map([
        ['feature1', 10], // > 5, contributes 2.0
        ['feature2', 1],  // > 0, contributes 1.0
        ['feature3', 5]   // < 10, contributes 0
    ]);
    // Expected score = (2.0 + 1.0) / (2.0 + 1.0 + 0.5) = 3.0 / 3.5 = 0.857...
    let score1 = detector.calculateScore(inputFeatures1);
    console.assert(Math.abs(score1 - (3.0 / 3.5)) < 0.001, `Test Failed: calculateScore - Scenario 1. Expected ~0.857, Got ${score1}`);
    if (Math.abs(score1 - (3.0 / 3.5)) < 0.001) console.log("  Passed: Scenario 1");

    const inputFeatures2 = new Map([
        ['feature1', 3],  // < 5, contributes 0
        ['feature2', 0],  // not > 0, contributes 0
        ['feature3', 20] // > 10, contributes 0.5
    ]);
    // Expected score = (0.5) / (2.0 + 1.0 + 0.5) = 0.5 / 3.5 = 0.142...
    let score2 = detector.calculateScore(inputFeatures2);
    console.assert(Math.abs(score2 - (0.5 / 3.5)) < 0.001, `Test Failed: calculateScore - Scenario 2. Expected ~0.142, Got ${score2}`);
    if (Math.abs(score2 - (0.5 / 3.5)) < 0.001) console.log("  Passed: Scenario 2");

    const inputFeatures3 = new Map(); // No features matching weights
    let score3 = detector.calculateScore(inputFeatures3);
     // Total weight will be sum of all weights if no features match, or 0 if weights map is empty.
     // current logic: totalWeight is sum of weights of features present in inputFeatures that are also in detector.features.weights
     // if inputFeatures is empty, score is 0 / 0 = NaN, or 0 if totalWeight is 0.
     // Corrected: totalWeight in calculateScore is sum of weights of features *present in the input features map*.
     // If inputFeatures is empty, totalWeight = 0, score = 0.
    console.assert(score3 === 0, `Test Failed: calculateScore - Empty features. Expected 0, Got ${score3}`);
    if (score3 === 0) console.log("  Passed: Empty features");
    
    // Reset detector features for other tests
    detector.features.weights = new Map();
    detector.features.patterns = new Map();
}

function testMLDetector_ModelSerialization() {
    console.log("Test: MLDetector - Model Serialization/Deserialization");
    const detector = new MLDetector(); // Constructor might load an empty model

    // Populate a model
    const originalModelData = {
        patterns: new Map([['featureA', 0.5], ['featureB', 10]]),
        contextual: new Map([['featureA', 100], ['featureB', 50]]),
        weights: new Map([['featureA', 1.5], ['featureB', 0.8]])
    };
    detector.features = originalModelData;

    // Serialize
    const serialized = detector.serializeModel();
    // console.log("Serialized model:", JSON.stringify(serialized));

    console.assert(Array.isArray(serialized.patterns), "Test Failed: Serialized patterns is not array");
    console.assert(Array.isArray(serialized.contextual), "Test Failed: Serialized contextual is not array");
    console.assert(Array.isArray(serialized.weights), "Test Failed: Serialized weights is not array");

    // Deserialize into a new "empty" detector or overwrite current
    const newDetector = new MLDetector(); // Fresh detector
    newDetector.features = newDetector.deserializeModel(serialized);
    
    // Verify
    console.assert(deepCompare(newDetector.features.patterns, originalModelData.patterns), "Test Failed: Deserialized patterns mismatch");
    if(deepCompare(newDetector.features.patterns, originalModelData.patterns)) console.log("  Passed: Patterns deserialized correctly");
    
    console.assert(deepCompare(newDetector.features.contextual, originalModelData.contextual), "Test Failed: Deserialized contextual mismatch");
    if(deepCompare(newDetector.features.contextual, originalModelData.contextual)) console.log("  Passed: Contextual deserialized correctly");

    console.assert(deepCompare(newDetector.features.weights, originalModelData.weights), "Test Failed: Deserialized weights mismatch");
    if(deepCompare(newDetector.features.weights, originalModelData.weights)) console.log("  Passed: Weights deserialized correctly");

    // Test with empty initial model
    detector.features = { patterns: new Map(), contextual: new Map(), weights: new Map() };
    const emptySerialized = detector.serializeModel();
    newDetector.features = newDetector.deserializeModel(emptySerialized);
    console.assert(newDetector.features.patterns.size === 0, "Test Failed: Empty model patterns");
    if(newDetector.features.patterns.size === 0) console.log("  Passed: Empty model patterns deserialized");

}


// --- End of Tests ---

// Example of how to run (uncomment in console):
// runAllTests();
// runAllBackgroundTests();
// runAllMLDetectorTests();

// To run specific tests:
// testWeakLRUCache_SetAndGet();
// testMLDetector_HashContent();
// testMLDetector_ExtractFeatures_ScriptTagDensity();

// Remember to paste class definitions if they are not globally available.
// E.g. for MLDetector, ensure MLMonitor and MLDetector classes are defined.
// For background.js WeakLRUCache, ensure its class is defined.
//
// class MLMonitor { constructor() { this.data = []; } recordValidation() {} recordLearningProgress() {} getPerformanceReport() { return { accuracy: 0, totalDetections: 0, averageConfidence: 0, topFeatures: [], recentPerformance: []}; } }
// class WeakLRUCache { constructor(maxSize) { this.maxSize = maxSize; this.cache = new Map(); this.keyMap = new Map(); } get(key) { const keyString = this.getKeyString(key); const value = this.cache.get(keyString); if (value) { this.cache.delete(keyString); this.cache.set(keyString, value); } return value; } set(key, value) { const keyString = this.getKeyString(key); if (this.cache.has(keyString)) { this.cache.delete(keyString); } else if (this.cache.size >= this.maxSize) { const oldestKey = this.cache.keys().next().value; this.cache.delete(oldestKey); } this.cache.set(keyString, value); this.keyMap.set(keyString, key); } clear() { this.cache.clear(); this.keyMap.clear(); } getKeyString(key) { return typeof key === 'object' ? JSON.stringify(key) : String(key); } }
// class MLDetector { constructor() { this.monitor = new MLMonitor(); this.features = { patterns: new Map(), contextual: new Map(), weights: new Map() }; this.threshold = 0.75; this.learningRate = 0.1; this.minSamples = 5; this.lastDetectionTime = 0; this.detectionThrottleMs = 1000; this.featureCache = new Map(); this.maxCacheSize = 1000; this.lastModelSave = Date.now(); this.saveThrottleMs = 30000; this.pendingSave = false; this.learningCount = 0; this.loadModel(); } async loadModel() { try { const data = await new Promise(resolve => { chrome.storage.local.get(['mlModel'], result => resolve(result.mlModel)); }); if (data?.mlModel) { this.features = this.deserializeModel(data.mlModel); } } catch (error) { console.error('Error loading ML model:', error); } } async saveModel() { try { const now = Date.now(); if (now - this.lastModelSave < this.saveThrottleMs) { if (!this.pendingSave) { this.pendingSave = true; setTimeout(() => { this.actualSaveModel(); this.pendingSave = false; }, this.saveThrottleMs - (now - this.lastModelSave)); } return; } await this.actualSaveModel(); } catch (error) { console.error('Error saving ML model:', error); } } async actualSaveModel() { try { await chrome.storage.local.set({ mlModel: this.serializeModel() }); this.lastModelSave = Date.now(); this.learningCount = 0; } catch (error) { console.error('Error in actualSaveModel:', error); } } serializeModel() { return { patterns: Array.from(this.features.patterns.entries()), contextual: Array.from(this.features.contextual.entries()), weights: Array.from(this.features.weights.entries()) }; } deserializeModel(data) { return { patterns: new Map(data.patterns), contextual: new Map(data.contextual), weights: new Map(data.weights) }; } extractFeatures(content) { const cacheKey = this.hashContent(content); if (this.featureCache.has(cacheKey)) { return this.featureCache.get(cacheKey); } const features = new Map(); const limitedContent = content.length > 50000 ? content.substring(0, 25000) + content.substring(content.length - 25000) : content; const limitedContentLength = limitedContent.length; const patternCounts = { base64Blocks: 0, totalBase64Chars: 0, blob: 0, download: 0, scriptTags: 0, encodingCalls: 0, binaryConstructs: 0, jsKeywords: 0, }; const base64Matches = limitedContent.match(/[A-Za-z0-9+/=]{100,}/g) || []; patternCounts.base64Blocks = base64Matches.length; for (const match of base64Matches) { patternCounts.totalBase64Chars += match.length; } features.set('base64BlockCount', patternCounts.base64Blocks); features.set('totalBase64Chars', patternCounts.totalBase64Chars); if (limitedContentLength > 0) { features.set('base64ContentRatio', patternCounts.totalBase64Chars / limitedContentLength); features.set('avgBase64BlockLength', patternCounts.base64Blocks > 0 ? patternCounts.totalBase64Chars / patternCounts.base64Blocks : 0); } else { features.set('base64ContentRatio', 0); features.set('avgBase64BlockLength', 0); } patternCounts.blob = (limitedContent.match(/new\s+blob/gi) || []).length; patternCounts.download = (limitedContent.match(/download\s*=\s*["'][^"']*["']/gi) || []).length; let scriptTagCount = 0; let scriptPos = limitedContent.indexOf('<script'); while (scriptPos > -1) { scriptTagCount++; scriptPos = limitedContent.indexOf('<script', scriptPos + 7); } patternCounts.scriptTags = scriptTagCount; patternCounts.encodingCalls = (limitedContent.match(/atob|btoa|encodeURIComponent|decodeURIComponent|escape|unescape/gi) || []).length; patternCounts.binaryConstructs = (limitedContent.match(/ArrayBuffer|Uint8Array|DataView|BlobBuilder/gi) || []).length; const jsKeywordsRegex = /eval|fromCharCode|Function\(|constructor|prototype|__proto__|setTimeout\(|setInterval\(|document\.write/gi; patternCounts.jsKeywords = (limitedContent.match(jsKeywordsRegex) || []).length; features.set('blobUsageCount', patternCounts.blob); features.set('downloadAttrCount', patternCounts.download); if (limitedContentLength > 0) { features.set('scriptTagDensity', patternCounts.scriptTags / (limitedContentLength / 1000)); features.set('jsKeywordDensity', patternCounts.jsKeywords / (limitedContentLength / 1000)); } else { features.set('scriptTagDensity', 0); features.set('jsKeywordDensity', 0); } features.set('encodingCallCount', patternCounts.encodingCalls); features.set('binaryConstructCount', patternCounts.binaryConstructs); features.set('hasDataUri', /data:(?:application|text)\/[^;]+;base64,/i.test(limitedContent) ? 1 : 0); features.set('hasBlobUri', /blob:[^"']+/i.test(limitedContent) ? 1 : 0); features.set('hasFileCreationPattern', /\.href\s*=\s*.*?\.download\s*=\s*.*?\.click\(\)/i.test(limitedContent) ? 1 : 0); if (this.featureCache.size >= this.maxCacheSize) { const firstKey = this.featureCache.keys().next().value; this.featureCache.delete(firstKey); } this.featureCache.set(cacheKey, features); return features; } hashContent(content) { let hash = 0; const start = content.substring(0, 1000); const end = content.length > 2000 ? content.substring(content.length - 1000) : ''; const toHash = start + end; for (let i = 0; i < toHash.length; i++) { hash = ((hash << 5) - hash) + toHash.charCodeAt(i); hash = hash & hash; } return hash + '_' + content.length; } calculateScore(features) { let score = 0; let totalWeight = 0; for (const [feature, value] of features) { const weight = this.features.weights.get(feature) || 1; const threshold = this.features.patterns.get(feature) || 0; if (value > threshold) { score += weight; } totalWeight += weight; } return totalWeight > 0 ? score / totalWeight : 0; } async learn(content, isSmuggling) { const features = this.extractFeatures(content); for (const [feature, value] of features) { const currentThreshold = this.features.patterns.get(feature) || 0; const samples = this.features.contextual.get(feature) || 0; const newThreshold = (currentThreshold * samples + value) / (samples + 1); this.features.patterns.set(feature, newThreshold); this.features.contextual.set(feature, samples + 1); if (samples >= this.minSamples) { const currentWeight = this.features.weights.get(feature) || 1; const correlation = isSmuggling ? 1 : -1; const newWeight = Math.max(0.1, currentWeight + (this.learningRate * correlation)); this.features.weights.set(feature, newWeight); } } this.monitor.recordValidation(isSmuggling); this.monitor.recordLearningProgress({ features: this.features, threshold: this.threshold }); this.learningCount++; if (this.learningCount >= 10 || Date.now() - this.lastModelSave >= this.saveThrottleMs) { await this.saveModel(); } } detect(content) { const now = Date.now(); if (now - this.lastDetectionTime < this.detectionThrottleMs) { return null; } this.lastDetectionTime = now; const features = this.extractFeatures(content); const score = this.calculateScore(features); const prediction = { isSmuggling: score >= this.threshold, confidence: score, features: Object.fromEntries(features) }; if (score > 0.3) { this.monitor.recordPrediction(prediction, Object.fromEntries(features)); } return prediction; } }
// MLDetector.mockModelStorage = null; // Initialize if needed for model load/save parts of tests

// For tests that need chrome.storage.local, you'll need to set up the mock:
// if (typeof chrome === 'undefined' || !chrome.storage) {
//     globalThis.chrome = { storage: mockChromeStorage };
// }
// MLDetector.mockModelStorage = null; // Reset before tests if needed

// To run in Node.js, you'd need to export classes from source files and import here.
// E.g., in background.js: module.exports = { WeakLRUCache };
// And here: const { WeakLRUCache } = require('../background.js');
// Similar for MLDetector.
// The provided `MLMonitor` and `MLDetector` at the end are for quick copy-pasting into console.
// Remove or comment them out if you are managing imports/globals differently.
//
