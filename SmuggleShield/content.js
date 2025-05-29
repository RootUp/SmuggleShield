const mlDetectorInstance = new MLDetector();

class PatternService {
    constructor(suspiciousPatterns, threshold) {
        this.threshold = threshold;
        this.suspiciousPatterns = suspiciousPatterns.map(({ pattern, weight }) => ({
            pattern: new RegExp(pattern, 'is'),
            weight,
            category: this.categorizePattern(pattern.source)
        }));
        this.patternsByWeight = this.groupPatternsByWeight();
        this.metrics = { matchCount: 0 };
    }

    categorizePattern(patternSource) {
        if (patternSource.includes('blob') || patternSource.includes('createobjecturl')) {
            return 'blob';
        } else if (patternSource.includes('base64') || patternSource.includes('atob')) {
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

    analyze(content) {
        let score = 0;
        const detectedPatterns = [];

        if (content.length < 50) {
            return { isSuspicious: false, detectedPatterns: [], score: 0 };
        }

        const quickCheck = /blob|atob|download|base64|arraybuffer|uint8array|createobjecturl|fromcharcode/i;
        if (!quickCheck.test(content)) {
            return { isSuspicious: false, detectedPatterns: [], score: 0 };
        }

        const highWeightPatterns = Object.keys(this.patternsByWeight)
            .filter(weight => parseInt(weight) >= 3)
            .flatMap(weight => this.patternsByWeight[weight]);

        for (const { pattern, weight } of highWeightPatterns) {
            if (pattern.test(content)) {
                score += weight;
                detectedPatterns.push(pattern.toString());
                this.metrics.matchCount++;
                if (score >= this.threshold) {
                    return { isSuspicious: true, detectedPatterns, score };
                }
            }
        }

        if (score >= this.threshold - 2) {
            const lowWeightPatterns = Object.keys(this.patternsByWeight)
                .filter(weight => parseInt(weight) < 3)
                .flatMap(weight => this.patternsByWeight[weight]);

            for (const { pattern, weight } of lowWeightPatterns) {
                if (pattern.test(content)) {
                    score += weight;
                    detectedPatterns.push(pattern.toString());
                    this.metrics.matchCount++;
                    if (score >= this.threshold) {
                        return { isSuspicious: true, detectedPatterns, score };
                    }
                }
            }
        }
        return { isSuspicious: score >= this.threshold, detectedPatterns, score };
    }

    isSuspiciousScript(scriptContent) {
        return this.suspiciousPatterns.some(({ pattern }) => pattern.test(scriptContent));
    }
}

class AnalysisCache {
    constructor(maxSize = 1000) {
        this.cache = new Map();
        this.maxSize = maxSize;
        this.metrics = { cacheHits: 0, cacheMisses: 0 };
    }

    getCacheKey(content) {
        let hash = 0;
        const len = Math.min(content.length, 500); // Use a prefix for hashing
        for (let i = 0; i < len; i++) {
            hash = ((hash << 5) - hash) + content.charCodeAt(i);
            hash = hash & hash;
        }
        return `${hash}_${content.length}`;
    }

    get(key) {
        if (this.cache.has(key)) {
            this.metrics.cacheHits++;
            return this.cache.get(key);
        }
        this.metrics.cacheMisses++;
        return null;
    }

    set(key, value) {
        this.cache.set(key, value);
        if (this.cache.size > this.maxSize) {
            const firstKey = this.cache.keys().next().value;
            this.cache.delete(firstKey);
        }
    }
}

class MLIntegrationService {
    constructor(mlEnabled = true, feedbackDelay = 2000) {
        this.mlDetector = mlDetectorInstance;
        this.mlEnabled = mlEnabled;
        this.feedbackDelay = feedbackDelay;
    }

    detect(content) {
        if (!this.mlEnabled) return null;
        return this.mlDetector.detect(content);
    }

    learn(content, isSmuggling) {
        if (!this.mlEnabled) return;
        this.mlDetector.learn(content, isSmuggling);
    }

    getPerformanceReport() {
        return this.mlDetector.monitor.getPerformanceReport();
    }
}

class DomScanner {
    constructor(patternService, analysisCache, mlIntegrationService, htmlSmugglingBlockerRef) {
        this.patternService = patternService;
        this.analysisCache = analysisCache;
        this.mlIntegrationService = mlIntegrationService;
        this.blocker = htmlSmugglingBlockerRef;
        this.observer = null;
    }

    setupObserver() {
        this.observer = new MutationObserver((mutations) => {
            if (this.blocker.isUrlWhitelisted) return;

            const nodesToAnalyze = new Set();
            for (const mutation of mutations) {
                if (mutation.addedNodes.length > 0) {
                    for (const node of mutation.addedNodes) {
                        if (node instanceof HTMLElement) nodesToAnalyze.add(node);
                    }
                }
                if (mutation.type === 'attributes' && mutation.target instanceof HTMLElement) {
                    nodesToAnalyze.add(mutation.target);
                }
            }
            if (nodesToAnalyze.size > 0) {
                this.analyzeNodes(Array.from(nodesToAnalyze));
            }
        });

        this.observer.observe(document.documentElement, {
            childList: true,
            subtree: true,
            attributes: true,
            attributeFilter: ['src', 'href', 'download', 'data-file', 'data-payload']
        });
    }

    disconnectObserver() {
        if (this.observer) {
            console.log('Disconnecting mutation observer.');
            this.observer.disconnect();
            this.observer = null;
        }
    }

    async performInitialTargetedScan() {
        if (this.blocker.isUrlWhitelisted) {
            console.log('URL is whitelisted, skipping initial targeted scan.');
            return;
        }
        console.log("Performing initial targeted scan for patterns.");
        const elementsToScan = document.querySelectorAll(
            'script:not([src]), a[download][href^="data:"], a[download][href^="blob:"], embed, svg, iframe[srcdoc]'
        );
        for (const el of elementsToScan) {
            if (el && el.parentNode) {
                await this.analyzeSingleNode(el);
            }
        }
        console.log("Initial targeted scan completed.");
    }

    async analyzeSingleNode(node) {
        const nodeAnalysisStartTime = performance.now();
        if (this.blocker.isUrlWhitelisted || !node || typeof node.hasAttribute !== 'function' || !node.parentNode) {
            return;
        }

        const htmlContent = node.outerHTML;
        if (!htmlContent || htmlContent.length < 20) return;

        const cacheKey = this.analysisCache.getCacheKey(htmlContent);
        const cachedResult = this.analysisCache.get(cacheKey);

        if (cachedResult) {
            if (cachedResult.isSuspicious) {
                this.handleSuspiciousNode(node, cachedResult.reportingPatterns);
            }
            this.blocker.updatePerformanceMetrics(nodeAnalysisStartTime);
            return;
        }

        const patternResult = this.patternService.analyze(htmlContent);
        let mlResult = null;

        if (this.mlIntegrationService.mlEnabled && (htmlContent.length > 1000 || patternResult.score > 1)) {
            mlResult = this.mlIntegrationService.detect(htmlContent);
        }

        const isSuspiciousByPattern = patternResult.score >= this.patternService.threshold;
        const isSuspiciousByML = this.mlIntegrationService.mlEnabled && (mlResult?.isSmuggling || false);
        const isSuspicious = isSuspiciousByPattern || isSuspiciousByML;

        this.analysisCache.set(cacheKey, {
            isSuspicious: isSuspicious,
            patternScore: patternResult.score,
            detectedPatterns: patternResult.detectedPatterns,
            mlIsSmuggling: mlResult?.isSmuggling || false,
            mlConfidence: mlResult?.confidence || 0,
            reportingPatterns: isSuspiciousByPattern ? patternResult.detectedPatterns : (isSuspiciousByML ? ["ML:HighConfidence"] : [])
        });
        
        if (isSuspicious) {
            const reportingPatterns = isSuspiciousByPattern ? patternResult.detectedPatterns : (isSuspiciousByML ? ["ML:HighConfidence"] : []);
            this.handleSuspiciousNode(node, reportingPatterns);

            setTimeout(() => {
                if (this.blocker.blocked && this.blocker.lastBlockedNode === node && node.parentNode) {
                    this.mlIntegrationService.learn(htmlContent, true);
                } else if (mlResult && node.parentNode) {
                    const actuallyBlockedByPatternsForThisNode = isSuspiciousByPattern && this.blocker.blocked && this.blocker.lastBlockedNode === node;
                    if (mlResult.isSmuggling && !actuallyBlockedByPatternsForThisNode) {
                        this.mlIntegrationService.learn(htmlContent, false);
                    } else if (!mlResult.isSmuggling && !actuallyBlockedByPatternsForThisNode) {
                         this.mlIntegrationService.learn(htmlContent, false);
                    }
                } else if (this.mlIntegrationService.mlEnabled && htmlContent.length > 1000 && !mlResult && node.parentNode) {
                     if (!(this.blocker.blocked && this.blocker.lastBlockedNode === node)) {
                        this.mlIntegrationService.learn(htmlContent, false);
                     }
                }
            }, this.mlIntegrationService.feedbackDelay);
        } else { 
            if (this.mlIntegrationService.mlEnabled && mlResult && node.parentNode) {
                this.mlIntegrationService.learn(htmlContent, false);
            } else if (this.mlIntegrationService.mlEnabled && htmlContent.length > 1000 && !mlResult && node.parentNode) {
                 this.mlIntegrationService.learn(htmlContent, false);
            }
        }
        this.blocker.updatePerformanceMetrics(nodeAnalysisStartTime);
    }

    analyzeNodes(nodes) {
        if (this.blocker.isUrlWhitelisted || nodes.length === 0) return;
        for (const node of nodes) {
            if (node instanceof HTMLElement && node.parentNode) {
                this.analyzeSingleNode(node);
            }
        }
    }

    handleSuspiciousNode(node, detectedPatterns) {
        if (this.blocker.isUrlWhitelisted || !node.parentNode) return;

        let removed = false;
        if (node.tagName === 'SCRIPT' && !node.src) {
            if (this.patternService.isSuspiciousScript(node.textContent)) {
                this.removeElement(node);
                removed = true;
            }
        } else if (node.tagName === 'A' && node.hasAttribute('download') && (node.href.startsWith('data:') || node.href.startsWith('blob:'))) {
            this.removeElement(node);
            removed = true;
        } else if (node.tagName === 'EMBED') {
            this.removeElement(node);
            removed = true;
        } else if (node.tagName === 'SVG' && node.querySelector('script')) {
            const scripts = node.querySelectorAll('script');
            scripts.forEach(script => this.removeElement(script));
            removed = true; 
        } else {

            const suspiciousChildren = node.querySelectorAll('a[download][href^="data:"], a[download][href^="blob:"], embed, svg script');
            if (suspiciousChildren.length > 0) {
                suspiciousChildren.forEach(el => this.removeElement(el));
                removed = true;
            }
            const inlineScripts = node.querySelectorAll('script:not([src])');
            inlineScripts.forEach(script => {
                if (this.patternService.isSuspiciousScript(script.textContent)) {
                    this.removeElement(script);
                    removed = true;
                }
            });
        }

        if (removed) {
            this.blocker.blocked = true;
            this.blocker.lastBlockedNode = node;
            this.blocker.logWarning(1, 0, 0, 0, detectedPatterns);
        }
    }

    removeElement(element) {
        if (element && element.parentNode) {
            element.parentNode.removeChild(element);
        }
    }
}


class HTMLSmugglingBlocker {
    constructor() {
        this.blocked = false;
        this.lastBlockedNode = null;
        this.isUrlWhitelisted = false;
        this.analysisCounter = 0;
        this.metrics = { analysisTime: [], earlyTerminations: 0 };

        const suspiciousPatternsConfig = [
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
            { pattern: /var\s+\w+=\w+;?\s*\(function\(\w+,\w+\)\{.*while\(!!\[\]\)\{try\{.*parseint.*\}catch\(\w+\)\{.*\}\}\(.*\)\);?/is, weight: 4 },
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
            { pattern: /document\.createElement\(['"]script['"]\).*?\.src\s*=.*?\.cache\.js/i, weight: 4 },
            { pattern: /(?:document|window)\.on(?:mousemove|load|mouseover)\s*=\s*function\s*\(\s*\)\s*\{[^}]*?data:application\/[^}]*?\.click\(\)[^}]*?(?:removeChild|remove)\(/i, weight: 4 },
            { pattern: /(?:window|var|let)\.\w+Triggered\s*=\s*(?:true|false).*?(?:navigator|platform).*?data:application\/[^;]+;base64,.*?\.(?:download|click)/i, weight: 4 },
            { pattern: /navigator\[?["']platform["']\]?.*?(?:document|window)\.on\w+.*?data:application\//i, weight: 4 },
            { pattern: /\[['"][^'"]+['"]\s*\+\s*['"][^'"]+['"]\]/i, weight: 3 },
            { pattern: /\['[a-z]+'\s*\+\s*'[a-z]+'\]/i, weight: 3 },
            { pattern: /\[\s*(?:['"][a-zA-Z0-9]?['"](?:\s*,\s*)?){4,}\s*\]\.join\s*\(\s*['"]*\s*\)/i, weight: 3 },
            { pattern: /const\s+\w+\s*=\s*\[\s*(?:['"][a-zA-Z]?['"](?:\s*,\s*)?){4,}/i, weight: 3 },
            { pattern: /(\[(?:\][^(]*|\[\])[^(]*|\w+\.)constructor\s*\(\s*(['"])return\s*\w+\2\s*\)/i, weight: 4 },
            { pattern: /Function\s*\(\s*['"]return\s+\w+['"](?:\s*\)\s*\(\s*\)|\(\))/i, weight: 4 },
            { pattern: /\w+\.split\s*\(\s*['"]['"]?\s*\)\.reverse\s*\(\s*\)\.join\s*\(/i, weight: 3 },
            { pattern: /\[\s*\w+\.split\s*\(\s*['"]['"]\s*\)\.reverse\s*\(\s*\)/i, weight: 3 },
            { pattern: /setTimeout\s*\(\s*(?:function|\(\)|[^,]+)\s*(?:=>)?\s*\{[\s\S]{10,}?setTimeout\s*\(/i, weight: 3 },
            { pattern: /setTimeout\s*\([^{)]*\{[^{}]*setTimeout\s*\([^{)]*\{[^{}]*\}/i, weight: 4 },
            { pattern: /new\s*\([^)]*\[\s*(?:['"][^'"]+['"]\.split|['"]\w+['"]\.split)/i, weight: 4 },
            { pattern: /\[[^\]]*(?:join|reverse)[^\]]*\]\s*\(\s*(?:\w+|['"][^'"]*['"])\s*\)/i, weight: 3 },
            { pattern: /\[\s*(?:urlMethod|parts\.join\(\)|['"]\w+['"]\s*\+)/i, weight: 3 },
            { pattern: /\w+\s*\[\s*(?:['"][^'"]+['"](?:\s*\+\s*)?)+\s*\]\s*\(\s*\w+\s*\)/i, weight: 4 },
            { pattern: /['"]?down['"]?\s*\+\s*['"]?load['"]?/i, weight: 3 },
            { pattern: /\['down' \+ 'load'\]/i, weight: 4 },
            { pattern: /createElement\s*\(\s*['"]a['"]\s*\)[^}]*?\[\s*['"]\w+['"]\s*\+\s*['"]\w+['"]\s*\]/i, weight: 4 },
            { pattern: /\['style'\]\['visi' \+ 'bility'\]/i, weight: 3 },
            { pattern: /function\s+\w+Chunks\s*\([^)]*\)\s*\{[^{}]*for\s*\([^{}]*\)\s*\{[^{}]*substr/i, weight: 3 },
            { pattern: /\.substr\s*\(\s*\w+\s*,\s*\w+Size\s*\)/i, weight: 2 },
            { pattern: /\(async\s*\(\s*\)\s*=>\s*\{\s*(?:let|var|const)\s+d\s*=.*?(?:document\.getElementById|document\.querySelector).*?dataset.*?\.href\s*=\s*d.*?\.download\s*=.*?\.click\s*\(\s*\)/is, weight: 4 },
            { pattern: /\bdocument\.getElementById\s*\(\s*['"]data['"]\s*\).*?\.dataset\.file.*?createElement\s*\(\s*['"]a['"]\s*\).*?\.download\s*=/is, weight: 4 },
            { pattern: /<div[^>]*id\s*=\s*["']data["'][^>]*data-file\s*=\s*["'][A-Za-z0-9+\/=]{50,}["'][^>]*>/is, weight: 3 },
            { pattern: /<script>\s*\(\s*async\s*\(\s*\)\s*=>\s*\{[^}]*createElement\s*\(\s*['"]a['"]\s*\)[^}]*\.click\s*\(\s*\)[^}]*\.remove\s*\(\s*\)/is, weight: 4 },
            { pattern: /\b(?:atob|decodeURIComponent)\s*\([^)]*(?:dataset|getAttribute)\s*\.[^)]*\)[^;]*\.href\s*=[^;]*\.download\s*=[^;]*\.click\s*\(\s*\)/is, weight: 4 },
            { pattern: /\bdocument\.body\.appendChild\s*\([^)]+\)[^;]*\.click\s*\(\s*\)[^;]*\.remove\s*\(\s*\)/is, weight: 4 },
        ];
        const patternThreshold = 4;

        this.patternService = new PatternService(suspiciousPatternsConfig, patternThreshold);
        this.analysisCache = new AnalysisCache();
        this.mlIntegrationService = new MLIntegrationService(); // Uses global mlDetectorInstance implicitly
        this.domScanner = new DomScanner(this.patternService, this.analysisCache, this.mlIntegrationService, this);

        this.checkInitialWhitelistSync();
        this.setupListeners();

        setTimeout(() => {
            this.checkInitialWhitelist().then(() => {
                if (!this.isUrlWhitelisted) {
                    this.domScanner.performInitialTargetedScan();
                }
            });
        }, 50);
    }

    checkInitialWhitelistSync() {
        try {
            const hostname = window.location.hostname;
            const whitelistStr = localStorage.getItem('smuggleshield_whitelist');
            if (whitelistStr) {
                const whitelist = JSON.parse(whitelistStr);
                this.isUrlWhitelisted = Array.isArray(whitelist) && whitelist.includes(hostname);
                console.log('Sync whitelist check:', hostname, 'Is whitelisted:', this.isUrlWhitelisted);
                if (this.isUrlWhitelisted) this.setWhitelistMode(true);
            }
        } catch (error) {
            console.error('Error in sync whitelist check:', error);
        }
    }

    async checkInitialWhitelist() {
        try {
            const hostname = window.location.hostname;
            const result = await chrome.storage.local.get('whitelist');
            const whitelist = result.whitelist || [];
            
            try { localStorage.setItem('smuggleshield_whitelist', JSON.stringify(whitelist)); } 
            catch (e) { console.warn('Could not save whitelist to localStorage:', e); }
            
            const wasWhitelisted = this.isUrlWhitelisted;
            this.isUrlWhitelisted = whitelist.includes(hostname);
            
            if (this.isUrlWhitelisted !== wasWhitelisted) {
                this.setWhitelistMode(this.isUrlWhitelisted);
            }
            return this.isUrlWhitelisted;
        } catch (error) {
            console.error('Error checking whitelist:', error);
            this.isUrlWhitelisted = false;
            return false;
        }
    }

    setWhitelistMode(enabled) {
        this.isUrlWhitelisted = enabled;
        this.blocked = false; 

        if (enabled) {
            console.log('Whitelist mode: ENABLED. Disabling DOM scanner.');
            if (this.domScanner) this.domScanner.disconnectObserver();
            
            document.documentElement.style.display = ''; 
            document.querySelectorAll('script[type="text/plain-smuggleshield"]').forEach(script => {
                 script.setAttribute('type', script.dataset.originalType || 'text/javascript');
                 delete script.dataset.originalType;
            });

        } else {
            console.log('Whitelist mode: DISABLED. Enabling DOM scanner.');
            if (this.domScanner && !this.domScanner.observer) { 
                 this.domScanner.setupObserver();
                 this.domScanner.performInitialTargetedScan(); 
            } else if (!this.domScanner) {
                console.error("DomScanner not initialized in setWhitelistMode.");
            }
        }
    }
    
    setupListeners() {
        chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
            if (request.action === "setWhitelisted") {
                this.setWhitelistMode(request.value);
            } else if (request.action === "whitelistUpdated") {
                this.checkInitialWhitelist();
            } else if (request.action === "getBlockedStatus") {
                sendResponse({ blocked: this.blocked });
            } else if (request.action === "suspiciousHeadersDetected") {
                if (!this.isUrlWhitelisted && this.domScanner) {
                    this.domScanner.performInitialTargetedScan();
                }
            } else if (request.action === "getMLMetrics") {
                if (this.mlIntegrationService) {
                    const report = this.mlIntegrationService.getPerformanceReport();
                    sendResponse({ metrics: {
                        accuracy: report.accuracy,
                        totalDetections: report.totalDetections,
                        averageConfidence: report.averageConfidence,
                        topFeatures: report.topFeatures,
                        recentPerformance: report.recentPerformance
                    }});
                } else {
                    sendResponse({ metrics: null, error: "ML service not available."})
                }
                return true; 
            }
        });

        if (!this.isUrlWhitelisted && this.domScanner) {
            this.domScanner.setupObserver();
        }
    }

    updatePerformanceMetrics(startTime) {
        const analysisTime = performance.now() - startTime;
        this.metrics.analysisTime.push(analysisTime);
        this.analysisCounter++;
        if (this.analysisCounter % 100 === 0) {
            this.logPerformanceMetrics();
        }
    }

    logPerformanceMetrics() {
        const avgAnalysisTime = this.metrics.analysisTime.length > 0 ? 
                               this.metrics.analysisTime.reduce((a, b) => a + b, 0) / this.metrics.analysisTime.length : 0;
        const cacheHitRate = (this.analysisCache.metrics.cacheHits + this.analysisCache.metrics.cacheMisses) > 0 ?
                             (this.analysisCache.metrics.cacheHits / 
                             (this.analysisCache.metrics.cacheHits + this.analysisCache.metrics.cacheMisses) * 100) : 0;
        
        console.debug('Performance Metrics:', {
            averageAnalysisTime: `${avgAnalysisTime.toFixed(2)}ms`,
            cacheHitRate: `${cacheHitRate.toFixed(2)}%`,
            totalMatchesInPatterns: this.patternService.metrics.matchCount,
            totalAnalyses: this.analysisCounter
        });
        this.metrics.analysisTime = [];
    }

    logWarning(elementsRemoved, scriptsDisabled, svgScriptsNeutralized, embedElementsRemoved, detectedPatterns) {
        const message = `HTML Smuggling attempt blocked. Patterns: ${detectedPatterns.join(', ')}`;
        console.warn(message);
        chrome.runtime.sendMessage({
            action: "logWarning",
            message: message,
            patterns: detectedPatterns
        }).catch(e => console.debug("Error sending logWarning message:", e));
    }
    
    isSuspiciousScript(scriptContent) {
        return this.patternService.isSuspiciousScript(scriptContent);
    }
}

new HTMLSmugglingBlocker();
console.log("HTMLSmugglingBlocker initialized with new modular structure.");
