// Global ML Detector instance - remains global as it manages its own state/model.
const mlDetectorInstance = new MLDetector();

class PatternService {
    constructor(suspiciousPatternsConfig, threshold) {
        this.threshold = threshold;
        // Sort patterns by a new 'priority' field (higher first), then by weight for tie-breaking.
        // Add critical flag processing.
        this.suspiciousPatterns = suspiciousPatternsConfig
            .map(({ pattern, weight, name, heuristic, critical, priority }) => ({
                pattern: new RegExp(pattern, 'is'), // Ensure flags are consistently applied
                weight,
                name: name || pattern.source, // Use provided name or regex source as a fallback name
                heuristic: heuristic, // Optional heuristic function for this pattern
                critical: critical || false, // Add critical flag
                priority: priority || 0, // Add priority
                category: this.categorizePattern(pattern.source)
            }))
            .sort((a, b) => b.priority - a.priority || b.weight - a.weight); // Sort by priority then weight

        this.patternsByWeight = this.groupPatternsByWeight(); 
        this.metrics = { matchCount: 0, heuristicAdjustments: {} };
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
        let currentScore = 0;
        const detectedPatternsInfo = [];
        const MAX_SCORE_TARGET = this.threshold * 1.5; // More aggressive early exit
        let criticalMatchFound = false;

        if (content.length < 20) { // Reduced min length for quick check
            return { isSuspicious: false, detectedPatterns: [], score: 0, heuristicDetails: [], criticalMatch: false };
        }

        // Expanded quickCheck, apply only if content is not extremely short
        const quickCheck = /blob|atob|download|base64|arraybuffer|uint8array|createobjecturl|fromcharcode|eval|document\.write|innerHTML|appendChild|createElement|Function\(|setTimeout|setInterval|script|iframe|srcdoc|location|href|window|document|self|navigator|screen|this|var|let|const|new|try|catch|throw|function|return|=>|import|export|class|extends|super|constructor|prototype|__proto__|yield|async|await|debugger|alert|prompt|confirm|localStorage|sessionStorage|indexedDB|fetch|XMLHttpRequest|WebSocket|importScripts|execScript|msSetImmediate|openDatabase|crypto\.subtle|navigator\.sendBeacon|\.wasm|wasm[_-]?exec\.js|\.src\s*=|\.href\s*=/i;
        if (content.length > 100 && !quickCheck.test(content)) { 
            return { isSuspicious: false, detectedPatterns: [], score: 0, heuristicDetails: [], criticalMatch: false };
        }
        
        for (const p_config of this.suspiciousPatterns) {
            // Using exec for first match to check critical status quickly if applicable
            const firstMatch = p_config.pattern.exec(content); // Get first match for this pattern
            p_config.pattern.lastIndex = 0; // Reset lastIndex for global regexes if we were to use matchAll later

            if (firstMatch) {
                this.metrics.matchCount++; // Count first match
                let effectiveWeight = p_config.weight;
                let heuristicAppliedInfo = null;
                let isCriticalAndConfirmed = p_config.critical;

                if (p_config.heuristic) {
                    const heuristicResult = p_config.heuristic(firstMatch[0], content, firstMatch);
                    if (heuristicResult) {
                        effectiveWeight = heuristicResult.adjustedWeight;
                        heuristicAppliedInfo = heuristicResult.details;
                        if (p_config.critical && heuristicResult.isBenign === true) {
                            isCriticalAndConfirmed = false;
                        }
                        this.metrics.heuristicAdjustments[p_config.name] = (this.metrics.heuristicAdjustments[p_config.name] || 0) + 1;
                    } else if (p_config.critical) {
                        // No heuristic result, critical status stands
                    }
                }
                
                currentScore += effectiveWeight;
                const detectedInfo = { 
                    pattern: p_config.pattern.toString(), name: p_config.name,
                    originalWeight: p_config.weight, effectiveWeight: effectiveWeight,
                    heuristic: heuristicAppliedInfo, critical: isCriticalAndConfirmed 
                };
                detectedPatternsInfo.push(detectedInfo);

                if (isCriticalAndConfirmed && effectiveWeight >= this.threshold) {
                    criticalMatchFound = true;
                    currentScore = Math.max(currentScore, this.threshold); 
                     return { 
                        isSuspicious: true, 
                        detectedPatterns: detectedPatternsInfo.map(d => `${d.name} (w:${d.effectiveWeight.toFixed(1)})${d.heuristic ? ' H:'+d.heuristic : ''}${d.critical ? ' C!' : ''}`), 
                        score: currentScore, heuristicDetails: detectedPatternsInfo, criticalMatch: true 
                    };
                }

                // If not critical or not above threshold from a single critical match, continue checking other matches of this pattern (if global)
                // and other patterns. For simplicity in this pass, we'll assume one significant match per pattern is enough for its contribution.
                // To check all matches of a global regex: use content.matchAll(p_config.pattern) and loop here.
                // However, for performance, processing only the first match of high-priority patterns is faster.
            }

            if (currentScore >= this.threshold && this.suspiciousPatterns.indexOf(p_config) < 5) {
                break; 
            }
            if (currentScore >= MAX_SCORE_TARGET) break;
        }

        return { 
            isSuspicious: currentScore >= this.threshold, 
            detectedPatterns: detectedPatternsInfo.map(d => `${d.name} (w:${d.effectiveWeight.toFixed(1)})${d.heuristic ? ' H:'+d.heuristic : ''}${d.critical ? ' C!' : ''}`), 
            score: currentScore, heuristicDetails: detectedPatternsInfo, criticalMatch: criticalMatchFound
        };
    }

    isSuspiciousScript(scriptContent) {
        // This method is used by HTMLSmugglingBlocker for inline script checks not going through full node analysis.
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
            hash = hash & hash; // Convert to 32bit integer
        }
        return `${hash}_${content.length}`; // Include length to differentiate content with same prefix hash
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
            this.cache.delete(firstKey); // FIFO eviction
        }
    }
}

class MLIntegrationService {
    constructor(mlEnabled = true, feedbackDelay = 2000) {
        this.mlDetector = mlDetectorInstance; // Use the global instance
        this.mlEnabled = mlEnabled;
        this.feedbackDelay = feedbackDelay;
    }

    detect(content) {
        if (!this.mlEnabled) return null;
        return this.mlDetector.detect(content);
    }

    learn(content, isSmuggling) {
        if (!this.mlEnabled) return;
        // Feedback delay is handled by the caller (DomScanner) for now
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
        this.blocker = htmlSmugglingBlockerRef; // Reference to the main blocker for state and logging
        this.observer = null;
    }

    setupObserver() {
        this.observer = new MutationObserver((mutations) => {
            if (this.blocker.isUrlWhitelisted) return;

            const nodesToAnalyze = new Set(); // Use Set to avoid duplicate nodes
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
            attributeFilter: ['src', 'href', 'download', 'data-file', 'data-payload'] // More specific data attributes
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
                this.handleSuspiciousNode(node, cachedResult.reportingPatterns || ["CachedSuspicion"]);
            }
            this.blocker.updatePerformanceMetrics(nodeAnalysisStartTime);
            return;
        }

        const patternResult = this.patternService.analyze(htmlContent);
        let mlResult = null;
        let isSuspiciousByML = false;

        if (patternResult.criticalMatch && patternResult.isSuspicious) {
            console.debug("Critical pattern match confirmed by PatternService, score:", patternResult.score);
            // If critical and already suspicious by patterns, we can potentially skip ML or run it with less weight.
            // For now, the existing logic will proceed.
        }
        
        const mlInvocationScoreThreshold = this.patternService.threshold * 0.4; // e.g. 40% of pattern threshold
        const shouldInvokeML = this.mlIntegrationService.mlEnabled && 
                               (htmlContent.length > 800 || // Reasonably long content
                                patternResult.score > mlInvocationScoreThreshold || // Pattern score is somewhat indicative
                                (patternResult.criticalMatch && patternResult.score > 0) ); // Critical pattern was involved, even if score low

        if (shouldInvokeML) {
            mlResult = this.mlIntegrationService.detect(htmlContent);
            isSuspiciousByML = mlResult?.isSmuggling || false;
        }

        const isSuspiciousByPattern = patternResult.isSuspicious;
        const isSuspicious = isSuspiciousByPattern || isSuspiciousByML;
        
        let finalReportingPatterns = [];
        if (isSuspiciousByPattern) {
            finalReportingPatterns = patternResult.detectedPatterns;
        } else if (isSuspiciousByML) {
            finalReportingPatterns = ["ML:HighConfidence"];
        }

        this.analysisCache.set(cacheKey, {
            isSuspicious: isSuspicious,
            patternScore: patternResult.score,
            mlIsSmuggling: mlResult?.isSmuggling || false,
            mlConfidence: mlResult?.confidence || 0,
            criticalMatch: patternResult.criticalMatch,
            reportingPatterns: finalReportingPatterns 
        });
        
        if (isSuspicious) {
            this.handleSuspiciousNode(node, finalReportingPatterns);

            setTimeout(() => {
                if (this.blocker.blocked && this.blocker.lastBlockedNode === node && node.parentNode) {
                    this.mlIntegrationService.learn(htmlContent, true); // Blocked, likely smuggling
                } else if (mlResult && node.parentNode) {
                    const actuallyBlockedByPatternsForThisNode = isSuspiciousByPattern && this.blocker.blocked && this.blocker.lastBlockedNode === node;
                    if (mlResult.isSmuggling && !actuallyBlockedByPatternsForThisNode) {
                        this.mlIntegrationService.learn(htmlContent, false); // ML said smuggling, but patterns didn't block or different node blocked
                    } else if (!mlResult.isSmuggling && !actuallyBlockedByPatternsForThisNode) {
                         this.mlIntegrationService.learn(htmlContent, false); // ML said not smuggling, and patterns didn't block
                    }
                } else if (this.mlIntegrationService.mlEnabled && htmlContent.length > 1000 && !mlResult && node.parentNode) {
                    // Content was eligible for ML, but no result (e.g. throttled), learn as non-smuggling if not blocked
                     if (!(this.blocker.blocked && this.blocker.lastBlockedNode === node)) {
                        this.mlIntegrationService.learn(htmlContent, false);
                     }
                }
            }, this.mlIntegrationService.feedbackDelay);
        } else { // Not suspicious
            if (this.mlIntegrationService.mlEnabled && mlResult && node.parentNode) {
                this.mlIntegrationService.learn(htmlContent, false); // ML processed, not suspicious
            } else if (this.mlIntegrationService.mlEnabled && htmlContent.length > 1000 && !mlResult && node.parentNode) {
                 this.mlIntegrationService.learn(htmlContent, false); // Eligible for ML, no result, not suspicious
            }
        }
        this.blocker.updatePerformanceMetrics(nodeAnalysisStartTime);
    }

    analyzeNodes(nodes) {
        if (this.blocker.isUrlWhitelisted || nodes.length === 0) return;
        for (const node of nodes) {
            if (node instanceof HTMLElement && node.parentNode) { // Ensure node is still in DOM
                this.analyzeSingleNode(node);
            }
        }
    }

    handleSuspiciousNode(node, detectedPatterns) {
        if (this.blocker.isUrlWhitelisted || !node.parentNode) return; // Check if node is still in DOM

        let removed = false;
        if (node.tagName === 'SCRIPT' && !node.src) {
            if (this.patternService.isSuspiciousScript(node.textContent)) { // Check script content again
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
            removed = true; // At least one script was targeted
        } else {
            // Check for suspicious children if the node itself isn't directly one of the above
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
            this.blocker.lastBlockedNode = node; // Or perhaps null if only children were removed
            this.blocker.logWarning(1, 0, 0, 0, detectedPatterns); // Simplified logging for this example
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
        this.metrics = { analysisTime: [], earlyTerminations: 0 }; // earlyTerminations not used currently

        // Define suspicious patterns here, or load from a config
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
            { name: "StringFromCharCodeGeneric", pattern: /string\.fromcharcode\([^)]*\)/i, weight: 1.5, priority: 1 },
            { name: "CharCodeAt", pattern: /\.charcodeat\([^)]*\)/i, weight: 1.5, priority: 1 },
            { name: "PasswordStealerAttempt", pattern: /document\.getelementbyid\(['"']passwordid['"']\)\.value/i, weight: 3, critical: true, priority: 9 },
            { name: "ImportCreateObjectUrl", pattern: /import\s*\(\s*url\.createobjecturl\s*\(/i, weight: 3, priority: 2 },
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
            { pattern: /setTimeout\s*\(\s*(?:function|\(\)|[^),]+)\s*(?:=>)?\s*\{[\s\S]{10,}?(?:eval|atob|document\.write|setAttribute|innerHTML|appendChild|createElement|fromCharCode)[\s\S]*?setTimeout\s*\(/is, weight: 3 }, // Refined Pattern 3
            { pattern: /setTimeout\s*\([^{)]*\{[^{}]*setTimeout\s*\([^{)]*\{[^{}]*\}/i, weight: 4 },
            { pattern: /new\s*\([^)]*\[\s*(?:['"][^'"]+['"]\.split|['"]\w+['"]\.split)/i, weight: 4 },
            { pattern: /\[[^\]]*(?:join|reverse)[^\]]*\]\s*\(\s*(?:\w+|['"][^'"]*['"])\s*\)/i, weight: 3 },
            { pattern: /\[\s*(?:['"](?:eval|atob|script|iframe|srcdoc|document|window|location|write|createElement|innerHTML|appendChild)['"]\s*\+\s*['"]\w+['"]|parts\.join\(\)|urlMethod)\s*\]/is, weight: 3 }, // Refined Pattern 1
            { pattern: /(?:window|document|this|self|navigator|screen)\s*\[\s*(?:['"][\w.-]+['"]\s*\+){1,}\s*['"][\w.-]+['"]\s*\]\s*\([\w\s.,'"]*\)/is, weight: 4 }, // Refined Pattern 4
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
            this.isUrlWhitelisted = false; // Default to not whitelisted on error
            return false;
        }
    }

    setWhitelistMode(enabled) {
        this.isUrlWhitelisted = enabled;
        this.blocked = false; // Reset blocked state when whitelist status changes

        if (enabled) {
            console.log('Whitelist mode: ENABLED. Disabling DOM scanner.');
            if (this.domScanner) this.domScanner.disconnectObserver();
            
            // Minimal overrides to prevent analysis when whitelisted
            // The DomScanner's methods already check this.isUrlWhitelisted
            document.documentElement.style.display = ''; // Ensure content is shown
            document.querySelectorAll('script[type="text/plain-smuggleshield"]').forEach(script => {
                 script.setAttribute('type', script.dataset.originalType || 'text/javascript');
                 delete script.dataset.originalType;
            });

        } else {
            console.log('Whitelist mode: DISABLED. Enabling DOM scanner.');
            if (this.domScanner && !this.domScanner.observer) { // Check if observer is null
                 this.domScanner.setupObserver();
                 this.domScanner.performInitialTargetedScan(); // Re-scan if transitioning from whitelisted to not
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
                return true; // Indicates asynchronous response
            }
        });

        // Initial setup of the observer if not whitelisted
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
            totalMatchesInPatterns: this.patternService.metrics.matchCount, // From PatternService
            totalAnalyses: this.analysisCounter
        });
        this.metrics.analysisTime = []; // Reset for next batch
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
    
    // This is a specific check for inline scripts found by DomScanner, might be redundant if all checks go via patternService.analyze
    isSuspiciousScript(scriptContent) {
        return this.patternService.isSuspiciousScript(scriptContent);
    }
}

// Initialize the blocker
new HTMLSmugglingBlocker();
console.log("HTMLSmugglingBlocker initialized with new modular structure.");
