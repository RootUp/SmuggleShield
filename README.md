# SmuggleShield
***Stable Version (2.0)***

[![CodeQL Advanced](https://github.com/RootUp/SmuggleShield/actions/workflows/codeql.yml/badge.svg)](https://github.com/RootUp/SmuggleShield/actions/workflows/codeql.yml)

SmuggleShield is a browser extension that aims to prevent **basic** HTML smuggling attacks by detecting common patterns. While this is not a comprehensive or bulletproof solution, it is an attempt to provide an additional layer of security during browsing or during your red/puprle team exercise.

The extension is compatible both on Chrome and Edge for Mac and Windows OS. Enable developer mode under extension settings and click on "Load unpacked" in the "**SumggleSheild**" folder. The extension would be up and running. Blocked URLs are stored in extension cache up to 10 days with blocked pattern, URL, and timestamp, which can be reviewed by clicking on extension then "**Export Blocked Content Logs**.". 

## Machine Learning Integration

First, the `HTMLSmugglingBlocker` analyzes webpage content and combines both pattern-based detection and ML-based analysis. The MLDetector then extracts six key features (`base64Length`, `blobUsage`, `downloadAttr`, `scriptDensity`, `encodingFunctions`, `binaryManipulation`) and makes predictions using a **0.75** confidence threshold. Then its a continuous learning loop where the `MLMonitor` tracks performance metrics and feeds results back to improve detection accuracy, with all learned patterns persisted in `chrome.storage.local` for adaptation to new threats.

![SmuggleShield-ML](https://github.com/user-attachments/assets/043b9f32-b28f-437f-a7c6-1f59e705dc22)

## Incognito Mode Support
SmuggleShield can protect against HTML smuggling attempts in incognito mode, but requires manual activation. To enable incognito protection: open Chrome's extension management page (`chrome://extensions/`), click "**Details**" on SmuggleShield, and toggle "**Allow in incognito**". Note: This setting is disabled by default as per Chrome's security policy. When enabled, the extension will maintain separate states for normal and incognito sessions to preserve privacy, while providing the same level of protection against HTML smuggling attempts in both modes.

## **Install from Chrome Web Store**
- [SmuggleShield](https://chromewebstore.google.com/detail/SmuggleShield/lglilndcogcapdkpfllcdlopgffbepce) - Currently, the GH version of this extension is more better than the one published on Chrome webstore.

![SmuggleShield_POC](https://github.com/user-attachments/assets/c8602882-cd1b-48fb-9512-642993aadf88)
[Watch on Youtube](https://youtu.be/6x0Fe_63qxA)

I have taken multiple code references from StackOverflow/Github and file smuggling samples from delivr[dot]to. Hence, special thanks to them!

## **Privacy Policy**
- [Privacy Policy for SmuggleShield](https://www.inputzero.io/p/smuggelsheild.html)

## **SmuggleShield could have prevented**

- [Quakbot- 14072022](https://github.com/0xToxin/Malware-IOCs/blob/main/Quakbot/Quakbot-%2014072022)
- [Pikabot | TA577 | 1.1.15-ghost](https://github.com/pr0xylife/Pikabot/blob/main/Pikabot_01.11.2023.txt)
- [A malspam campaign delivering AsyncRAT](https://x.com/RandomDhiraj/status/1854182495337476211)
- [HTML smuggling is delivering DCRat malware, bypassing traditional security controls by embedding malicious payloads in HTML files. This advanced technique poses a global threat to unsuspecting users](https://x.com/RandomDhiraj/status/1839717748970021027)

