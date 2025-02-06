# SmuggleShield
***Stable Version (2.0)***

[![CodeQL Advanced](https://github.com/RootUp/SmuggleShield/actions/workflows/codeql.yml/badge.svg)](https://github.com/RootUp/SmuggleShield/actions/workflows/codeql.yml) <br>
[![Install SmuggleShield](https://img.shields.io/badge/Chrome-Install_SmuggleShield-green?logo=google-chrome&logoColor=white)](https://chromewebstore.google.com/detail/SmuggleShield/lglilndcogcapdkpfllcdlopgffbepce)

SmuggleShield is a browser extension that aims to prevent **basic** HTML smuggling attacks by detecting common patterns. While this is not a comprehensive or bulletproof solution, it is an attempt to provide an additional layer of security during browsing or during your red/puprle team exercise.

The extension is compatible both on Chrome and Edge for Mac and Windows OS. Enable developer mode under extension settings and click on "Load unpacked" in the "SumggleSheild" folder. The extension would be up and running. Blocked URLs are stored in extension cache up to 10 days with blocked pattern, URL, and timestamp, which can be reviewed by clicking on extension then "Export Blocked Content Logs", the current stable version also has key fatures such as "URL Whitelisting" because sometimes SmuggleShield could take few seconds extra to load a page, it scans every elements of the webpage but with this key feature (URL Whitelisting) you can reduce the overhead 

## Extension Workflow

![SmuggleShield-Workflow](https://github.com/user-attachments/assets/a42d9f8d-3968-42c8-b0e8-a9507defa197)

## Machine Learning Integration & Workflow

First, the `HTMLSmugglingBlocker` analyzes webpage content and combines both pattern-based detection and ML-based analysis. The MLDetector then extracts six key features (`base64Length`, `blobUsage`, `downloadAttr`, `scriptDensity`, `encodingFunctions`, `binaryManipulation`) and makes predictions using a **0.75** confidence threshold. Then its a continuous learning loop where the `MLMonitor` tracks performance metrics and feeds results back to improve detection accuracy, with all learned patterns persisted in `chrome.storage.local` for adaptation to new threats.

![SmuggleShield-ML](https://github.com/user-attachments/assets/043b9f32-b28f-437f-a7c6-1f59e705dc22)

https://github.com/user-attachments/assets/8b8f1333-6a99-4979-bc17-56026a048ba8

## In Action

https://github.com/user-attachments/assets/8d97fdcf-b3d2-4ddb-a846-0900e333b7fe

## Incognito Mode Support
SmuggleShield can protect against HTML smuggling attempts in incognito mode, but requires manual activation. To enable incognito protection: open Chrome's extension management page (`chrome://extensions/`), click "**Details**" on SmuggleShield, and toggle "**Allow in incognito**". Note: This setting is disabled by default as per Chrome's security policy. When enabled, the extension will maintain separate states for normal and incognito sessions to preserve privacy, while providing the same level of protection against HTML smuggling attempts in both modes.

## SmuggleShield Could Have Prevented

| **Sr. No.** | **Details**                                | **Reference**                                                                                                                 |
|-------------|--------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------|
| 1           | Shuckworm                                  | [X (Twitter)](https://x.com/RandomDhiraj/status/1887387347387371528)                                                       |
| 2           | Quakbot campaign (14th July 2022)          | [GitHub](https://github.com/0xToxin/Malware-IOCs/blob/main/Quakbot/Quakbot-%2014072022)                                    |
| 3           | DCRat malware via HTML Smuggling           | [X (Twitter)](https://x.com/RandomDhiraj/status/1839717748970021027)                                                       |
| 4           | Pikabot (TA577, Version 1.1.15-ghost)      | [GitHub](https://github.com/pr0xylife/Pikabot/blob/main/Pikabot_01.11.2023.txt)                                            |
| 5           | AsyncRAT delivered via malspam campaign    | [X (Twitter)](https://x.com/RandomDhiraj/status/1854182495337476211)                                                       |

## Special Thanks
I have taken multiple code references from StackOverflow/Github and file smuggling samples from delivr[dot]to. Hence, special thanks to them!

## Privacy Policy
[Privacy Policy for SmuggleShield](https://www.inputzero.io/p/smuggelsheild.html)
