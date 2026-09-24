# PhishGuard Security Policy

## Threat Analysis Boundaries

PhishGuard is designed entirely around **static, offline, lexical analysis**. The system acts as a heuristic and statistical filter to assess structural risks within a URL string. 

It does **not** provide complete threat intelligence. Because it is strictly offline, it cannot account for:
- IP/Domain Reputation
- HTML/JavaScript content payloads
- Zero-day malware hosted at the destination
- Time-of-click redirection chains

## Offline Analysis Design

To ensure the safety of the user and the system, PhishGuard strictly enforces the following rules:
- **No HTTP/HTTPS Requests**: The system will never intentionally visit, request, or download content from the submitted URL.
- **No DNS/WHOIS**: The system does not attempt to resolve the domain to an IP address or look up registration details.
- **No Scraping**: No automated browsers or scrapers are utilized.

This architecture ensures that PhishGuard can safely analyze URLs targeting internal infrastructure or highly malicious command-and-control servers without accidentally tipping off threat actors or compromising the host machine.

## Responsible Use Statement

PhishGuard is a portfolio project designed to demonstrate the integration of machine learning and explainable cybersecurity heuristics. 
- It is **not** a production-grade enterprise security appliance.
- It should **not** be relied upon as the sole line of defense for critical infrastructure or personal security.
- The probabilistic outputs and heuristic scores are decision-support tools, not definitive proof of a URL's safety or malicious intent.

## Vulnerability Reporting

*(TODO: Add vulnerability reporting instructions or email placeholder if this repository accepts external security reports.)*
