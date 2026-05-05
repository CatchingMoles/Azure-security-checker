In an era of increasing regulatory pressure and cyber threats, Catching Moles provides a non-intrusive, high-impact security assessment of your Azure environment. It is designed to find the "moles" (vulnerabilities) before they can be exploited, without the need for permanent access or sensitive data exposure.


Why CatchingMoles?

    Privacy-First (Zero-Crypto): Our proprietary architecture ensures that no sensitive data (no names, no emails, no IP addresses) ever leaves your Azure environment. All findings are anonymized using random identifiers. So even if CatchingMoles ever gets hacked, your sensitive data will not be leaked.

    Regulatory Alignment: The scan evaluates your posture against international standards such as NIS2, ISO 27001, and the Microsoft Cloud Security Benchmark.  

    Cost & Surface Optimization: Beyond security, we identify "Orphaned Resources"—unused assets that increase your attack surface and waste your budget.  

    Fast & Non-Intrusive: The scan runs in minutes directly within your own secure Azure environment. No software installation is required.  

🛠️ For the Engineer: Technical Deep-Dive

Catching Moles is a modular PowerShell-based auditor that performs a deep inspection of Azure resources against the OWASP Top 10 and cloud best practices.  
Core Audit Modules

    Identity & Access (RBAC): Detects "Owner Sprawl," wildcard assignments, and privileged Service Principals.  

    Network Perimeter: Scans for open management ports (RDP/SSH), database exposure, and orphaned Public IPs.  

    Security Posture (CSPM): Integrates with Microsoft Defender for Cloud to extract real-time compliance scores and unhealthy assessments.  

    Resource Hardening: Deep checks for Storage Accounts (TLS/Public Access), SQL Servers (AD Auth/Auditing), and Key Vaults (Purge Protection/Soft Delete).  

    Monitoring (OWASP A09): Validates Diagnostic Settings and log retention compliance (GDPR/NIS2).  

Data Architecture

The auditor generates two distinct outputs locally:  

    Client_Secret_Mapping.csv (Confidential): Stays with you. Maps the random identifiers back to your real resource names.  

    Transmit_Payload.json (Anonymous): Safe for external analysis. Contains only the technical findings and random IDs.  

🚀 Quick Start

Run the compiled release directly from the Azure Cloud Shell (PowerShell) to perform a full tenant-wide audit.
PowerShell

# Run the release build with reporting capabilities and forward secured information to your function app in .json format
```& ([scriptblock]::Create((irm 'https://raw.githubusercontent.com/CatchingMoles/Azure-security-checker/main/CatchingMoles-Release.ps1'))) -FunctionUrl "https://yourfunction..."```

Requirements

    Permissions: Reader access (at minimum) on the target Subscriptions. Global reader role is adviced 

    Modules: Requires the Az PowerShell module (Pre-installed in Cloud Shell).  

Using the Azure Cloud Shell? Please remember you can download the .csv's using the manage files button: <img width="919" height="119" alt="afbeelding" src="https://github.com/user-attachments/assets/07658e3b-b587-4f67-9b76-c45ff9118152" />


Interested in the full analytical report?
The raw scan provides JSON data. For a professional, board-ready PDF report including executive summaries and prioritized action plans, visit CatchingMoles.com.
