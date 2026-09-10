# Active Directory Detection & SIEM Monitoring Lab

A hands-on cybersecurity lab focused on Active Directory security monitoring, Windows authentication telemetry, Splunk SIEM, and detection engineering.

This project demonstrates the workflow of simulating suspicious authentication activity, collecting Windows Security logs, analyzing authentication patterns, developing SPL-based detection logic, and configuring SIEM alerting.

## Project Overview

The lab was built as an isolated security monitoring environment consisting of:

- Windows Server acting as an Active Directory Domain Controller
- Windows 10 client joined to the domain
- Splunk Enterprise for centralized log collection and analysis
- Splunk Universal Forwarder for forwarding Windows event logs
- Controlled authentication attack simulation

The primary detection scenario implemented in this project is **password spraying**.

## Architecture

![Lab Architecture](architecture/lab-architecture.png)

### Environment

| Component | Role | IP Address |
|---|---|---|
| Windows Server | Active Directory Domain Controller | `192.168.10.10` |
| Windows 10 | Domain-joined client / attack simulation host | `192.168.10.20` |
| Splunk Enterprise | SIEM / log analysis | `192.168.10.6` |

**Domain:** `soc.lab`

## Detection Workflow

The project follows a basic detection-engineering workflow:

**Attack Simulation → Telemetry Generation → Log Collection → Event Analysis → Detection Logic → SIEM Alert**

### 1. Attack Simulation

Five controlled domain accounts were created for the simulation:

- `Spray01`
- `Spray02`
- `Spray03`
- `Spray04`
- `Spray05`

Controlled failed authentication attempts were generated against these accounts from the Windows 10 client.

The activity was performed only within the isolated lab environment.

### 2. Windows Security Telemetry

The authentication failures generated **Windows Security Event ID 4625**.

Event ID 4625 represents a failed logon attempt.

A single 4625 event does not automatically indicate password spraying. The detection depends on identifying a behavioral pattern across multiple authentication events.

### 3. Password Spray Pattern

Password spraying differs from traditional brute-force activity:

- **Password spraying:** one or a small number of passwords are attempted against multiple accounts.
- **Brute force:** many passwords are attempted against a single account.

In this lab, the observed pattern was multiple failed authentication attempts against distinct domain accounts originating from the same source.

### 4. Splunk Log Collection

Splunk Universal Forwarder was configured on the Windows systems to forward Windows Security telemetry to Splunk Enterprise.

The collected events were stored in the `endpoint` index.

Example search:

```spl
index=endpoint host="AD-Server" EventCode=4625
````

This search was used to identify failed authentication events generated on the Active Directory server.

## Password Spray Detection

The detection correlates failed authentication events within a 10-minute time window and counts the number of distinct accounts targeted by the same source.

```spl
index=endpoint host="AD-Server" EventCode=4625
| bin _time span=10m
| stats dc(Account_Name) as unique_accounts values(Account_Name) as accounts count by _time Source_Network_Address
| where unique_accounts >= 3
```

### Detection Logic

The rule:

1. Filters for Windows Event ID `4625`.
2. Groups events into 10-minute windows.
3. Groups activity by source network address.
4. Counts distinct targeted accounts.
5. Returns activity when at least three different accounts are affected.

The threshold of three accounts within ten minutes was selected for this small lab environment and is not intended as a production-ready threshold.

## SIEM Alerting

A scheduled Splunk alert was configured:

**Alert:** `Potential Password Spray - Multiple Accounts`

**Description:**

> Detects multiple failed authentication attempts against distinct Active Directory accounts from a single source within a 10-minute window.

The alert evaluates the detection query periodically and triggers when the correlation condition is met.

## Investigation

The investigation process involved moving from individual authentication events to a broader behavioral pattern.

Initial investigation:

```spl
index=endpoint host="AD-Server" EventCode=4625
```

Account-based analysis:

```spl
index=endpoint host="AD-Server" EventCode=4625
| stats count by Account_Name
```

Source-based correlation:

```spl
index=endpoint host="AD-Server" EventCode=4625
| stats dc(Account_Name) as unique_accounts count by Source_Network_Address
| sort - unique_accounts
```

The final correlation confirmed multiple distinct accounts being targeted from the same source within the defined time window.

## MITRE ATT&CK

The simulated behavior maps to:

**T1110.003 — Password Spraying**

The technique describes attempting commonly used passwords against multiple accounts rather than repeatedly attacking a single account.

## Evidence

Screenshots and supporting evidence are organized in the repository, including:

* Active Directory user configuration
* Network and domain validation
* Windows Security Event ID 4625
* Splunk event searches
* Account and source correlation
* Password spray detection results
* Splunk alert configuration

## Key Concepts Demonstrated

* Active Directory fundamentals
* Windows authentication telemetry
* Security Event ID 4625
* SIEM log collection
* Splunk SPL
* Event correlation
* Authentication attack detection
* Password spraying
* Detection engineering
* SIEM alert configuration
* Security investigation workflow


## Repository Structure


active-directory-detection-lab/
├── README.md
├── architecture/
│   └── lab-architecture.png
├── attacks/
│   └── password-spray.md
├── detections/
│   └── password-spray.spl
└── screenshots/
    ├── ad/
    ├── splunk/
    └── detection/


## Skills & Technologies

**Security:** Active Directory, Windows Security Events, Authentication Monitoring, Detection Engineering

**SIEM:** Splunk Enterprise, SPL, Log Correlation, Alerting

**Systems:** Windows Server, Windows 10, Windows Event Viewer

**Networking:** TCP/IP, DNS, Internal Lab Networking

**Framework:** MITRE ATT&CK
