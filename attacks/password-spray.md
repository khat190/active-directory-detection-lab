# Password Spray Simulation

## Objective

Simulate controlled failed authentication activity against multiple Active Directory accounts and analyze the resulting Windows Security telemetry in Splunk.

The goal was to understand how password-spray behavior appears in Windows authentication logs and how that behavior can be converted into a SIEM detection.

## Lab Setup

The simulation was performed in an isolated Active Directory environment.

- Domain: `soc.lab`
- Active Directory Server: `192.168.10.10`
- Windows 10 Client: `192.168.10.20`
- Splunk Enterprise: `192.168.10.6`
- Test accounts: `Spray01` through `Spray05`

All accounts used for the simulation were created specifically for this lab.

## Attack Concept

Password spraying is an authentication attack in which an attacker attempts one or a small number of commonly used passwords against multiple accounts.

This differs from brute-force authentication, where many passwords are repeatedly attempted against a single account.

The distinguishing behavior investigated in this lab was:

**Multiple failed authentication attempts → Multiple distinct accounts → Common source**

## Simulation

Controlled failed authentication attempts were generated from the Windows 10 client against the test accounts in the `soc.lab` domain.

**The activity was intentionally performed against the five lab accounts:**

Spray01
Spray02
Spray03
Spray04
Spray05

The purpose was not to compromise an account, but to generate realistic failed-authentication telemetry for defensive analysis.

Windows Telemetry

The failed authentication activity generated:

Windows Security Event ID: 4625

Event ID 4625 represents a failed logon attempt.

**The events contained information such as:**

Target account
Account domain
Failure reason
Logon type
Workstation information
Source network address
Timestamp

**A single Event ID 4625 is not sufficient to identify password spraying. The detection depends on correlating multiple events and identifying the broader authentication pattern.**

**Splunk Analysis**

The Windows Security logs were forwarded to Splunk Enterprise using Splunk Universal Forwarder.

The events were stored in the endpoint index.

**Initial search:**

index=endpoint host="AD-Server" EventCode=4625

This allowed the failed authentication events to be examined in Splunk.

**Account Analysis**

To identify which accounts were targeted:
```text
index=endpoint host="AD-Server" EventCode=4625
| stats count by Account_Name
```
This showed failed authentication activity across the simulated accounts.

**Source Analysis**

The events were then correlated by source:
```text
index=endpoint host="AD-Server" EventCode=4625
| stats dc(Account_Name) as unique_accounts count by Source_Network_Address
| sort - unique_accounts
```
The analysis showed multiple distinct accounts being targeted from the same source.

**Detection**

The final detection correlated failed authentication events within a 10-minute window:
```text
index=endpoint host="AD-Server" EventCode=4625
| bin _time span=10m
| stats dc(Account_Name) as unique_accounts values(Account_Name) as accounts count by _time Source_Network_Address
| where unique_accounts >= 3
Detection Logic
```
**The detection:**

Filters for failed Windows authentication events.
Groups events into 10-minute windows.
Groups activity by source network address.
Counts distinct targeted accounts.
Flags activity when three or more distinct accounts are targeted.

The threshold was selected specifically for this small lab environment.

**Alert**

A scheduled Splunk alert was configured using the detection query.

Alert name:

Potential Password Spray - Multiple Accounts

**Description:**

Detects multiple failed authentication attempts against distinct Active Directory accounts from a single source within a 10-minute window.

The alert was configured to evaluate the detection periodically and trigger when matching activity was found.

**Result**

The simulation successfully generated Windows authentication telemetry that could be analyzed in Splunk.

The investigation progressed from individual failed-logon events to a correlated behavioral pattern involving:

Multiple failed authentication events
Multiple distinct domain accounts
A common source
Activity occurring within a defined time window

This provided the basis for the password-spray detection and SIEM alert.

MITRE ATT&CK Mapping
```text
T1110.003 — Password Spraying
```
The simulated behavior corresponds to the Password Spraying sub-technique under Brute Force.



**Ethical Scope
**
The simulation was conducted only against systems and accounts created for this lab.

No external systems, organizations, or user accounts were targeted.




**After that, next is `detections/password-spray.spl`** — that one is much shorter.
