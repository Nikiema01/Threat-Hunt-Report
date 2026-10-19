# Threat Hunt Report: ECHOLEAK

**Author:** Fabrice Nikiema  
**Report date:** 19 October 2026  
**Incident date:** 20 September 2026  
**Organisation:** Cormorant Capital Partners

## Platforms and Tools Used

- **Platform:** Microsoft Sentinel and Microsoft 365 E5 with Copilot
- **Workspace:** `LAW-HuntPractice`
- **Language:** Kusto Query Language (KQL)
- **Tables:** `OfficeActivity_CL`, `CopilotAudit_CL`, `EntraSignIn_CL`
- **RunId:** `el--17-20260920`
- **Window:** 09:00 to 11:00 UTC on 20 September 2026
- **Identities:** `emily.chen@cormorantcapital.com`, `mark.ross@cormorantcapital.com`

## Scenario Summary

A financial analyst received an external quarterly report and asked Copilot to summarise it. Copilot then searched for unrelated sensitive documents, read 13 files and generated responses containing external image URLs with Base64 encoded identifiers. The hunt supports indirect prompt injection and an attempted exfiltration channel through generated content. Successful external delivery and full data loss remain unconfirmed.

## Investigation Notes

This training case is organised into 17 findings. Their numbers are report navigation, not a verified mapping to the lab’s flag numbering. Findings cite retained CSVs or explicitly identify earlier hunt observations. Queries are reusable investigation queries; they do not claim new execution. CSV timestamps display Eastern time and are reported below in UTC by adding four hours. Preserve original records because the OriginalTime field is invalid in some exports.

## Finding Analysis and Results

### Finding 1 — External email sender

**Answer:** quarterly.reports@globalfinancereview.net

**Discovery:** The delivery screenshot identifies an email delivered to Emily at 09:15:22 UTC. Its subject was Q3 2026 Global Markets Review - For Your Analysis. Preserve the original email audit results alongside this report; the retained CSV set does not contain that delivery row.

**Investigation query:**

```kql
OfficeActivity_CL
| where RunId == "el--17-20260920"
| where TimeGenerated between
    (datetime(2026-09-20T09:00:00Z) .. datetime(2026-09-20T11:00:00Z))
| where UserId =~ "emily.chen@cormorantcapital.com"
| where isnotempty(SenderAddress)
| project TimeGenerated, Operation, SenderAddress, Subject, AttachmentNames
| order by TimeGenerated asc
```

![External email delivery](images/01-email-delivery.png)

*Figure 1. The expanded MessageReceived row shows the sender, subject, attachment and 05:15:22 Eastern timestamp, equivalent to 09:15:22 UTC.*

---

### Finding 2 — Suspected poisoned attachment

**Answer:** Q3-2026-Global-Markets-Review.docx

**Discovery:** The report appeared to be a routine quarterly market review. It is the suspected entry point for malicious instructions. The exact injected document text is not included in the retained exports.

**Investigation query:**

```kql
OfficeActivity_CL
| where RunId == "el--17-20260920"
| where TimeGenerated between
    (datetime(2026-09-20T09:00:00Z) .. datetime(2026-09-20T11:00:00Z))
| where tostring(AttachmentNames) contains "Global-Markets-Review"
| project TimeGenerated, UserId, SenderAddress, Subject, AttachmentNames
```

---

### Finding 3 — Document access and activation gap

**Answer:** 10:42:08 UTC; 1 hour 26 minutes 46 seconds after delivery

**Discovery:** The report access screenshot records Emily opening the report before the Copilot invocation. The delay supports activation when the report was processed rather than immediate execution on email receipt. Screenshots below substantiate both timestamps; retain the original exports for a complete evidence record.

**Investigation query:**

```kql
OfficeActivity_CL
| where RunId == "el--17-20260920"
| where TimeGenerated between
    (datetime(2026-09-20T09:00:00Z) .. datetime(2026-09-20T11:00:00Z))
| where UserId =~ "emily.chen@cormorantcapital.com"
| where OfficeObjectId contains "Q3-2026-Global-Markets-Review"
| project TimeGenerated, Operation, OfficeObjectId
| order by TimeGenerated asc
```

![Report access](images/02-report-access.png)

*Figure 2. The FileAccessed record identifies the quarterly report and shows 06:42:08 Eastern, equivalent to 10:42:08 UTC.*

---

### Finding 4 — Legitimate user request

**Answer:** Summarise the key findings of this quarterly report

**Discovery:** The Copilot prompt screenshot records this Word prompt at 10:42:35 UTC. It requested a summary, not searches across HR, executive or client files.

**Investigation query:**

```kql
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where TimeGenerated between
    (datetime(2026-09-20T09:00:00Z) .. datetime(2026-09-20T11:00:00Z))
| where SessionId == "cp-emily-20261007-1042"
| where isnotempty(UserPrompt)
| project TimeGenerated, UserId, Application, UserPrompt
```

![Legitimate Copilot prompt](images/03-user-prompt.png)

*Figure 3. The prompt asks for a summary of the quarterly report. The source document, Word application and session identifier are visible.*

---

### Finding 5 — Anomalous Copilot session

**Answer:** cp-emily-20261007-1042

**Discovery:** Use this exact session identifier to correlate interactions. The embedded October date is inconsistent with the September event date; treat the identifier as an opaque value. The exported event timestamps and RunId define scope.

**Investigation query:**

```kql
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where TimeGenerated between
    (datetime(2026-09-20T09:00:00Z) .. datetime(2026-09-20T11:00:00Z))
| where SessionId == "cp-emily-20261007-1042"
| project TimeGenerated, InteractionType, ToolName, ToolParameters
| order by TimeGenerated asc
```

---

### Finding 6 — Initial targeted searches

**Answer:** board minutes confidential; M&A acquisition target; salary review confidential

**Discovery:** New query-17.csv records three Graph.SearchFiles calls at 10:42:41, 10:42:43 and 10:42:45 UTC. All searched site:cormorantcapital.sharepoint.com. Their subject matter exceeds the summary request.

**Investigation query:**

```kql
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where TimeGenerated between
    (datetime(2026-09-20T09:00:00Z) .. datetime(2026-09-20T11:00:00Z))
| where SessionId == "cp-emily-20261007-1042"
| where ToolName == "Graph.SearchFiles"
| extend SearchTerm=tostring(ToolParameters.query)
| project TimeGenerated, InteractionType, SearchTerm, ToolParameters
| order by TimeGenerated asc
```

![Targeted Graph search](images/04-targeted-search.png)

*Figure 4. Graph.SearchFiles searches for board minutes confidential in the same session, beyond the requested summary.*

---

### Finding 7 — Initial sensitive file burst

**Answer:** Five files between 10:42:47 and 10:42:55 UTC

**Discovery:** New query-18.csv confirms five successful FileAccessed events matching the initial Graph.ReadFile calls. The exported interval is eight seconds; the briefing describes six. The briefing also calls these first-time accesses, which requires historical access data to validate independently.

**Investigation query:**

```kql
OfficeActivity_CL
| where RunId == "el--17-20260920"
| where TimeGenerated between
    (datetime(2026-09-20T09:00:00Z) .. datetime(2026-09-20T11:00:00Z))
| where UserId =~ "emily.chen@cormorantcapital.com"
| where Operation == "FileAccessed"
| where TimeGenerated between
    (datetime(2026-09-20T10:42:47Z) .. datetime(2026-09-20T10:42:55Z))
| project TimeGenerated, SourceFileName, OfficeObjectId, ResultStatus
| order by TimeGenerated asc
```

![Sensitive file access results](images/05-file-access-burst.png)

*Figure 5. Five results are returned. The expanded successful record identifies Board Meeting Minutes - October 2026.docx. Full exported timestamps establish the eight second interval.*

---

### Finding 8 — Graph file retrieval

**Answer:** 13 Graph.ReadFile records

**Discovery:** New query-17.csv shows five initial reads and eight later reads across Executive, Finance, HR and IT. Only the first five have matching OfficeActivity records in the retained Office CSV. The complete file inventory appears below.

**Investigation query:**

```kql
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where TimeGenerated between
    (datetime(2026-09-20T09:00:00Z) .. datetime(2026-09-20T11:00:00Z))
| where SessionId == "cp-emily-20261007-1042"
| where ToolName == "Graph.ReadFile"
| project TimeGenerated, ToolParameters
| order by TimeGenerated asc
```

---

### Finding 9 — External destination

**Answer:** metrics-cdn.analyticshub.io

**Discovery:** Three exported Copilot responses contain Markdown image references to the external destination. The URL path is /img and the parameters include d and s. An external hostname in output is an indicator; it is not itself proof that a network request completed.

**Investigation query:**

```kql
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where TimeGenerated between
    (datetime(2026-09-20T09:00:00Z) .. datetime(2026-09-20T11:00:00Z))
| where SessionId == "cp-emily-20261007-1042"
| where CopilotResponse contains "metrics-cdn.analyticshub.io"
| project TimeGenerated, CopilotResponse
| order by TimeGenerated asc
```

![Copilot response with image references](images/06-copilot-response.png)

*Figure 6. The response includes a market summary and four Markdown image references. The UI truncates the URLs; New query-19.csv supplies their complete values.*

---

### Finding 10 — Encoded image channel

**Answer:** Base64 encoded identifiers in image URL query parameters

**Discovery:** At 10:43:08 UTC, a plausible market summary included four image URLs. Decoding their d values yields document names. Loading these images would send URL parameters to the receiving service. A cloud proxy could perform the request; endpoint-only visibility may miss that path. The exported payloads do not demonstrate full document contents.

**Investigation query:**

```kql
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where TimeGenerated between
    (datetime(2026-09-20T09:00:00Z) .. datetime(2026-09-20T11:00:00Z))
| where SessionId == "cp-emily-20261007-1042"
| where CopilotResponse contains "metrics-cdn.analyticshub.io"
| extend EncodedValues=extract_all(@"[?&]d=([^&\s)]+)", CopilotResponse)
| mv-expand EncodedValues
| extend DecodedValue=base64_decode_tostring(tostring(EncodedValues))
| project TimeGenerated, EncodedValues, DecodedValue
```

---

### Finding 11 — Configuration disclosed in output

**Answer:** System prompt and enterprise configuration text at 10:44:19 UTC

**Discovery:** The response includes sensitivity labels, classification and DLP policy strings, permitted data sources and department names. The image marker decodes to system_prompt_cormorant_capital. The text access_scope: Global Reader is not independent proof of an actual tenant role or a configuration change.

**Investigation query:**

```kql
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where TimeGenerated between
    (datetime(2026-09-20T09:00:00Z) .. datetime(2026-09-20T11:00:00Z))
| where SessionId == "cp-emily-20261007-1042"
| where CopilotResponse contains "System configuration extracted"
| project TimeGenerated, CopilotResponse
```

---

### Finding 12 — Normal session comparison

**Answer:** Graph activity; unrelated file burst; external encoded image URLs

**Discovery:** New query-20.csv contains a 35-session aggregate. Other sampled sessions have zero ToolCall records and show ordinary editing or summaries. Legitimate chart responses use the internal SharePoint chart endpoint. Zero ToolCall counts do not exclude Search category events.

**Investigation query:**

```kql
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where TimeGenerated between
    (datetime(2026-09-20T09:00:00Z) .. datetime(2026-09-20T11:00:00Z))
| summarize ToolCallRows=countif(InteractionType == "ToolCall"),
    SearchRows=countif(InteractionType == "Search"),
    ToolBearingRows=countif(isnotempty(ToolName)),
    ExternalResponses=countif(CopilotResponse contains "metrics-cdn.analyticshub.io")
    by UserId, SessionId
| order by ToolBearingRows desc
```

---

### Finding 13 — Broader sensitive searches

**Answer:** confidential; restricted; board; acquisition; salary

**Discovery:** New query-21.csv records five Graph.SearchFiles events between 10:45:30 and 10:45:45 UTC. These are labelled InteractionType Search. Filtering only ToolCall would miss this phase.

**Investigation query:**

```kql
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where TimeGenerated between
    (datetime(2026-09-20T09:00:00Z) .. datetime(2026-09-20T11:00:00Z))
| where SessionId == "cp-emily-20261007-1042"
| where InteractionType == "Search"
| project TimeGenerated, ToolName, ToolParameters
| order by TimeGenerated asc
```

![Expanded sensitive searches](images/07-expanded-searches.png)

*Figure 7. Five Search category records are returned. The expanded row shows the confidential query; other visible rows include restricted, board and acquisition. The CSV includes salary.*

---

### Finding 14 — Expanded retrieval and event counts

**Answer:** Eight additional reads; 13 reads and eight searches overall

**Discovery:** The later reads run from 10:45:46 to 10:46:26 UTC, followed by eight external image references at 10:46:35. Across the two tool exports, there are 21 tool-bearing records: 16 in the ToolCall export plus five Search rows.

**Investigation query:**

```kql
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where TimeGenerated between
    (datetime(2026-09-20T09:00:00Z) .. datetime(2026-09-20T11:00:00Z))
| where SessionId == "cp-emily-20261007-1042"
| where isnotempty(ToolName)
| summarize Events=count() by InteractionType, ToolName
| order by ToolName asc
```

---

### Finding 15 — Visibility limitation

**Answer:** Full data loss and successful external delivery are unconfirmed

**Discovery:** The retained records establish retrieval activity, configuration text in output and encoded identifiers in external image references. They do not provide complete Graph response bodies, successful HTTP fetches, exact byte counts or the full injected instructions. Network or service proxy evidence is needed to establish delivery.

---

### Finding 16 — Authentication and configuration alternatives

**Answer:** No account or configuration compromise demonstrated by the retained exports

**Discovery:** The briefing reports no sign-in anomalies. An EntraSignIn_CL result export and a configuration-change audit export are still needed to independently evaluate the alternatives. Exposure of configuration text does not establish tampering. Inspect the sign-in schema and inventory Office operations before applying specific filters.

**Investigation query:**

```kql
EntraSignIn_CL
| where RunId == "el--17-20260920"
| where TimeGenerated between
    (datetime(2026-09-20T09:00:00Z) .. datetime(2026-09-20T11:00:00Z))
| order by TimeGenerated asc

// Run separately to inventory configuration-related operations
OfficeActivity_CL
| where RunId == "el--17-20260920"
| where TimeGenerated between
    (datetime(2026-09-20T09:00:00Z) .. datetime(2026-09-20T11:00:00Z))
| summarize Events=count() by OfficeWorkload, Operation
| order by OfficeWorkload asc, Operation asc
```

---

### Finding 17 — Incident classification

**Answer:** External input manipulation through indirect prompt injection

**Discovery:** The strongest explanation is an untrusted report influencing Copilot to act outside the user’s request through its legitimate data access workflow. Sensitive retrieval and generated external image references support attempted exfiltration. Successful transfer is unconfirmed. The lab briefing associates this pattern with CVE-2025-32711; no production version or patch state was verified.

---

## Accessed File Inventory

| UTC time | SharePoint site | File |
|---|---|---|
| 10:42:47 | Executive | Board Meeting Minutes - October 2026.docx |
| 10:42:49 | Executive | Project Falcon - M&A Target Assessment.xlsx |
| 10:42:51 | HR | Salary Review FY2027 - Executive Summary.pdf |
| 10:42:53 | Finance | Client Portfolio - Henderson Family Office.xlsx |
| 10:42:55 | IT | Copilot System Configuration - Cormorant.json |
| 10:45:46 | Finance | Compliance Audit Results - H2 2026.xlsx |
| 10:45:54 | Finance | Restricted Client List - Internal Only.docx |
| 10:45:59 | Finance | Board Resolution - Emergency Session.pdf |
| 10:46:05 | Finance | Acquisition Pipeline - Q4 2026.xlsx |
| 10:46:07 | HR | Executive Salary Benchmarking 2027.pdf |
| 10:46:13 | HR | Confidential Investigation - Insider Trading.docx |
| 10:46:18 | Executive | Board Committee Minutes - Audit Committee.docx |
| 10:46:26 | Executive | Quarterly Revenue Report - Restricted Distribution.xlsx |

## Summary Table

| Finding | Description | Result |
|---|---|---|
| 1 | External email sender | quarterly.reports@globalfinancereview.net |
| 2 | Suspected poisoned attachment | Q3-2026-Global-Markets-Review.docx |
| 3 | Document access and activation gap | 10:42:08 UTC; 1 hour 26 minutes 46 seconds after delivery |
| 4 | Legitimate user request | Summarise the key findings of this quarterly report |
| 5 | Anomalous Copilot session | cp-emily-20261007-1042 |
| 6 | Initial targeted searches | board minutes confidential; M&A acquisition target; salary review confidential |
| 7 | Initial sensitive file burst | Five files between 10:42:47 and 10:42:55 UTC |
| 8 | Graph file retrieval | 13 Graph.ReadFile records |
| 9 | External destination | metrics-cdn.analyticshub.io |
| 10 | Encoded image channel | Base64 encoded identifiers in image URL query parameters |
| 11 | Configuration disclosed in output | System prompt and enterprise configuration text at 10:44:19 UTC |
| 12 | Normal session comparison | Graph activity; unrelated file burst; external encoded image URLs |
| 13 | Broader sensitive searches | confidential; restricted; board; acquisition; salary |
| 14 | Expanded retrieval and event counts | Eight additional reads; 13 reads and eight searches overall |
| 15 | Visibility limitation | Full data loss and successful external delivery are unconfirmed |
| 16 | Authentication and configuration alternatives | No account or configuration compromise demonstrated by the retained exports |
| 17 | Incident classification | External input manipulation through indirect prompt injection |

## Recommended Response Actions

- Quarantine the source email and report; preserve the attachment and complete Copilot session.
- Investigate the external domain using cloud service or proxy request records to confirm delivery.
- Review access permissions for the affected SharePoint sites and assess exposure with data owners.
- Collect sign-in and configuration audit results before closing those alternative explanations.
- Verify applicable Copilot protections and supported controls for external resource rendering.
- Revoke sessions or reset credentials if authentication evidence warrants those actions.

These are recommendations. No containment or tenant changes were performed as part of the documented hunt.

## Lessons Learned

- A legitimate user request can expose an assistant to malicious instructions embedded in retrieved content.
- User identity in a file audit does not by itself explain whether the user or an assistant initiated the access.
- Correlating Copilot interactions with Office audit events explains the gap between delivery and file access.
- Count tool activity across interaction categories; a ToolCall-only filter missed five searches.
- Base64 is encoding, not encryption. Decode preserved strings locally without fetching suspicious URLs.
- Distinguish generated exfiltration references from successful delivery and confirmed data loss.
