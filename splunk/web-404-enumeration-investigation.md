# Web 404 Enumeration Investigation

## Objective

Investigate a client IP generating a large number of HTTP 404 (Not Found) responses and determine whether the activity may indicate web enumeration or scanning.

## Dataset

Splunk tutorialdata, sourcetype=access_combined_wcookie

## Investigation Steps

1. Identified client IPs generating HTTP 404 responses.
2. Ranked client IPs by the number of 404 events.
3. Selected the most active client IP for further investigation.
4. Reviewed requested URIs associated with the suspicious client.
5. Assessed whether the activity was consistent with web enumeration behavior.

## Investigation Queries

### Query 1 – Identify Top 404 Sources

```spl
index=main sourcetype=access_combined_wcookie status=404
| stats count by clientip
| sort - count
```

Purpose: Identify client IPs responsible for the highest number of HTTP 404 responses.

### Query 2 – Analyze Requested URIs

```spl
index=main sourcetype=access_combined_wcookie status=404 clientip="87.194.216.51"
| stats count by uri
| sort - count
```

Purpose: Determine which resources were repeatedly requested by the client.

## Findings

* Client IP: 87.194.216.51
* Generated a large number of HTTP 404 responses.
* Frequently requested missing resources including:

  * /hidden/anna_nicole.html
  * /numa/numa.html
  * /passwords.pdf
  * /rush/signals.zip
  * /stuff/logo.ico
* Multiple requests targeted resources that were not available on the server.

## SOC Analyst Conclusion

The client generated a significant number of requests resulting in HTTP 404 responses.

The activity may indicate automated browsing, web crawling, broken links, or potential reconnaissance activity. Additional investigation is required before classifying the activity as malicious.

## Recommendations

* Monitor the client IP for additional suspicious behavior.
* Review successful requests (HTTP 200 responses) from the same IP.
* Correlate activity with other web logs and authentication events.
* Investigate whether similar URI requests were observed from other client IPs.

```
```
