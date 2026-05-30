# SSH Brute Force Investigation in Splunk

## Objective
Investigate repeated failed SSH login attempts.

## Dataset
Splunk tutorialdata, sourcetype=www1/secure

## Investigation Steps

1. Identified authentication logs in the `www1/secure` sourcetype.
2. Searched for failed SSH password attempts.
3. Extracted source IP addresses using the `rex` command.
4. Counted failed login attempts by source IP.
5. Reviewed the most active IP addresses for suspicious behavior.

## SPL Search
```spl
index=main sourcetype=www1/secure "Failed password"
| rex "from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| stats count by src_ip
| sort - count
```

## Findings

- Multiple failed SSH login attempts were observed.
- Source IP: 194.8.74.23
- Target service: SSH
- Event type: Failed password authentication
- Pattern suggests possible brute-force activity.

## SOC Analyst Conclusion

This activity may indicate an SSH brute-force attack against the target system.

## Recommendation

- Monitor the source IP for future activity.
- Investigate whether any successful logins originated from the same IP.
- Review affected usernames and authentication logs.
- Consider blocking the IP if malicious activity is confirmed.
