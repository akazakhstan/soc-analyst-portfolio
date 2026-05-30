# SSH Brute Force Investigation in Splunk

## Objective
Investigate repeated failed SSH login attempts.

## Dataset
Splunk tutorialdata, sourcetype=www1/secure

## SPL Search
```spl
index=main sourcetype=www1/secure "Failed password"
| rex "from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| stats count by src_ip
| sort - count
```

## Finding

The IP 194.8.74.23 showed repeated failed login attempts.

## SOC Analyst Conclusion

This may indicate SSH brute-force activity.

## Recommendation

Block or monitor the IP, check for successful logins, and review affected usernames.
