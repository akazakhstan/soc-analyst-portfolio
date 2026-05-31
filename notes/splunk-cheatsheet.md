# Splunk Cheat Sheet

This file contains useful Splunk SPL commands for SOC analyst practice.

## Basic Search

```spl
index=main
```

## Find Sourcetypes

```spl
index=main
| stats count by sourcetype
| sort - count
```

## Failed SSH Logins
```spl
index=main sourcetype="www1/secure" "Failed password"
```

## Top Source IPs

```spl
index=main sourcetype="www1/secure" "Failed password"
| rex "(?<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
| stats count by src_ip
| sort - count
```

## Investigate Specific IP

```spl
index=main sourcetype="www1/secure" "Failed password"
| rex "(?<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
| search src_ip="87.194.216.51"
```

## Analyze Targeted Usernames

```spl
index=main sourcetype="www1/secure" "Failed password"
| rex "Failed password for (invalid user )?(?<target_user>\S+) from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| search src_ip="87.194.216.51"
| stats count by target_user
| sort - count
```
