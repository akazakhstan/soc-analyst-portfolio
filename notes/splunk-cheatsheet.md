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

