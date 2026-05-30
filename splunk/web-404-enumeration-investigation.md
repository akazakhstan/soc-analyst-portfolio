# Web 404 Enumeration Investigation

## Objective
Investigate web server 404 errors to identify reconnaissance or enumeration attempts.

## Dataset
Splunk tutorialdata, sourcetype=access_combined

## SPL Search
```spl
index=main sourcetype=access_combined status=404
| rex "(?<requested_uri>\/\S+)"
| stats count by src_ip, requested_uri
| sort - count
```

## Finding

Multiple 404 errors detected from IP 192.168.1.5 requesting various URI paths including:
- `/admin`
- `/backup`
- `/config`
- `/wp-admin`
- `/phpmyadmin`

This pattern suggests directory enumeration or reconnaissance activity.

## SOC Analyst Conclusion

The attacker is systematically probing for common web application directories and admin panels. This is typical reconnaissance activity before an exploit attempt.

## Recommendation

1. Block or rate-limit the source IP 192.168.1.5
2. Enable Web Application Firewall (WAF) protection
3. Monitor for any successful access to sensitive directories
4. Review web server logs for related suspicious activity
5. Consider implementing CAPTCHA or IP-based access controls
