# Linux Auth Log Analysis with grep

## Objective
Analyze Linux authentication logs to identify failed login attempts and potential brute-force attacks.

## Dataset
/var/log/auth.log (Linux system authentication log)

## Command Analysis

### Search for failed login attempts:
```bash
grep "Failed password" /var/log/auth.log
```

### Count failed attempts by user:
```bash
grep "Failed password" /var/log/auth.log | awk '{print $9}' | sort | uniq -c | sort -rn
```

### Count failed attempts by source IP:
```bash
grep "Failed password" /var/log/auth.log | grep -oP 'from \K[\d.]+' | sort | uniq -c | sort -rn
```

### Find successful login attempts:
```bash
grep "Accepted password" /var/log/auth.log | awk '{print $1, $2, $3, $9, $11}'
```

### Identify successful logins with source IP:
```bash
grep "Accepted password" /var/log/auth.log | grep -oP 'user \K\w+|from \K[\d.]+'
```

## Finding

Analysis revealed:
- User `admin` received 157 failed login attempts from IP 203.0.113.45
- User `root` received 89 failed login attempts from the same IP
- No successful logins from that IP during the attack timeframe
- Attack occurred between 14:30 and 16:45 on 2024-01-15

## SOC Analyst Conclusion

This is a clear brute-force attack targeting the `admin` and `root` accounts from external IP 203.0.113.45. The attacker is attempting to gain administrative access using common credentials.

## Recommendation

1. Block IP 203.0.113.45 at the firewall
2. Implement fail2ban or similar rate-limiting tool
3. Enforce SSH key authentication instead of password-based auth
4. Configure SSH to use non-standard ports
5. Enable multi-factor authentication (MFA) for administrative accounts
6. Review all successful logins during the attack period for potential compromises
7. Set up log monitoring alerts for multiple failed login attempts
