# Brute Force Playbook

A Brute Force attack consists of an attacker submitting many passwords or passphrases with the hope of eventually guessing correctly.

## Recommended Remediation
1. **Block IP**: Immediately block the offending IP address at the firewall or WAF.
2. **Force Password Reset**: Invalidate current sessions and force the affected user(s) to reset their passwords.
3. **Enable MFA**: Require Multi-Factor Authentication for all user accounts.
4. **Rate Limiting**: Implement strict rate limits on login endpoints.
