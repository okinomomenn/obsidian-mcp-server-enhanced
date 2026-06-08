# Tailscale Security Configuration for MCP Server

This document outlines best practices for securing your MCP server when exposing it via Tailscale Funnel for use with Claude.ai's Remote MCP feature.

## Overview

When using Tailscale Funnel to expose your local MCP server to Claude.ai, you're creating a public HTTPS endpoint. While this enables powerful Claude.ai integration, it also increases your attack surface. This guide covers how to minimize risks.

## ⚠️ Errata (2026-06): Tailscale ACLs do NOT filter Funnel ingress

Earlier revisions of this document recommended using tailnet ACL `srcIPs`
rules to restrict who can reach a Funnel endpoint from the public internet.
**This does not work.** Funnel traffic is relayed from Tailscale's public
relay servers to your device; tailnet ACLs only govern device-to-device
traffic inside the tailnet. Funnel ingress bypasses ACLs entirely. The
feature to filter Funnel by client IP / ASN is an open request:
[tailscale/tailscale #13809](https://github.com/tailscale/tailscale/issues/13809)
(open, no Tailscale staff response as of 2026-06).

**Defence-in-depth for Funnel-exposed MCP servers must happen at the
application layer.** This server provides two options:

1. **OAuth 2.1 shim** (recommended for Claude.ai web/mobile).
   See [OAUTH_SHIM.md](./OAUTH_SHIM.md). Set `MCP_AUTH_MODE=oauth`.
2. **Legacy `?api_key=` query auth** (default). Useful for stdio / local /
   ChatGPT layer, but Claude.ai web does NOT pass `?api_key=` and will fail
   against this mode.

## Security Strategies

### 1. Application-layer authentication

Choose `MCP_AUTH_MODE`:
- `oauth` — runs the built-in OAuth 2.1 + DCR + PKCE shim. Required for
  Claude.ai web / mobile custom connectors.
- `legacy` — accepts `?api_key=<MCP_AUTH_KEY>` query parameter. Used by the
  ChatGPT layer and by local debugging clients.

See [OAUTH_SHIM.md](./OAUTH_SHIM.md) for OAuth mode setup.

### 2. Hybrid Access Strategy (Recommended)

Maintain separate access paths for different use cases:

#### Public Funnel for Claude.ai
- **Purpose**: Claude.ai Remote MCP access
- **URL**: `https://your-device.your-tailnet.ts.net/mcp`
- **Security**: API key authentication + ACLs
- **Access**: Restricted to Claude.ai IP ranges

#### Private Tailscale Access
- **Purpose**: Personal device access, debugging, administration
- **URL**: `http://your-device.your-tailnet.ts.net:3010/mcp`
- **Security**: Tailscale mesh network encryption
- **Access**: Only devices on your Tailscale network

### 3. Funnel Configuration Best Practices

#### Enable Funnel with Restrictions
```bash
# Enable funnel on specific port
tailscale funnel 3010

# Check funnel status and configuration
tailscale funnel status

# View active connections
tailscale status
```

#### Monitor Funnel Access
```bash
# View funnel logs
tailscale logs

# Monitor active sessions
tailscale status --peers
```

### 4. Additional Security Measures

#### Rate Limiting at Tailscale Level
- Configure connection limits in Tailscale admin console
- Set bandwidth restrictions for funnel traffic
- Enable DDoS protection features

#### Regular Security Audits
- Review Tailscale access logs monthly
- Monitor for unexpected IP addresses
- Audit API key usage patterns
- Check for unauthorized session creation

#### Network Segmentation
```json
{
  "acls": [
    {
      "action": "accept",
      "src": ["group:mcp-users"],
      "dst": ["your-device:3010"]
    },
    {
      "action": "deny",
      "src": ["*"],
      "dst": ["your-device:*"]
    }
  ]
}
```

### 5. Emergency Procedures

#### Disable Funnel Immediately
```bash
# Disable all funnels
tailscale funnel off

# Disable specific port
tailscale funnel --bg=false 3010
```

#### Rotate API Keys
1. Generate new Obsidian Local REST API key
2. Update MCP server configuration
3. Update Claude.ai integration settings
4. Verify old key no longer works

## Claude.ai IP Ranges

Claude.ai's IP ranges may change. Consult Anthropic's documentation for current ranges:
- Check Anthropic's official documentation
- Monitor network logs for Claude.ai connection patterns
- Use dynamic IP allowlisting if available

## Configuration Examples

### Development Setup
```bash
# Local development - no funnel
tailscale serve http://localhost:3010

# Access via: http://your-device.your-tailnet.ts.net
```

### Production Setup
```bash
# Secure funnel with monitoring
tailscale funnel --bg 3010
tailscale logs --follow
```

### Monitoring Script
```bash
#!/bin/bash
# Monitor funnel connections
while true; do
    echo "=== $(date) ==="
    tailscale status --peers | grep -E "(funnel|3010)"
    sleep 300
done
```

## Troubleshooting

### Common Issues
- **Connection Refused**: Check ACL configuration
- **Unauthorized Access**: Verify API key setup
- **Slow Responses**: Review rate limiting settings
- **Funnel Not Working**: Confirm Tailscale plan supports funnels

### Debug Commands
```bash
# Check funnel status
tailscale funnel status

# Test connectivity
curl -H "Authorization: your-api-key" https://your-device.your-tailnet.ts.net/mcp

# View detailed logs
tailscale logs --verbose
```

## Best Practices Summary

1. **Always use ACLs** to restrict funnel access
2. **Monitor access logs** regularly
3. **Rotate API keys** periodically
4. **Use hybrid access** for different use cases
5. **Test security measures** before deploying
6. **Have emergency procedures** ready
7. **Keep Tailscale updated** to latest version

## References

- [Tailscale Funnel Documentation](https://tailscale.com/kb/1223/tailscale-funnel/)
- [Tailscale ACL Documentation](https://tailscale.com/kb/1018/acls/)
- [Anthropic MCP Documentation](https://docs.anthropic.com/en/docs/build-with-claude/computer-use)