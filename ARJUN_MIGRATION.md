# Arjun Integration - Parameter Discovery Migration

## Overview

The `discover_params` function has been migrated from a custom implementation to use **Arjun**, an industry-standard parameter discovery tool with advanced detection techniques.

## What Changed

### Before (Custom Implementation)
- Custom Python implementation with concurrent testing
- Fixed wordlist of 80 common parameters
- Simple detection based on response length and status code differences
- Built-in progress tracking

### After (Arjun Integration)
- Uses Arjun external tool
- Supports custom wordlists from SecLists
- Advanced detection techniques (headers, cookies, JSON, etc.)
- Industry-standard accuracy and reliability

## Installation

Ensure Arjun is installed:

```bash
pip install arjun
```

Or install from source:

```bash
git clone https://github.com/s0md3v/Arjun.git
cd Arjun
python setup.py install
```

## Usage

### 1. MCP Tool (Recommended)

```python
# Basic usage - uses Arjun's default wordlist
result = discover_params(
    url="https://example.com/api/endpoint",
    method="GET"
)

# With custom wordlist alias
result = discover_params(
    url="https://example.com/api/endpoint",
    method="POST",
    wordlist="params_common"  # Uses SecLists burp-parameter-names.txt
)

# With custom wordlist path
result = discover_params(
    url="https://example.com/api/endpoint",
    wordlist="/path/to/custom/params.txt"
)
```

### 2. Direct API Call

```bash
curl -X POST http://localhost:8888/api/scan/params \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com/api/endpoint",
    "method": "GET",
    "wordlist": "params_common"
  }'
```

### 3. Python Function

```python
from web.advanced_scanner import discover_params

result = discover_params(
    url="https://example.com/api/endpoint",
    wordlist="params_common",
    method="GET"
)

print(f"Found {result['total_found']} parameters:")
for param in result['parameters']:
    print(f"  - {param}")
```

## Response Format

```json
{
  "success": true,
  "url": "https://example.com/api/endpoint",
  "method": "GET",
  "found_params": [
    {"param": "id"},
    {"param": "user"},
    {"param": "token"}
  ],
  "total_found": 3,
  "parameters": ["id", "user", "token"],
  "duration": 12.5,
  "tool": "arjun",
  "raw_output": "Arjun output..."
}
```

## Available Wordlists

The following wordlist aliases are available in `config/wordlists.py`:

- **`params_common`** - Burp parameter names (6.4K entries) - **Recommended**
- Custom path - Any custom wordlist file path

## Arjun Plugin Configuration

The Arjun plugin automatically handles:

- ✅ Wordlist resolution (aliases → full paths)
- ✅ SECLISTS_PATH integration
- ✅ Multiple output format parsing (text, JSON)
- ✅ Method support (GET, POST)
- ✅ Custom arguments via `additional_args`

## Advanced Usage

### With Additional Arjun Arguments

```python
from core.plugin import run_tool

result = run_tool(
    "arjun",
    "https://example.com/api/endpoint",
    method="POST",
    wordlist="params_common",
    additional_args="--stable --passive"
)
```

### Arjun Command-Line Flags

Common flags you can pass via `additional_args`:

- `--stable` - Prefer stability over speed
- `--passive` - Passive mode (no active requests)
- `--include` - Include specific parameters
- `--exclude` - Exclude specific parameters
- `--headers` - Custom headers (JSON format)
- `--delay` - Delay between requests (seconds)

## Testing

Run the test script to verify the integration:

```bash
python test_arjun_integration.py
```

This will test:
1. Basic Arjun tool execution
2. `discover_params()` function wrapper
3. Custom wordlist integration

## Troubleshooting

### Arjun Not Found

```
Error: Arjun execution failed
```

**Solution**: Install Arjun
```bash
pip install arjun
```

### Wordlist Not Found

```
Error: Wordlist not found: params_common
```

**Solution**: Ensure SecLists is installed at `/usr/share/SecLists` or set `SECLISTS_PATH` environment variable:

```bash
export SECLISTS_PATH=/path/to/SecLists
```

### No Parameters Found

This is normal if:
- The endpoint doesn't accept additional parameters
- Parameters are well-hidden (try different wordlists)
- WAF/rate limiting is blocking requests

**Try**:
- Use `--stable` flag for better accuracy
- Use larger wordlist
- Add delay between requests: `--delay 1`

## Migration Notes

### Breaking Changes

1. **Wordlist parameter type changed**: `list` → `str`
   - Before: `wordlist=["id", "user", "token"]`
   - After: `wordlist="params_common"` or `wordlist="/path/to/list.txt"`

2. **Response format changed**:
   - `found_params` now contains `[{"param": "name"}]` instead of detailed objects
   - Added `parameters` field with simple list: `["param1", "param2"]`
   - Added `tool` field: `"arjun"`

### Backward Compatibility

The API endpoint remains the same:
- `POST /api/scan/params`
- Same request parameters
- Response structure enhanced but compatible

## Performance Comparison

| Metric | Custom Implementation | Arjun |
|--------|----------------------|-------|
| Speed | ⚡ Fast (10 concurrent) | 🐢 Slower (sequential) |
| Accuracy | ✅ Good | ✅✅ Excellent |
| Detection Methods | 1 (response diff) | 5+ (headers, cookies, etc.) |
| Wordlist Size | 80 params | Unlimited |
| Maintenance | ❌ Manual | ✅ Community |

## Best Practices

1. **Start with default wordlist** - Arjun's built-in list is well-tested
2. **Use `params_common` for thorough scans** - 6.4K parameters from Burp Suite
3. **Add delays for production targets** - Avoid rate limiting
4. **Use `--stable` flag** - Better accuracy, especially with WAFs
5. **Combine with other tools** - Use discovered params with SQLMap, XSS scanners, etc.

## Examples

### Bug Bounty Workflow

```python
# 1. Discover parameters
params_result = discover_params(
    url="https://target.com/api/user",
    wordlist="params_common",
    method="GET"
)

# 2. Test discovered parameters for vulnerabilities
for param in params_result['parameters']:
    # Test for SQL injection
    sqli_result = vuln_test(
        url=f"https://target.com/api/user?{param}=test",
        vuln_type="sqli"
    )
    
    # Test for XSS
    xss_result = vuln_test(
        url=f"https://target.com/api/user?{param}=test",
        vuln_type="xss"
    )
```

### API Testing

```python
# Discover API parameters
result = discover_params(
    url="https://api.example.com/v1/users",
    method="POST",
    wordlist="params_common"
)

# Generate IDOR test cases for discovered params
for param in result['parameters']:
    if param in ['id', 'user_id', 'account_id']:
        idor_tests = generate_access_tests(
            test_type="idor",
            value=param
        )
```

## References

- [Arjun GitHub](https://github.com/s0md3v/Arjun)
- [SecLists](https://github.com/danielmiessler/SecLists)
- [Burp Parameter Names](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/burp-parameter-names.txt)

## Support

For issues or questions:
1. Check Arjun installation: `arjun --help`
2. Verify SecLists path: `echo $SECLISTS_PATH`
3. Run test script: `python test_arjun_integration.py`
4. Check logs for detailed error messages
