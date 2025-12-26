#!/usr/bin/env python3
"""
Test script to verify Arjun integration for parameter discovery
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from web.advanced_scanner import discover_params
from core.plugin import run_tool

def test_arjun_basic():
    """Test basic Arjun execution"""
    print("=" * 60)
    print("TEST 1: Basic Arjun Tool Execution")
    print("=" * 60)
    
    result = run_tool("arjun", "https://httpbin.org/get", method="GET")
    
    print(f"Success: {result.success}")
    print(f"Tool: {result.tool_name}")
    print(f"Duration: {result.duration_seconds:.2f}s")
    print(f"Exit Code: {result.exit_code}")
    print(f"Parsed Data: {result.parsed_data}")
    print(f"Output (first 500 chars):\n{result.output[:500] if result.output else 'None'}")
    
    return result.success

def test_discover_params_function():
    """Test discover_params wrapper function"""
    print("\n" + "=" * 60)
    print("TEST 2: discover_params() Function")
    print("=" * 60)
    
    result = discover_params("https://httpbin.org/get", method="GET")
    
    print(f"Success: {result.get('success')}")
    print(f"URL: {result.get('url')}")
    print(f"Method: {result.get('method')}")
    print(f"Tool: {result.get('tool')}")
    print(f"Parameters Found: {result.get('parameters', [])}")
    print(f"Total Found: {result.get('total_found')}")
    print(f"Duration: {result.get('duration', 0):.2f}s")
    
    if not result.get('success'):
        print(f"Error: {result.get('error')}")
    
    return result.get('success', False)

def test_with_wordlist():
    """Test with custom wordlist"""
    print("\n" + "=" * 60)
    print("TEST 3: With Custom Wordlist (params_common)")
    print("=" * 60)
    
    result = discover_params(
        "https://httpbin.org/get",
        wordlist="params_common",
        method="GET"
    )
    
    print(f"Success: {result.get('success')}")
    print(f"Parameters Found: {result.get('parameters', [])}")
    print(f"Total Found: {result.get('total_found')}")
    
    if not result.get('success'):
        print(f"Error: {result.get('error')}")
    
    return result.get('success', False)

def main():
    print("\n🧪 Testing Arjun Integration for Parameter Discovery\n")
    
    # Check if Arjun is installed
    import shutil
    if not shutil.which("arjun"):
        print("⚠️  WARNING: Arjun is not installed!")
        print("Install with: pip install arjun")
        print("\nTests will likely fail, but running anyway...\n")
    else:
        print("✅ Arjun is installed\n")
    
    results = []
    
    try:
        results.append(("Basic Arjun Execution", test_arjun_basic()))
    except Exception as e:
        print(f"❌ Test 1 failed with exception: {e}")
        results.append(("Basic Arjun Execution", False))
    
    try:
        results.append(("discover_params Function", test_discover_params_function()))
    except Exception as e:
        print(f"❌ Test 2 failed with exception: {e}")
        results.append(("discover_params Function", False))
    
    try:
        results.append(("With Custom Wordlist", test_with_wordlist()))
    except Exception as e:
        print(f"❌ Test 3 failed with exception: {e}")
        results.append(("With Custom Wordlist", False))
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    for test_name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status} - {test_name}")
    
    total = len(results)
    passed = sum(1 for _, p in results if p)
    print(f"\nTotal: {passed}/{total} tests passed")
    
    return 0 if passed == total else 1

if __name__ == "__main__":
    sys.exit(main())
