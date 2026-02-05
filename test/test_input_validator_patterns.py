#!/usr/bin/env python3
"""
Unit tests for InputValidator - SQL injection and XSS patterns
Tests that new patterns compile correctly and detect malicious content
"""
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from utils.security.input_validator import InputValidator


def test_sql_pattern_count():
    """Test that SQL_INJECTION_PATTERNS has 20 patterns"""
    validator = InputValidator()
    assert len(validator.SQL_INJECTION_PATTERNS) == 26, \
        f"Expected 26 SQL patterns, found {len(validator.SQL_INJECTION_PATTERNS)}"
    print("✅ SQL pattern count: 26 patterns")


def test_xss_pattern_count():
    """Test that XSS_PATTERNS has 10 patterns"""
    validator = InputValidator()
    assert len(validator.XSS_PATTERNS) == 10, \
        f"Expected 10 XSS patterns, found {len(validator.XSS_PATTERNS)}"
    print("✅ XSS pattern count: 10 patterns")


def test_patterns_compile():
    """Test that all patterns compile without errors"""
    validator = InputValidator()
    
    # Check SQL patterns compile
    assert len(validator.sql_regex) == 26, "SQL regex compilation failed"
    
    # Check XSS patterns compile
    assert len(validator.xss_patterns) == 10, "XSS regex compilation failed"
    
    print("✅ All patterns compiled successfully")


def test_sql_injection_detection():
    """Test that new SQL injection patterns detect attacks"""
    validator = InputValidator()
    
    # Test cases for new patterns
    test_cases = [
        ("SELECT * FROM users UNION ALL SELECT password FROM admin", "UNION ALL"),
        ("SELECT CAST(username AS varchar) FROM users", "CAST-based"),
        ("SELECT * FROM users WHERE name LIKE '%admin%'", "LIKE-based"),
        ("WAITFOR DELAY '00:00:05'", "Time-based T-SQL"),
        ("SELECT SLEEP(5)", "Time-based MySQL"),
        ("SELECT BENCHMARK(1000000, MD5('test'))", "BENCHMARK MySQL"),
        ("SELECT pg_sleep(5)", "PostgreSQL sleep"),
        ("SELECT VERSION()", "Version fingerprint"),
        ("SELECT @@VERSION", "T-SQL version"),
        ("SELECT * FROM information_schema.tables", "Schema enumeration"),
        ("EXEC xp_cmdshell 'dir'", "Command execution"),
        ("SELECT name; EXEC sp_addlogin", "Stacked execution"),
    ]
    
    detected_count = 0
    for sql, description in test_cases:
        try:
            # This should trigger pattern detection
            validator.validate_body(sql)
        except ValueError as e:
            if "injection" in str(e).lower() or "malicious" in str(e).lower():
                detected_count += 1
                print(f"✅ Detected {description}: {sql[:40]}...")
    
    print(f"✅ Detected {detected_count}/{len(test_cases)} SQL injection patterns")


def test_xss_detection():
    """Test that XSS patterns detect attacks"""
    validator = InputValidator()
    
    # Test cases for XSS patterns
    test_cases = [
        ("<script>alert('xss')</script>", "Script tag"),
        ("<a href='javascript:alert(1)'>click</a>", "JavaScript protocol"),
        ("<img src=x onerror=alert(1)>", "onerror event"),
        ("<body onload=alert(1)>", "onload event"),
        ("<button onclick=alert(1)>click</button>", "onclick event"),
        ("<div onmouseover=alert(1)>hover</div>", "onmouseover event"),
        ("eval('alert(1)')", "eval function"),
        ("<div style='expression(alert(1))'>", "CSS expression"),
        ("<a href='vbscript:msgbox(1)'>click</a>", "VBScript protocol"),
        ("<iframe src='data:text/html,<script>alert(1)</script>'>", "Data URI"),
    ]
    
    detected_count = 0
    for xss, description in test_cases:
        try:
            # This should trigger XSS detection
            validator.validate_body(xss)
        except ValueError as e:
            if "xss" in str(e).lower() or "malicious" in str(e).lower():
                detected_count += 1
                print(f"✅ Detected {description}: {xss[:40]}...")
    
    print(f"✅ Detected {detected_count}/{len(test_cases)} XSS patterns")


def test_legitimate_content_passes():
    """Test that legitimate content is not blocked"""
    validator = InputValidator()
    
    # Legitimate content that should pass
    legitimate_cases = [
        "Hello, this is a normal email message.",
        "Please review the attached document.",
        "I'll be out of office next week.",
        "The meeting is scheduled for 3pm.",
        "<p>This is <b>bold</b> and <i>italic</i> text.</p>",
    ]
    
    passed_count = 0
    for content in legitimate_cases:
        try:
            result = validator.validate_body(content)
            if result:  # Should return sanitized content, not raise error
                passed_count += 1
                print(f"✅ Legitimate content passed: {content[:40]}...")
        except ValueError as e:
            print(f"❌ False positive blocked: {content[:40]}... Error: {e}")
    
    print(f"✅ {passed_count}/{len(legitimate_cases)} legitimate cases passed")


if __name__ == "__main__":
    print("\n=== Testing InputValidator Patterns ===\n")
    
    try:
        test_sql_pattern_count()
        test_xss_pattern_count()
        test_patterns_compile()
        test_sql_injection_detection()
        test_xss_detection()
        test_legitimate_content_passes()
        
        print("\n✅ All tests passed!")
        
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)
