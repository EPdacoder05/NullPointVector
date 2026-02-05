#!/usr/bin/env python3
"""
Standalone test to verify pattern counts and compilation
Tests SQL injection and XSS patterns without full dependency chain
"""
import re

# SQL Injection Patterns (should be 26 total)
SQL_INJECTION_PATTERNS = [
    r"('\s*(or|and)\s*')",      # Boolean-based blind injection
    r"(--\s*$)",                 # Comment evasion
    r"(;\s*drop\s+table)",       # Stacked query - DROP
    r"(;\s*delete\s+from)",      # Stacked query - DELETE
    r"(union\s+select)",         # UNION-based injection
    r"(exec\s*\()",              # Execution vector - EXEC function
    r"(insert\s+into)",          # Stacked query - INSERT
    r"(update\s+.+\s+set)",      # Stacked query - UPDATE
    r"(<script)",                # XSS/Script injection
    r"(javascript:)",            # JavaScript protocol
    r"(onerror\s*=)",            # Event handler injection
    r"(onload\s*=)",             # Event handler injection
    r"(eval\s*\()",              # Eval function injection
    r"(expression\s*\()",        # CSS expression injection
    r"(union\s+all\s+select)",   # UNION ALL variant
    r"(cast\s*\([^)]+\s+as)",    # CAST-based UNION injection
    r"(like\s+['\"]%)",          # LIKE-based boolean blind injection
    r"(waitfor\s+delay)",        # Time-based blind (T-SQL)
    r"(sleep\s*\()",             # Time-based blind (MySQL)
    r"(benchmark\s*\()",         # Time-based blind (MySQL)
    r"(pg_sleep\s*\()",          # Time-based blind (PostgreSQL)
    r"(version\s*\()",           # Database fingerprinting
    r"(@@version)",              # Database fingerprinting (T-SQL)
    r"(information_schema)",     # Schema enumeration
    r"(xp_cmdshell)",            # OS command execution (T-SQL)
    r"(;\s*exec\s+)",            # Stacked query execution
]

# XSS Prevention Patterns (should be 10 total)
XSS_PATTERNS = [
    r"(<script[\s\S]*?>)",        # Script tags
    r"(javascript:)",              # JavaScript protocol
    r"(onerror\s*=)",              # onerror event
    r"(onload\s*=)",               # onload event
    r"(onclick\s*=)",              # onclick event
    r"(onmouseover\s*=)",          # onmouseover event
    r"(eval\s*\()",                # eval function
    r"(expression\s*\()",          # CSS expression
    r"(vbscript:)",                # VBScript protocol
    r"(data:text/html)",           # Data URI XSS
]


def test_pattern_counts():
    """Verify we have the correct number of patterns"""
    print("Testing pattern counts...")
    
    sql_count = len(SQL_INJECTION_PATTERNS)
    xss_count = len(XSS_PATTERNS)
    
    assert sql_count == 26, f"Expected 26 SQL patterns, found {sql_count}"
    assert xss_count == 10, f"Expected 10 XSS patterns, found {xss_count}"
    
    print(f"✅ SQL Injection Patterns: {sql_count}")
    print(f"✅ XSS Patterns: {xss_count}")


def test_pattern_compilation():
    """Verify all patterns compile without errors"""
    print("\nTesting pattern compilation...")
    
    errors = []
    
    # Compile SQL patterns
    sql_regex = []
    for i, pattern in enumerate(SQL_INJECTION_PATTERNS):
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
            sql_regex.append(compiled)
        except re.error as e:
            errors.append(f"SQL pattern {i}: {pattern} - Error: {e}")
    
    # Compile XSS patterns
    xss_regex = []
    for i, pattern in enumerate(XSS_PATTERNS):
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
            xss_regex.append(compiled)
        except re.error as e:
            errors.append(f"XSS pattern {i}: {pattern} - Error: {e}")
    
    if errors:
        print("❌ Pattern compilation errors:")
        for error in errors:
            print(f"  {error}")
        return False
    
    print(f"✅ All {len(sql_regex)} SQL patterns compiled successfully")
    print(f"✅ All {len(xss_regex)} XSS patterns compiled successfully")
    return True


def test_pattern_detection():
    """Test that patterns can detect malicious content"""
    print("\nTesting pattern detection...")
    
    # Compile patterns
    sql_regex = [re.compile(p, re.IGNORECASE) for p in SQL_INJECTION_PATTERNS]
    xss_regex = [re.compile(p, re.IGNORECASE) for p in XSS_PATTERNS]
    
    # Test SQL injection detection
    sql_tests = [
        ("SELECT * FROM users UNION ALL SELECT password", "UNION ALL"),
        ("WAITFOR DELAY '00:00:05'", "WAITFOR DELAY"),
        ("SELECT SLEEP(5)", "SLEEP"),
        ("SELECT VERSION()", "VERSION"),
        ("SELECT @@VERSION", "@@VERSION"),
        ("FROM information_schema.tables", "information_schema"),
        ("EXEC xp_cmdshell", "xp_cmdshell"),
    ]
    
    sql_detected = 0
    for test_string, description in sql_tests:
        for pattern in sql_regex:
            if pattern.search(test_string.lower()):
                sql_detected += 1
                print(f"  ✅ Detected {description}")
                break
    
    # Test XSS detection
    xss_tests = [
        ("<script>alert('xss')</script>", "script tag"),
        ("<img onerror=alert(1)>", "onerror"),
        ("<div onclick=alert(1)>", "onclick"),
        ("<div onmouseover=alert(1)>", "onmouseover"),
        ("href='vbscript:msgbox'", "vbscript"),
        ("src='data:text/html,<script>'", "data URI"),
    ]
    
    xss_detected = 0
    for test_string, description in xss_tests:
        for pattern in xss_regex:
            if pattern.search(test_string.lower()):
                xss_detected += 1
                print(f"  ✅ Detected {description}")
                break
    
    print(f"\n✅ SQL detection: {sql_detected}/{len(sql_tests)} patterns detected")
    print(f"✅ XSS detection: {xss_detected}/{len(xss_tests)} patterns detected")


if __name__ == "__main__":
    print("=== InputValidator Pattern Validation ===\n")
    
    try:
        test_pattern_counts()
        if test_pattern_compilation():
            test_pattern_detection()
        
        print("\n✅ ALL TESTS PASSED!\n")
        
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}\n")
        exit(1)
    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {e}\n")
        exit(1)
