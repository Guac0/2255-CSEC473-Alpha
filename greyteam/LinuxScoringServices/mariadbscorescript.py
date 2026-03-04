#!/usr/bin/env python3
#Hopefully this works

import sys
import socket
import pymysql
from typing import Tuple

# Configuration - matches your Ansible variables
DB_HOST = '10.0.10.4'
DB_PORT = 3306
DB_NAME = 'Ponies'
DB_USER = 'pony'
DB_PASSWORD = 'FriendshipIsMagic0!'

def check_port_open(host: str, port: int) -> Tuple[bool, str]:
    """Check if MariaDB port 3306 is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            return True, f"✓ MariaDB is listening on port {port}"
        else:
            return False, f"✗ MariaDB is NOT listening on port {port}"
    except Exception as e:
        return False, f"✗ Error checking port: {e}"

def check_database_login() -> Tuple[bool, str, object]:
    """Attempt to login to database with non-root user"""
    try:
        connection = pymysql.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            connect_timeout=10
        )
        return True, f"✓ Successfully logged in as non-root user '{DB_USER}'", connection
    except pymysql.err.OperationalError as e:
        return False, f"✗ Failed to connect to database: {e}", None
    except Exception as e:
        return False, f"✗ Login error: {e}", None

def check_database_exists(connection) -> Tuple[bool, str]:
    """Verify the configured database exists"""
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT DATABASE()")
        current_db = cursor.fetchone()[0]
        cursor.close()
        
        if current_db == DB_NAME:
            return True, f"✓ Database '{DB_NAME}' exists and is selected"
        else:
            return False, f"✗ Wrong database selected: '{current_db}' (expected '{DB_NAME}')"
    except Exception as e:
        return False, f"✗ Error checking database: {e}"

def check_ponies_count(connection) -> Tuple[bool, str]:
    """Verify ponies table has exactly 6 rows"""
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM ponies")
        count = cursor.fetchone()[0]
        cursor.close()
        
        if count == 30:
            return True, f"✓ Ponies table has correct count: {count} rows"
        else:
            return False, f"✗ Ponies table has incorrect count: {count} rows (expected 6)"
    except pymysql.err.ProgrammingError as e:
        return False, f"✗ Ponies table does not exist or query failed: {e}"
    except Exception as e:
        return False, f"✗ Error querying ponies count: {e}"

def check_twilight_sparkle(connection) -> Tuple[bool, str]:
    """Verify Twilight Sparkle's element_of_harmony is 'Magic'"""
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT DISTINCT element_of_harmony FROM ponies WHERE name='Twilight Sparkle'")
        result = cursor.fetchone()
        cursor.close()
        
        if result is None:
            return False, "✗ Twilight Sparkle not found in database"
        
        element = result[0]
        if element == 'Magic':
            return True, f"✓ Twilight Sparkle's element is correct: '{element}'"
        else:
            return False, f"✗ Twilight Sparkle's element is incorrect: '{element}' (expected 'Magic')"
    except Exception as e:
        return False, f"✗ Error querying Twilight Sparkle: {e}"

def main():
    """Run all checks and report results"""
    print("=" * 60)
    print("MariaDB Service Scoring Check")
    print("=" * 60)
    
    checks_passed = 0
    total_checks = 5
    connection = None
    
    # Check 1: Port 3306 is open
    print("\n[1/5] Checking if MariaDB is running on port 3306...")
    success, message = check_port_open(DB_HOST, DB_PORT)
    print(f"      {message}")
    if success:
        checks_passed += 1
    
    # Check 2: Non-root user can login
    print("\n[2/5] Checking non-root user login...")
    success, message, connection = check_database_login()
    print(f"      {message}")
    if success:
        checks_passed += 1
    else:
        print("\n" + "=" * 60)
        print(f"FAILED: Cannot proceed without database connection")
        print(f"Score: {checks_passed}/{total_checks} checks passed")
        print("=" * 60)
        sys.exit(1)
    
    # Check 3: Database exists
    print("\n[3/5] Checking if configured database exists...")
    success, message = check_database_exists(connection)
    print(f"      {message}")
    if success:
        checks_passed += 1
    
    # Check 4: Ponies table has correct count
    print("\n[4/5] Checking ponies table row count...")
    success, message = check_ponies_count(connection)
    print(f"      {message}")
    if success:
        checks_passed += 1
    
    # Check 5: Twilight Sparkle data is correct
    print("\n[5/5] Checking Twilight Sparkle's element...")
    success, message = check_twilight_sparkle(connection)
    print(f"      {message}")
    if success:
        checks_passed += 1
    
    # Close connection
    if connection:
        connection.close()
    
    # Final report
    print("\n" + "=" * 60)
    if checks_passed == total_checks:
        print(f"SUCCESS: All {total_checks} checks passed! Service is UP ✓")
        print("=" * 60)
        sys.exit(0)
    else:
        print(f"FAILED: {checks_passed}/{total_checks} checks passed")
        print("=" * 60)
        sys.exit(1)

if __name__ == "__main__":
    main()
