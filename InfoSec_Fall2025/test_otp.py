#!/usr/bin/env python3
"""
Simple OTP testing script for Lab 5
This script shows how the OTP generation works independently
"""

import hashlib
import datetime

def generate_test_otp(seed_value, timestamp_str):
    """Generate a test OTP for given seed and timestamp using proper hash chain"""
    # Initialize hash chain with seed
    current_hash = hashlib.sha256(seed_value.encode('utf-8')).hexdigest()
    
    # Create hash for this timestamp: hash(seed_hash + timestamp)
    hash_input = f"{current_hash}{timestamp_str}".encode('utf-8')
    hash_value = hashlib.sha256(hash_input).hexdigest()
    
    # Convert to 6-digit OTP
    otp_code = str(int(hash_value[:8], 16))[-6:].zfill(6)
    return otp_code

def main():
    print("=== Lab 5 OTP Test Script ===")
    print()
    
    # Example user data
    andrew_id = "testuser"
    password = "testpass"
    seed_value = andrew_id + password
    
    print(f"Test seed value: {seed_value}")
    print()
    
    # Get current time
    current_time = datetime.datetime.utcnow()
    current_timestamp = current_time.strftime("%Y%m%d%H%M")
    
    print(f"Current timestamp: {current_timestamp}")
    print(f"Current time: {current_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print()
    
    # Generate OTP for current time
    current_otp = generate_test_otp(seed_value, current_timestamp)
    print(f"Current OTP: {current_otp}")
    print()
    
    # Show OTPs for ±2 minutes (tolerance window)
    print("OTPs in tolerance window (±2 minutes):")
    for offset in range(-2, 3):
        test_time = current_time + datetime.timedelta(minutes=offset)
        test_timestamp = test_time.strftime("%Y%m%d%H%M")
        test_otp = generate_test_otp(seed_value, test_timestamp)
        status = "CURRENT" if offset == 0 else f"{offset:+d} min"
        print(f"  {test_timestamp} ({status:>8}): {test_otp}")
    
    print()
    print("=== For Development/Debugging Only ===")
    print("This script helps developers verify OTP generation logic.")
    print("In actual usage:")
    print("1. User logs in → redirected to /2fa")
    print("2. User visits /show-otp → copies current OTP")  
    print("3. User returns to /2fa → enters OTP")
    print("4. Authentication complete!")
    print()
    print("The test script matches what /show-otp displays in the browser.")

if __name__ == "__main__":
    main()