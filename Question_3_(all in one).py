

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import os

def main():
    print("=" * 80)
    print("RSA ASYMMETRIC ENCRYPTION")
    print("=" * 80)
    
    # ========================================================================
    # PART (i): Generate RSA Key Pair 
    # ========================================================================
    print("\n" + "=" * 60)
    print("PART (i): GENERATING RSA KEY PAIR")
    print("=" * 60)
    
    print("Generating 2048-bit RSA key pair...")
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    
    print("✓ Key pair generated successfully!")
    print(f"\nKey Details:")
    print(f"  Key Size: {private_key.size_in_bits()} bits")
    print(f"  Public Exponent (e): {public_key.e}")
    print(f"  Modulus (n): {hex(public_key.n)[:40]}...")
    
    # ========================================================================
    # PART (ii): Encrypt Message with Public Key 
    # ========================================================================
    print("\n" + "=" * 60)
    print("PART (ii): ENCRYPTING MESSAGE WITH PUBLIC KEY")
    print("=" * 60)
    
    message = "Confidential"
    print(f"Original Message: '{message}'")
    
    # Convert to bytes
    plaintext_bytes = message.encode('utf-8')
    print(f"Message as bytes: {plaintext_bytes}")
    
    # Create encryption cipher
    encrypt_cipher = PKCS1_OAEP.new(public_key)
    
    # Encrypt the message
    ciphertext = encrypt_cipher.encrypt(plaintext_bytes)
    
    print(f"\nEncryption Process:")
    print("  1. Message converted to bytes: ✓")
    print("  2. OAEP padding applied: ✓")
    print("  3. RSA encryption with public key: ✓")
    
    print(f"\nEncrypted Ciphertext:")
    print(f"  Hex format: {ciphertext.hex()}")
    print(f"  Base64 format: {base64.b64encode(ciphertext).decode()}")
    print(f"  Length: {len(ciphertext)} bytes")
    
    # ========================================================================
    # PART (iii): Decrypt with Private Key 
    # ========================================================================
    print("\n" + "=" * 60)
    print("PART (iii): DECRYPTING WITH PRIVATE KEY")
    print("=" * 60)
    
    # Create decryption cipher
    decrypt_cipher = PKCS1_OAEP.new(private_key)
    
    # Decrypt the ciphertext
    try:
        decrypted_bytes = decrypt_cipher.decrypt(ciphertext)
        decrypted_message = decrypted_bytes.decode('utf-8')
        
        print(f"Decryption Process:")
        print("  1. Receive ciphertext: ✓")
        print("  2. RSA decryption with private key: ✓")
        print("  3. OAEP padding removed: ✓")
        print("  4. Convert bytes to string: ✓")
        
        print(f"\nDecryption Results:")
        print(f"  Decrypted bytes: {decrypted_bytes}")
        print(f"  Decrypted message: '{decrypted_message}'")
        
    except Exception as e:
        print(f"❌ Decryption failed: {e}")
        return
    
    # ========================================================================
    # PART (iv): Print Original, Encrypted, and Decrypted 
    # ========================================================================
    print("\n" + "=" * 60)
    print("PART (iv): COMPLETE PROCESS OUTPUT")
    print("=" * 60)
    
    print("\n1. ORIGINAL DATA:")
    print(f"   Message: '{message}'")
    print(f"   Bytes: {plaintext_bytes}")
    
    print("\n2. ENCRYPTED DATA (Ciphertext):")
    print(f"   Hex: {ciphertext.hex()[:60]}...")
    print(f"   Base64: {base64.b64encode(ciphertext).decode()[:40]}...")
    print(f"   Length: {len(ciphertext)} bytes")
    
    print("\n3. DECRYPTED DATA:")
    print(f"   Bytes: {decrypted_bytes}")
    print(f"   Message: '{decrypted_message}'")
    
    print("\nENCRYPTION/DECRYPTION FLOW:")
    print(f"   '{message}' → RSA Encryption → {ciphertext.hex()[:20]}...")
    print(f"   → RSA Decryption → '{decrypted_message}'")
    
    # ========================================================================
    # Confirm Successful Recovery 
    # ========================================================================
    print("\n" + "=" * 60)
    print("PART (v): VERIFICATION OF SUCCESSFUL RECOVERY")
    print("=" * 60)
    
    print("Verifying decryption results...")
    
    # Perform multiple checks
    checks = []
    
    # Check 1: String equality
    string_match = message == decrypted_message
    checks.append(("String content matches", string_match))
    
    # Check 2: Byte equality
    byte_match = plaintext_bytes == decrypted_bytes
    checks.append(("Byte content matches", byte_match))
    
    # Check 3: Length comparison
    length_match = len(message) == len(decrypted_message)
    checks.append(("Length matches", length_match))
    
    print("\nVerification Results:")
    for check_name, result in checks:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {status}: {check_name}")
    
    # Final verification
    if all(result for _, result in checks):
        print("\n✅ SUCCESS: Original message perfectly recovered!")
        print("   The RSA encryption/decryption process is working correctly.")
    else:
        print("\n❌ FAILURE: Decryption did not recover original message!")
    
    # ========================================================================
    # ADDITIONAL: Save keys and results
    # ========================================================================
    print("\n" + "=" * 60)
    print("ADDITIONAL: SAVING KEYS AND RESULTS")
    print("=" * 60)
    
    # Create directory for keys
    os.makedirs("rsa_keys", exist_ok=True)
    
    # Save keys
    with open("rsa_keys/private_key.pem", "wb") as f:
        f.write(private_key.export_key())
    
    with open("rsa_keys/public_key.pem", "wb") as f:
        f.write(public_key.export_key())
    
    # Save encryption results
    with open("rsa_keys/encryption_results.txt", "w") as f:
        f.write("RSA ENCRYPTION RESULTS\n")
        f.write("=" * 50 + "\n")
        f.write(f"Original Message: {message}\n")
        f.write(f"Ciphertext (Base64): {base64.b64encode(ciphertext).decode()}\n")
        f.write(f"Decrypted Message: {decrypted_message}\n")
        f.write(f"Verification: {'SUCCESS' if all(r for _, r in checks) else 'FAILED'}\n")
    
    print("✓ Keys saved to 'rsa_keys/' directory:")
    print("  - private_key.pem (PRIVATE - KEEP SECURE!)")
    print("  - public_key.pem")
    print("  - encryption_results.txt")
    
    print("\n" + "=" * 80)
    print("QUESTION 3 COMPLETE - ALL PARTS DEMONSTRATED")
    print("=" * 80)

if __name__ == "__main__":
    try:
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_OAEP
        main()
    except ImportError:
        print("ERROR: Required libraries not installed.")
        print("Please install pycryptodome:")
        print("  pip install pycryptodome")
        print("\nOr for the simplified version:")
        print("  pip install cryptography")
