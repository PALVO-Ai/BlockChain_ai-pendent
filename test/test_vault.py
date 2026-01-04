"""
Blockchain Audio Vault - Test Script
Run from project root: python test_vault.py
"""
import httpx
import base64
import hashlib
import os
import asyncio
import time

BASE_URL = "http://localhost:8001/api/v1/vault"


async def test_health():
    print("\n" + "="*50)
    print("TEST 1: Health Check")
    print("="*50)
    
    async with httpx.AsyncClient() as client:
        r = await client.get(f"{BASE_URL}/health")
        data = r.json()
        print(f"  Solana: {data.get('solana', {}).get('status')}")
        print(f"  IPFS:   {data.get('ipfs', {}).get('status')}")
        return data.get('status') == 'healthy'


async def test_store_and_retrieve():
    print("\n" + "="*50)
    print("TEST 2: Store & Retrieve Audio")
    print("="*50)
    
    # Create test audio
    audio = os.urandom(512)
    audio_hash = hashlib.sha256(audio).hexdigest()
    print(f"  Audio: {len(audio)} bytes")
    print(f"  Hash:  {audio_hash[:16]}...")
    
    payload = {
        "wallet_address": "11111111111111111111111111111111",
        "encrypted_audio_base64": base64.b64encode(audio).decode(),
        "encrypted_key_base64": base64.b64encode(os.urandom(48)).decode(),
        "nonce_base64": base64.b64encode(os.urandom(12)).decode(),
        "original_filename": "test.wav",
        "audio_hash": audio_hash,
        "duration_seconds": 5
    }
    
    async with httpx.AsyncClient(timeout=60) as client:
        # Store
        print("\n  Storing...")
        r = await client.post(f"{BASE_URL}/store", json=payload)
        
        if r.status_code != 200:
            print(f"  ❌ Store failed: {r.text}")
            return False, False
        
        data = r.json()
        audio_cid = data.get('audio_cid')
        print(f"  ✅ Stored! CID: {audio_cid}")
        
        # Wait for IPFS propagation
        print("\n  Waiting 3s for IPFS propagation...")
        await asyncio.sleep(3)
        
        # Retrieve
        print("  Retrieving...")
        r = await client.post(
            f"{BASE_URL}/retrieve", 
            json={"audio_cid": audio_cid}
        )
        
        if r.status_code == 200:
            retrieved = r.json()
            print(f"  ✅ Retrieved! Size: {retrieved.get('file_size')} bytes")
            return True, True
        else:
            print(f"  ❌ Retrieve failed: {r.status_code}")
            return True, False


async def test_encryption():
    print("\n" + "="*50)
    print("TEST 3: Local Encryption")
    print("="*50)
    
    try:
        from app.services.encryption import EncryptionService
        
        original = b"Test audio data for encryption"
        print(f"  Original: {original.decode()}")
        
        # Encrypt
        key = EncryptionService.generate_aes_key()
        encrypted, nonce = EncryptionService.encrypt_audio(original, key)
        print(f"  Encrypted: {len(encrypted)} bytes")
        
        # Decrypt
        decrypted = EncryptionService.decrypt_audio(encrypted, key, nonce)
        print(f"  Decrypted: {decrypted.decode()}")
        
        if original == decrypted:
            print("  ✅ Encryption/Decryption works!")
            return True
        return False
    except ImportError:
        print("  ⚠️ Run from project root folder!")
        return False
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False


async def main():
    print("\n" + "="*50)
    print("🔐 BLOCKCHAIN AUDIO VAULT - TESTS")
    print("="*50)
    print("Server: http://localhost:8001")
    
    results = {}
    
    # Test 1: Health
    try:
        results['health'] = await test_health()
    except Exception as e:
        print(f"  ❌ Server error: {e}")
        results['health'] = False
    
    # Test 2: Store & Retrieve
    if results.get('health'):
        try:
            store_ok, retrieve_ok = await test_store_and_retrieve()
            results['store'] = store_ok
            results['retrieve'] = retrieve_ok
        except Exception as e:
            print(f"  ❌ Error: {e}")
            results['store'] = False
            results['retrieve'] = False
    else:
        results['store'] = False
        results['retrieve'] = False
    
    # Test 3: Local Encryption
    results['encryption'] = await test_encryption()
    
    # Summary
    print("\n" + "="*50)
    print("📊 RESULTS")
    print("="*50)
    for name, passed in results.items():
        icon = "✅" if passed else "❌"
        print(f"  {icon} {name}")
    
    total = len(results)
    passed = sum(results.values())
    print(f"\n  {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed!")


if __name__ == "__main__":
    asyncio.run(main())