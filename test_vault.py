"""
Test script for Blockchain Audio Vault
Run: python test_vault.py
"""
import httpx
import base64
import hashlib
import os
import asyncio
from nacl.signing import SigningKey
from nacl.encoding import RawEncoder
import base58

BASE_URL = "http://localhost:8001/api/v1/vault"


def generate_test_wallet():
    """Generate a test Solana wallet (Ed25519 keypair)"""
    # Generate random Ed25519 signing key
    signing_key = SigningKey.generate()
    
    # Get public key (32 bytes)
    public_key = signing_key.verify_key.encode(encoder=RawEncoder)
    
    # Get secret key (64 bytes: 32 seed + 32 public)
    secret_key = signing_key.encode(encoder=RawEncoder) + public_key
    
    # Base58 encode public key (Solana format)
    wallet_address = base58.b58encode(public_key).decode('utf-8')
    
    return {
        "address": wallet_address,
        "public_key": public_key,
        "secret_key": secret_key,
        "signing_key": signing_key
    }


def generate_test_audio():
    """Generate fake audio data for testing"""
    # 1KB of random data (simulating audio)
    audio_data = os.urandom(1024)
    audio_hash = hashlib.sha256(audio_data).hexdigest()
    return audio_data, audio_hash


async def test_health():
    """Test 1: Health Check"""
    print("\n" + "="*60)
    print("TEST 1: Health Check")
    print("="*60)
    
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{BASE_URL}/health")
        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()}")
        return response.status_code == 200


async def test_encryption_guide():
    """Test 2: Get Encryption Guide"""
    print("\n" + "="*60)
    print("TEST 2: Encryption Guide")
    print("="*60)
    
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{BASE_URL}/encryption-guide")
        print(f"Status: {response.status_code}")
        data = response.json()
        print(f"Description: {data.get('description')}")
        print(f"Steps: {len(data.get('steps', []))} steps provided")
        return response.status_code == 200


async def test_store_encrypted_audio():
    """Test 3: Store Encrypted Audio"""
    print("\n" + "="*60)
    print("TEST 3: Store Encrypted Audio")
    print("="*60)
    
    # Generate test wallet
    wallet = generate_test_wallet()
    print(f"Test Wallet: {wallet['address'][:20]}...")
    
    # Generate test audio
    audio_data, audio_hash = generate_test_audio()
    print(f"Audio Size: {len(audio_data)} bytes")
    print(f"Audio Hash: {audio_hash[:20]}...")
    
    # Import encryption service
    from app.services.encryption import EncryptionService
    
    # Encrypt audio (simulating client-side encryption)
    aes_key = EncryptionService.generate_aes_key()
    encrypted_audio, nonce = EncryptionService.encrypt_audio(audio_data, aes_key)
    
    # Encrypt AES key with wallet public key
    encrypted_key = EncryptionService.encrypt_key_for_wallet(
        aes_key, 
        wallet['address']
    )
    
    print(f"Encrypted Audio Size: {len(encrypted_audio)} bytes")
    print(f"Nonce Size: {len(nonce)} bytes")
    
    # Prepare request
    request_data = {
        "wallet_address": wallet['address'],
        "encrypted_audio_base64": base64.b64encode(encrypted_audio).decode('utf-8'),
        "encrypted_key_base64": encrypted_key,
        "nonce_base64": base64.b64encode(nonce).decode('utf-8'),
        "original_filename": "test_audio.wav",
        "audio_hash": audio_hash,
        "duration_seconds": 10
    }
    
    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(
            f"{BASE_URL}/store",
            json=request_data
        )
        
        print(f"\nStatus: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"Success: {data.get('success')}")
            print(f"Audio CID: {data.get('audio_cid')}")
            print(f"Metadata CID: {data.get('metadata_cid')}")
            print(f"Gateway URL: {data.get('audio_gateway_url')}")
            print(f"Message: {data.get('message')}")
            return data
        else:
            print(f"Error: {response.text}")
            return None


async def test_retrieve_audio(audio_cid: str):
    """Test 4: Retrieve Encrypted Audio"""
    print("\n" + "="*60)
    print("TEST 4: Retrieve Encrypted Audio")
    print("="*60)
    
    if not audio_cid:
        print("Skipping - no audio CID from previous test")
        return False
    
    request_data = {
        "audio_cid": audio_cid
    }
    
    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(
            f"{BASE_URL}/retrieve",
            json=request_data
        )
        
        print(f"Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"Audio CID: {data.get('audio_cid')}")
            print(f"File Size: {data.get('file_size')} bytes")
            enc_audio = data.get('encrypted_audio_base64', '')
            print(f"Encrypted Audio (first 50 chars): {enc_audio[:50]}...")
            return True
        else:
            print(f"Error: {response.text}")
            return False


async def test_wallet_records(wallet_address: str):
    """Test 5: Get Wallet Records"""
    print("\n" + "="*60)
    print("TEST 5: Get Wallet Records")
    print("="*60)
    
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{BASE_URL}/wallet/{wallet_address}/records",
            params={"limit": 10}
        )
        
        print(f"Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"Wallet: {data.get('wallet_address')[:20]}...")
            print(f"Total Records: {data.get('total_count')}")
            return True
        else:
            print(f"Error: {response.text}")
            return False


async def test_full_encryption_decryption():
    """Test 6: Full Encryption/Decryption Cycle (Local)"""
    print("\n" + "="*60)
    print("TEST 6: Full Encryption/Decryption Cycle (Local)")
    print("="*60)
    
    from app.services.encryption import EncryptionService
    
    # Generate wallet
    wallet = generate_test_wallet()
    print(f"Wallet: {wallet['address'][:20]}...")
    
    # Original audio
    original_audio = b"Hello, this is a test audio message!"
    original_hash = hashlib.sha256(original_audio).hexdigest()
    print(f"Original: {original_audio.decode()}")
    print(f"Original Hash: {original_hash[:20]}...")
    
    # Step 1: Generate AES key
    aes_key = EncryptionService.generate_aes_key()
    print(f"AES Key: {aes_key.hex()[:20]}...")
    
    # Step 2: Encrypt audio
    encrypted_audio, nonce = EncryptionService.encrypt_audio(original_audio, aes_key)
    print(f"Encrypted: {encrypted_audio.hex()[:40]}...")
    
    # Step 3: Encrypt AES key with wallet
    encrypted_key_b64 = EncryptionService.encrypt_key_for_wallet(
        aes_key, 
        wallet['address']
    )
    print(f"Encrypted Key: {encrypted_key_b64[:40]}...")
    
    # Step 4: Decrypt AES key with wallet secret
    decrypted_aes_key = EncryptionService.decrypt_key_with_ed25519_secret(
        encrypted_key_b64,
        wallet['secret_key']
    )
    print(f"Decrypted AES Key: {decrypted_aes_key.hex()[:20]}...")
    
    # Verify AES keys match
    assert aes_key == decrypted_aes_key, "AES keys don't match!"
    print("✅ AES keys match!")
    
    # Step 5: Decrypt audio
    decrypted_audio = EncryptionService.decrypt_audio(
        encrypted_audio, 
        decrypted_aes_key, 
        nonce
    )
    print(f"Decrypted: {decrypted_audio.decode()}")
    
    # Verify audio matches
    assert original_audio == decrypted_audio, "Audio doesn't match!"
    print("✅ Audio decrypted successfully!")
    
    # Verify hash
    decrypted_hash = hashlib.sha256(decrypted_audio).hexdigest()
    assert original_hash == decrypted_hash, "Hash doesn't match!"
    print("✅ Hash verified!")
    
    return True


async def run_all_tests():
    """Run all tests"""
    print("\n" + "="*60)
    print("🔐 BLOCKCHAIN AUDIO VAULT - TEST SUITE")
    print("="*60)
    
    results = {}
    
    # Test 1: Health
    results['health'] = await test_health()
    
    # Test 2: Encryption Guide
    results['encryption_guide'] = await test_encryption_guide()
    
    # Test 3: Store Audio
    store_result = await test_store_encrypted_audio()
    results['store'] = store_result is not None
    
    # Test 4: Retrieve Audio
    audio_cid = store_result.get('audio_cid') if store_result else None
    results['retrieve'] = await test_retrieve_audio(audio_cid)
    
    # Test 5: Wallet Records (use a known devnet wallet or generated one)
    test_wallet = generate_test_wallet()
    results['wallet_records'] = await test_wallet_records(test_wallet['address'])
    
    # Test 6: Full Encryption Cycle
    results['encryption_cycle'] = await test_full_encryption_decryption()
    
    # Summary
    print("\n" + "="*60)
    print("📊 TEST RESULTS SUMMARY")
    print("="*60)
    
    for test_name, passed in results.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"  {test_name}: {status}")
    
    total = len(results)
    passed = sum(1 for v in results.values() if v)
    print(f"\n  Total: {passed}/{total} tests passed")
    
    return all(results.values())


if __name__ == "__main__":
    asyncio.run(run_all_tests())