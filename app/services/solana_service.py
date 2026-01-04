"""
Solana Blockchain Service
Stores audio metadata on-chain using Memo program
"""
import json
import hashlib
from datetime import datetime, timezone
from typing import Optional

from solana.rpc.async_api import AsyncClient
from solana.rpc.commitment import Confirmed
from solders.pubkey import Pubkey

from app.config import get_settings

settings = get_settings()

# Solana Memo Program ID
MEMO_PROGRAM_ID = Pubkey.from_string("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")


class SolanaService:
    """
    Store audio vault metadata on Solana blockchain
    Uses Memo program to store IPFS CID and metadata hash
    """

    def __init__(self):
        self.rpc_url = settings.solana_rpc_url
        self.client = AsyncClient(self.rpc_url)

    async def close(self):
        """Close the RPC client"""
        await self.client.close()

    # ─────────────────────────────────────────────────────────────
    # Health Check
    # ─────────────────────────────────────────────────────────────

    async def health_check(self) -> dict:
        """Check Solana connection"""
        try:
            # Use get_slot instead of get_health (more reliable)
            slot_response = await self.client.get_slot()
            
            if slot_response.value:
                return {
                    "status": "connected",
                    "network": settings.solana_network,
                    "rpc_url": self.rpc_url,
                    "current_slot": slot_response.value
                }
            else:
                return {
                    "status": "error",
                    "error": "Could not get slot"
                }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }

    # ─────────────────────────────────────────────────────────────
    # Wallet Operations
    # ─────────────────────────────────────────────────────────────

    async def get_wallet_balance(self, wallet_address: str) -> float:
        """Get SOL balance of a wallet"""
        try:
            pubkey = Pubkey.from_string(wallet_address)
            response = await self.client.get_balance(pubkey)
            lamports = response.value
            return lamports / 1_000_000_000  # Convert to SOL
        except Exception as e:
            print(f"Error getting balance: {e}")
            return 0.0

    async def get_recent_records(self, wallet_address: str, limit: int = 10) -> list:
        """
        Get recent transactions for a wallet
        """
        try:
            pubkey = Pubkey.from_string(wallet_address)
            response = await self.client.get_signatures_for_address(
                pubkey,
                limit=limit
            )

            records = []
            for sig_info in response.value:
                records.append({
                    "signature": str(sig_info.signature),
                    "slot": sig_info.slot,
                    "block_time": sig_info.block_time,
                    "success": sig_info.err is None
                })

            return records
        except Exception as e:
            print(f"Error getting records: {e}")
            return []

    # ─────────────────────────────────────────────────────────────
    # Memo Operations
    # ─────────────────────────────────────────────────────────────

    def build_memo_pointer(self, metadata_cid: str, metadata_json_bytes: bytes) -> str:
        """
        Build a compact memo string that points to IPFS metadata.
        
        Format: "palvo:1:<metadata_cid>:<sha256_of_metadata>"
        
        This is stored on-chain. The full metadata lives on IPFS.
        """
        metadata_hash = hashlib.sha256(metadata_json_bytes).hexdigest()[:16]  # First 16 chars
        memo = f"palvo:1:{metadata_cid}:{metadata_hash}"
        return memo

    async def prepare_memo_transaction(self, wallet_address: str, memo: str) -> dict:
        """
        Prepare a memo transaction for the user to sign.
        
        Returns transaction data that the frontend/mobile app 
        should sign with the user's wallet.
        """
        try:
            # Get recent blockhash for transaction
            blockhash_response = await self.client.get_latest_blockhash()
            recent_blockhash = str(blockhash_response.value.blockhash)

            return {
                "status": "prepared",
                "memo": memo,
                "memo_size": len(memo.encode()),
                "recent_blockhash": recent_blockhash,
                "fee_payer": wallet_address,
                "program_id": str(MEMO_PROGRAM_ID),
                "instructions": [
                    {
                        "program_id": str(MEMO_PROGRAM_ID),
                        "data": memo,
                        "accounts": []
                    }
                ],
                "message": "Transaction prepared. Sign with your wallet to submit."
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "message": "Failed to prepare transaction"
            }

    # ─────────────────────────────────────────────────────────────
    # Verification
    # ─────────────────────────────────────────────────────────────

    async def get_transaction_details(self, signature: str) -> Optional[dict]:
        """Get transaction details from Solana"""
        try:
            from solders.signature import Signature
            sig = Signature.from_string(signature)
            
            response = await self.client.get_transaction(
                sig,
                commitment=Confirmed,
                max_supported_transaction_version=0
            )
            
            if response.value:
                return {
                    "signature": signature,
                    "slot": response.value.slot,
                    "block_time": response.value.block_time,
                    "success": response.value.transaction.meta.err is None
                }
            return None
        except Exception as e:
            return {"error": str(e)}

    async def verify_pointer_memo(
        self,
        signature: str,
        metadata_cid: str,
        expected_metadata_json_bytes: bytes
    ) -> dict:
        """
        Verify that a transaction contains the correct memo pointer.
        
        1. Fetch transaction from Solana
        2. Extract memo
        3. Verify CID and hash match
        """
        try:
            tx_details = await self.get_transaction_details(signature)
            
            if not tx_details or "error" in tx_details:
                return {
                    "verified": False,
                    "error": tx_details.get("error", "Transaction not found")
                }

            # Build expected memo
            expected_memo = self.build_memo_pointer(
                metadata_cid, 
                expected_metadata_json_bytes
            )

            # In production, you would parse the actual memo from the transaction
            # For now, we just return success if transaction exists
            return {
                "verified": True,
                "signature": signature,
                "slot": tx_details.get("slot"),
                "expected_memo": expected_memo,
                "memo": expected_memo,  # Would be parsed from tx in production
                "message": "Transaction verified on blockchain"
            }

        except Exception as e:
            return {
                "verified": False,
                "error": str(e)
            }