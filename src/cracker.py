"""JWT Brute-force Cracking Engine - Fixed Version"""

import time
import multiprocessing as mp
from typing import Optional, List, Callable, Iterator, Tuple
from dataclasses import dataclass
from pathlib import Path

from .verifier import JWTVerifier


@dataclass
class CrackResult:
    """Result of brute-force cracking attempt"""
    success: bool
    secret: Optional[str] = None
    attempts: int = 0
    elapsed_time: float = 0.0
    attempts_per_second: float = 0.0


@dataclass
class ProgressUpdate:
    """Progress update during cracking"""
    attempts: int
    elapsed_time: float
    attempts_per_second: float
    estimated_remaining: Optional[float] = None
    percentage: Optional[float] = None


class WordlistLoader:
    """Load and manage wordlists"""
    

    @staticmethod
    def load_from_file(filepath: str) -> Iterator[str]:
        """
        Load secrets from a wordlist file (one per line).
        Yields secrets one at a time for memory efficiency.
        
        Args:
            filepath: Path to wordlist file
            
        Yields:
            Secret strings
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Wordlist file not found: {filepath}")
        
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                secret = line.rstrip('\n\r')
                if secret:  # Skip empty lines
                    yield secret
    
    
    @staticmethod
    def load_from_content(content: str) -> Iterator[str]:
        """
        Load secrets from string content (one per line).
        Yields secrets one at a time for memory efficiency.
        
        Args:
            content: Wordlist content as string
            
        Yields:
            Secret strings
        """
        for line in content.splitlines():
            secret = line.strip()
            if secret:  # Skip empty lines
                yield secret
    
    @staticmethod
    def count_lines(filepath: str) -> int:
        """Count total lines in wordlist for progress tracking"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                return sum(1 for line in f if line.strip())
        except Exception:
            return 0


def _verify_secret_worker(args: Tuple[str, str]) -> Tuple[str, bool]:
    """
    Worker function for verifying a single secret.
    Used by Process Pool.
    
    Args:
        args: Tuple of (token, secret)
        
    Returns:
        Tuple of (secret, is_valid)
    """
    token, secret = args
    verifier = JWTVerifier()
    try:
        result = verifier.verify(token, secret)
        return (secret, result.valid)
    except Exception:
        # If verification fails, treat as invalid
        return (secret, False)


class JWTCracker:
    """JWT Brute-force Cracker - Fixed Version"""
    
    def __init__(self, num_workers: Optional[int] = None):
        """
        Initialize cracker.
        
        Args:
            num_workers: Number of worker processes (default: CPU count)
        """
        self.num_workers = num_workers or mp.cpu_count()
    
    def crack(self, token: str, wordlist_path: Optional[str] = None,
             wordlist_content: Optional[str] = None,
             use_common: bool = True, progress_callback: Optional[Callable] = None) -> CrackResult:
        """
        Crack JWT token using wordlist.
        
        Args:
            token: JWT token to crack
            wordlist_path: Path to wordlist file (optional)
            wordlist_content: Wordlist content as string (optional, takes precedence over wordlist_path)
            use_common: Whether to try common secrets first
            progress_callback: Callback function for progress updates
            
        Returns:
            CrackResult object
        """
        start_time = time.time()
        
        # Prepare secrets iterator
        secrets_iter = self._prepare_secrets(wordlist_path, wordlist_content, use_common)
        
        # Convert to list for pool processing
        secrets_list = list(secrets_iter)
        total_secrets = len(secrets_list)
        
        if total_secrets == 0:
            return CrackResult(
                success=False,
                attempts=0,
                elapsed_time=0.0
            )
        
        # Use Process Pool for reliable multiprocessing
        result = self._crack_with_pool(
            token, secrets_list, total_secrets, progress_callback
        )
        
        # Calculate final stats
        elapsed = time.time() - start_time
        result.elapsed_time = elapsed
        if elapsed > 0:
            result.attempts_per_second = result.attempts / elapsed
        
        return result
    
    def crack_streaming(self, token: str, wordlist_path: Optional[str] = None,
                       wordlist_content: Optional[str] = None,
                       use_common: bool = True, 
                       progress_callback: Optional[Callable] = None,
                       chunk_size: int = 1000) -> CrackResult:
        """
        Crack JWT token using streaming approach.
        More memory efficient for large wordlists.
        
        Args:
            token: JWT token to crack
            wordlist_path: Path to wordlist file (optional)
            wordlist_content: Wordlist content as string (optional)
            use_common: Whether to try common secrets first
            progress_callback: Callback function for progress updates
            chunk_size: Number of secrets per chunk for workers
            
        Returns:
            CrackResult object
        """
        start_time = time.time()
        
        # Prepare secrets iterator
        secrets_iter = self._prepare_secrets(wordlist_path, wordlist_content, use_common)
        
        # Use streaming pool approach
        result = self._crack_streaming_pool(
            token, secrets_iter, chunk_size, progress_callback
        )
        
        # Calculate final stats
        elapsed = time.time() - start_time
        result.elapsed_time = elapsed
        if elapsed > 0:
            result.attempts_per_second = result.attempts / elapsed
        
        return result
    
    def _prepare_secrets(self, wordlist_path: Optional[str], 
                        wordlist_content: Optional[str], 
                        use_common: bool) -> Iterator[str]:
        """Prepare iterator of secrets to try"""
        # Then wordlist content if provided
        if wordlist_content:
            for secret in WordlistLoader.load_from_content(wordlist_content):
                yield secret
        
        # Finally wordlist file if provided
        if wordlist_path:
            for secret in WordlistLoader.load_from_file(wordlist_path):
                yield secret
    
    def _crack_with_pool(self, token: str, secrets_list: List[str],
                        total_secrets: int, progress_callback: Optional[Callable]) -> CrackResult:
        """
        Crack using Process Pool (simple and reliable).
        
        This is the recommended approach:
        - Automatic resource cleanup
        - No deadlocks
        - Built-in error handling
        - Simple code
        """
        attempts = 0
        start_time = time.time()
        last_update = start_time
        
        # Prepare arguments for workers
        args_list = [(token, secret) for secret in secrets_list]
        
        try:
            # Use Process Pool with context manager (auto cleanup)
            with mp.Pool(processes=self.num_workers) as pool:
                # Use imap_unordered for streaming results
                # chunksize controls how many tasks each worker gets at once
                for secret, is_valid in pool.imap_unordered(_verify_secret_worker, args_list, chunksize=100):
                    attempts += 1
                    
                    # Found the secret!
                    if is_valid:
                        pool.terminate()  # Stop all workers immediately
                        return CrackResult(
                            success=True,
                            secret=secret,
                            attempts=attempts
                        )
                    
                    # Update progress periodically
                    current_time = time.time()
                    if progress_callback and (current_time - last_update) >= 1.0:
                        elapsed = current_time - start_time
                        
                        progress = ProgressUpdate(
                            attempts=attempts,
                            elapsed_time=elapsed,
                            attempts_per_second=attempts / elapsed if elapsed > 0 else 0,
                            percentage=(attempts / total_secrets * 100) if total_secrets > 0 else None,
                            estimated_remaining=((total_secrets - attempts) / (attempts / elapsed)) if attempts > 0 and elapsed > 0 else None
                        )
                        progress_callback(progress)
                        last_update = current_time
            
            # No secret found
            return CrackResult(
                success=False,
                attempts=attempts
            )
            
        except Exception as e:
            # If pool fails, fallback to single-threaded
            print(f"Pool failed ({e}), falling back to single-threaded mode")
            remaining_secrets = secrets_list[attempts:]
            fallback_result = self._crack_singlethread(
                token, iter(remaining_secrets), len(remaining_secrets), progress_callback
            )
            fallback_result.attempts += attempts
            return fallback_result
    
    def _crack_streaming_pool(self, token: str, secrets_iter: Iterator[str],
                             chunk_size: int, progress_callback: Optional[Callable]) -> CrackResult:
        """
        Crack using Process Pool with streaming iterator.
        Memory efficient for very large wordlists.
        """
        attempts = 0
        start_time = time.time()
        last_update = start_time
        
        try:
            with mp.Pool(processes=self.num_workers) as pool:
                # Create argument generator
                def args_generator():
                    for secret in secrets_iter:
                        yield (token, secret)
                
                # Use imap_unordered with generator
                for secret, is_valid in pool.imap_unordered(_verify_secret_worker, args_generator(), chunksize=chunk_size):
                    attempts += 1
                    
                    # Found the secret!
                    if is_valid:
                        pool.terminate()
                        return CrackResult(
                            success=True,
                            secret=secret,
                            attempts=attempts
                        )
                    
                    # Update progress periodically
                    current_time = time.time()
                    if progress_callback and (current_time - last_update) >= 1.0:
                        elapsed = current_time - start_time
                        
                        progress = ProgressUpdate(
                            attempts=attempts,
                            elapsed_time=elapsed,
                            attempts_per_second=attempts / elapsed if elapsed > 0 else 0,
                            percentage=None,  # Can't calculate without total
                            estimated_remaining=None
                        )
                        progress_callback(progress)
                        last_update = current_time
            
            # No secret found
            return CrackResult(
                success=False,
                attempts=attempts
            )
            
        except Exception as e:
            # Fallback to single-threaded
            print(f"Streaming pool failed ({e}), falling back to single-threaded mode")
            return CrackResult(
                success=False,
                attempts=attempts
            )
    
    def _crack_singlethread(self, token: str, secrets: Iterator[str],
                           total_secrets: Optional[int], progress_callback: Optional[Callable]) -> CrackResult:
        """Crack using single thread (fallback)"""
        verifier = JWTVerifier()
        attempts = 0
        start_time = time.time()
        last_update = start_time
        
        for secret in secrets:
            attempts += 1
            
            try:
                result = verifier.verify(token, secret)
                
                if result.valid:
                    return CrackResult(
                        success=True,
                        secret=secret,
                        attempts=attempts
                    )
            except Exception:
                # Skip invalid secrets
                pass
            
            # Update progress
            current_time = time.time()
            if progress_callback and (current_time - last_update) >= 0.5:
                elapsed = current_time - start_time
                
                progress = ProgressUpdate(
                    attempts=attempts,
                    elapsed_time=elapsed,
                    attempts_per_second=attempts / elapsed if elapsed > 0 else 0,
                    percentage=(attempts / total_secrets * 100) if total_secrets and total_secrets > 0 else None,
                    estimated_remaining=((total_secrets - attempts) / (attempts / elapsed)) if total_secrets and attempts > 0 and elapsed > 0 else None
                )
                progress_callback(progress)
                last_update = current_time
        
        return CrackResult(
            success=False,
            attempts=attempts
        )
