"""JWT Brute-force Cracking Engine"""

import time
import multiprocessing as mp
from typing import Optional, List, Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from queue import Empty

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
    
    # Built-in common weak secrets
    COMMON_SECRETS = [
        "",  # Empty secret
        "secret",
        "Secret",
        "SECRET",
        "password",
        "Password",
        "PASSWORD",
        "123456",
        "12345678",
        "admin",
        "root",
        "test",
        "jwt-secret",
        "jwt_secret",
        "jwtsecret",
        "your-256-bit-secret",
        "my-secret-key",
        "mysecretkey",
        "default",
        "changeme",
        "letmein",
        "qwerty",
        "abc123",
        "JWT_SECRET",
        "SECRET_KEY",
        "API_KEY",
        "TOKEN_SECRET",
        # Environment variable names (common in config leaks)
        "JWT_SECRET_KEY",
        "APP_SECRET",
        "SESSION_SECRET",
    ]
    
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
    def load_common_secrets() -> List[str]:
        """Get built-in common weak secrets"""
        return WordlistLoader.COMMON_SECRETS.copy()
    
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


def _worker_process(token: str, secret_queue: mp.Queue, result_queue: mp.Queue, 
                    counter: mp.Value, stop_event: mp.Event):
    """
    Worker process for parallel cracking.
    
    Args:
        token: JWT token to crack
        secret_queue: Queue of secrets to test
        result_queue: Queue to put result if found
        counter: Shared counter for attempts
        stop_event: Event to signal workers to stop
    """
    verifier = JWTVerifier()
    
    while not stop_event.is_set():
        try:
            # Get secret from queue (timeout to check stop_event)
            secret = secret_queue.get(timeout=0.1)
            
            if secret is None:  # Poison pill
                break
            
            # Try to verify
            result = verifier.verify(token, secret)
            
            # Increment counter
            with counter.get_lock():
                counter.value += 1
            
            # If valid, put in result queue and signal stop
            if result.valid:
                result_queue.put((True, secret))
                stop_event.set()
                break
                
        except Empty:
            continue
        except Exception as e:
            # Log error but continue
            pass


class JWTCracker:
    """JWT Brute-force Cracker"""
    
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
        
        # For multiprocessing, we need to convert to list (unfortunately)
        # But for streaming approach, we can process directly
        secrets_list = list(secrets_iter)
        total_secrets = len(secrets_list)
        
        if total_secrets == 0:
            return CrackResult(
                success=False,
                attempts=0,
                elapsed_time=0.0
            )
        
        # Try multiprocessing first, fall back to single-threaded
        try:
            result = self._crack_multiprocess(
                token, secrets_list, total_secrets, progress_callback
            )
        except Exception as e:
            # Fallback to single-threaded
            result = self._crack_singlethread(
                token, iter(secrets_list), total_secrets, progress_callback
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
        Crack JWT token using streaming approach with chunked multiprocessing.
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
        
        # Prepare secrets iterator (don't convert to list!)
        secrets_iter = self._prepare_secrets(wordlist_path, wordlist_content, use_common)
        
        # Try chunked multiprocessing, fall back to single-threaded
        try:
            result = self._crack_streaming_multiprocess(
                token, secrets_iter, chunk_size, progress_callback
            )
        except Exception as e:
            # Fallback: recreate iterator and use single-threaded
            secrets_iter = self._prepare_secrets(wordlist_path, wordlist_content, use_common)
            result = self._crack_singlethread(
                token, secrets_iter, None, progress_callback
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
        # Start with common secrets if requested
        if use_common:
            for secret in WordlistLoader.load_common_secrets():
                yield secret
        
        # Then load from content (takes precedence) or file
        if wordlist_content:
            for secret in WordlistLoader.load_from_content(wordlist_content):
                yield secret
        elif wordlist_path:
            for secret in WordlistLoader.load_from_file(wordlist_path):
                yield secret
    
    def _crack_multiprocess(self, token: str, secrets_list: List[str],
                           total_secrets: int, progress_callback: Optional[Callable]) -> CrackResult:
        """Crack using multiprocessing"""
        # Create shared objects
        manager = mp.Manager()
        secret_queue = manager.Queue()
        result_queue = manager.Queue()
        counter = mp.Value('i', 0)
        stop_event = mp.Event()
        
        # Start worker processes
        workers = []
        for _ in range(self.num_workers):
            p = mp.Process(
                target=_worker_process,
                args=(token, secret_queue, result_queue, counter, stop_event),
                daemon=True
            )
            p.start()
            workers.append(p)
        
        # Feed secrets to queue
        start_time = time.time()
        last_update = start_time
        
        try:
            # Put all secrets in queue
            for secret in secrets_list:
                if stop_event.is_set():
                    break
                secret_queue.put(secret)
                
                # Update progress periodically
                current_time = time.time()
                if progress_callback and (current_time - last_update) >= 1.0:
                    elapsed = current_time - start_time
                    attempts = counter.value
                    
                    progress = ProgressUpdate(
                        attempts=attempts,
                        elapsed_time=elapsed,
                        attempts_per_second=attempts / elapsed if elapsed > 0 else 0,
                        percentage=(attempts / total_secrets * 100) if total_secrets > 0 else None,
                        estimated_remaining=((total_secrets - attempts) / (attempts / elapsed)) if attempts > 0 and elapsed > 0 else None
                    )
                    progress_callback(progress)
                    last_update = current_time
            
            # Send poison pills to stop workers
            for _ in range(self.num_workers):
                secret_queue.put(None)
            
            # Wait for workers to finish or result to be found
            timeout = max(30.0, total_secrets / 1000)  # Dynamic timeout
            for p in workers:
                p.join(timeout=timeout)
                if p.is_alive():
                    p.terminate()
                    p.join(timeout=1)
            
            # Check result
            try:
                success, secret = result_queue.get_nowait()
                return CrackResult(
                    success=True,
                    secret=secret,
                    attempts=counter.value
                )
            except Empty:
                return CrackResult(
                    success=False,
                    attempts=counter.value
                )
                
        except Exception as e:
            # Clean up workers
            stop_event.set()
            for p in workers:
                if p.is_alive():
                    p.terminate()
                    p.join(timeout=1)
            raise
        finally:
            # Ensure all workers are cleaned up
            for p in workers:
                if p.is_alive():
                    p.terminate()
    
    def _crack_streaming_multiprocess(self, token: str, secrets_iter: Iterator[str],
                                      chunk_size: int, 
                                      progress_callback: Optional[Callable]) -> CrackResult:
        """
        Crack using multiprocessing with streaming approach.
        Feeds secrets in chunks to reduce queue overhead.
        """
        # Create shared objects
        manager = mp.Manager()
        secret_queue = manager.Queue(maxsize=self.num_workers * 2)  # Limit queue size
        result_queue = manager.Queue()
        counter = mp.Value('i', 0)
        stop_event = mp.Event()
        
        # Start worker processes
        workers = []
        for _ in range(self.num_workers):
            p = mp.Process(
                target=_worker_process,
                args=(token, secret_queue, result_queue, counter, stop_event),
                daemon=True
            )
            p.start()
            workers.append(p)
        
        # Feed secrets to queue in chunks
        start_time = time.time()
        last_update = start_time
        
        try:
            chunk = []
            for secret in secrets_iter:
                if stop_event.is_set():
                    break
                
                chunk.append(secret)
                
                # When chunk is full, feed each secret to queue
                if len(chunk) >= chunk_size:
                    for s in chunk:
                        if stop_event.is_set():
                            break
                        secret_queue.put(s)
                    chunk = []
                
                # Update progress periodically
                current_time = time.time()
                if progress_callback and (current_time - last_update) >= 1.0:
                    elapsed = current_time - start_time
                    attempts = counter.value
                    
                    progress = ProgressUpdate(
                        attempts=attempts,
                        elapsed_time=elapsed,
                        attempts_per_second=attempts / elapsed if elapsed > 0 else 0,
                        percentage=None,  # Can't calculate without total
                        estimated_remaining=None
                    )
                    progress_callback(progress)
                    last_update = current_time
            
            # Feed remaining secrets in chunk
            for s in chunk:
                if stop_event.is_set():
                    break
                secret_queue.put(s)
            
            # Send poison pills to stop workers
            for _ in range(self.num_workers):
                secret_queue.put(None)
            
            # Wait for workers to finish or result to be found
            for p in workers:
                p.join(timeout=30.0)
                if p.is_alive():
                    p.terminate()
                    p.join(timeout=1)
            
            # Check result
            try:
                success, secret = result_queue.get_nowait()
                return CrackResult(
                    success=True,
                    secret=secret,
                    attempts=counter.value
                )
            except Empty:
                return CrackResult(
                    success=False,
                    attempts=counter.value
                )
                
        except Exception as e:
            # Clean up workers
            stop_event.set()
            for p in workers:
                if p.is_alive():
                    p.terminate()
                    p.join(timeout=1)
            raise
        finally:
            # Ensure all workers are cleaned up
            for p in workers:
                if p.is_alive():
                    p.terminate()
    
    def _crack_singlethread(self, token: str, secrets: Iterator[str],
                           total_secrets: int, progress_callback: Optional[Callable]) -> CrackResult:
        """Crack using single thread (fallback)"""
        verifier = JWTVerifier()
        attempts = 0
        start_time = time.time()
        last_update = start_time
        
        for secret in secrets:
            attempts += 1
            
            result = verifier.verify(token, secret)
            
            if result.valid:
                return CrackResult(
                    success=True,
                    secret=secret,
                    attempts=attempts
                )
            
            # Update progress
            current_time = time.time()
            if progress_callback and (current_time - last_update) >= 0.5:
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
        
        return CrackResult(
            success=False,
            attempts=attempts
        )
