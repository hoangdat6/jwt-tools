"""Time and timestamp utilities"""

from datetime import datetime, timezone
from typing import Optional


def humanize_timestamp(timestamp: int) -> str:
    """
    Convert Unix timestamp to human-readable format.
    
    Args:
        timestamp: Unix timestamp (seconds since epoch)
        
    Returns:
        Human-readable date string
    """
    try:
        dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
    except (ValueError, OSError):
        return f"Invalid timestamp: {timestamp}"


def is_expired(exp_timestamp: int) -> bool:
    """
    Check if a timestamp has expired.
    
    Args:
        exp_timestamp: Expiration timestamp
        
    Returns:
        True if expired, False otherwise
    """
    now = datetime.now(timezone.utc).timestamp()
    return exp_timestamp < now


def time_until_expiry(exp_timestamp: int) -> Optional[str]:
    """
    Calculate time remaining until expiry.
    
    Args:
        exp_timestamp: Expiration timestamp
        
    Returns:
        Human-readable time remaining or None if expired
    """
    now = datetime.now(timezone.utc).timestamp()
    diff = exp_timestamp - now
    
    if diff < 0:
        return "EXPIRED"
    
    if diff < 60:
        return f"{int(diff)} seconds"
    elif diff < 3600:
        return f"{int(diff / 60)} minutes"
    elif diff < 86400:
        return f"{int(diff / 3600)} hours"
    else:
        return f"{int(diff / 86400)} days"
