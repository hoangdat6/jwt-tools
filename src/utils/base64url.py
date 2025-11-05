"""Base64URL encoding/decoding utilities"""

import base64


def base64url_decode(data: str) -> bytes:
    """
    Decode base64url encoded string to bytes.
    Handles missing padding automatically.
    
    Args:
        data: Base64URL encoded string
        
    Returns:
        Decoded bytes
    """
    # Add padding if needed
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += '=' * padding
    
    # Replace URL-safe characters
    data = data.replace('-', '+').replace('_', '/')
    
    try:
        return base64.b64decode(data)
    except Exception as e:
        raise ValueError(f"Invalid base64url string: {e}")


def base64url_encode(data: bytes) -> str:
    """
    Encode bytes to base64url string.
    
    Args:
        data: Bytes to encode
        
    Returns:
        Base64URL encoded string (without padding)
    """
    encoded = base64.b64encode(data).decode('utf-8')
    # Replace standard base64 characters with URL-safe ones
    encoded = encoded.replace('+', '-').replace('/', '_')
    # Remove padding
    return encoded.rstrip('=')
