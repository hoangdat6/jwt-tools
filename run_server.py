#!/usr/bin/env python3
"""Run the JWT Security Tool Web Server"""

import sys
import uvicorn


if __name__ == "__main__":
    print("=" * 70)
    print("JWT Security Tool - Web Server")
    print("=" * 70)
    print()
    print("Starting server on http://localhost:8000")
    print("API documentation available at http://localhost:8000/docs")
    print()
    print("Press Ctrl+C to stop the server")
    print("=" * 70)
    print()
    
    try:
        uvicorn.run(
            "src.api.app:app",
            host="0.0.0.0",
            port=8000,
            reload=True,
            log_level="info"
        )
    except KeyboardInterrupt:
        print("\n\nServer stopped by user")
        sys.exit(0)
