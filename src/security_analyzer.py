"""JWT Security Analyzer - Comprehensive Security Checks"""

import re
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class SecurityWarning:
    """Security warning found in JWT"""
    severity: str  # "critical", "high", "medium", "low", "info"
    category: str
    message: str
    recommendation: str
    cve: Optional[str] = None  # Related CVE if applicable
    owasp: Optional[str] = None  # Related OWASP category


class JWTSecurityAnalyzer:
    """Comprehensive JWT Security Analysis"""
    
    # Algorithm definitions
    SYMMETRIC_ALGORITHMS = ['HS256', 'HS384', 'HS512']
    ASYMMETRIC_ALGORITHMS = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 
                             'PS256', 'PS384', 'PS512', 'EdDSA']
    WEAK_ALGORITHMS = ['HS256']
    DEPRECATED_ALGORITHMS = ['RS256']
    
    # Time thresholds (in seconds)
    MAX_RECOMMENDED_LIFETIME = 3600  # 1 hour
    LONG_LIFETIME_WARNING = 86400    # 1 day
    VERY_LONG_LIFETIME = 86400 * 30  # 30 days
    EXTREME_LIFETIME = 86400 * 365   # 1 year
    
    # Sensitive data patterns
    SENSITIVE_PATTERNS = {
        'password': r'pass(word|wd|phrase)?',
        'secret': r'secret|token|key',
        'api_key': r'api[_-]?key',
        'private_key': r'private[_-]?key',
        'ssn': r'ssn|social[_-]?security',
        'credit_card': r'(credit[_-]?card|cc[_-]?number|card[_-]?number)',
        'email': r'email',
        'phone': r'phone|mobile',
        'address': r'address',
        'dob': r'(date[_-]?of[_-]?birth|dob|birthday)',
    }
    
    def __init__(self):
        self.warnings: List[SecurityWarning] = []
        self.security_score = 100
    
    def analyze(self, header: Dict, payload: Dict, signature: str, algorithm: str, 
                algorithm_type: str) -> tuple[List[SecurityWarning], int]:
        """
        Perform comprehensive security analysis.
        
        Returns:
            Tuple of (warnings list, security score)
        """
        self.warnings = []
        self.security_score = 100
        
        # Run all security checks
        self._analyze_algorithm(algorithm, algorithm_type, header)
        self._analyze_header(header)
        self._analyze_payload(payload)
        self._analyze_claims(payload)
        self._analyze_signature(signature)
        
        # Sort warnings by severity
        self._sort_warnings()
        
        return self.warnings, max(0, self.security_score)
    
    def _add_warning(self, severity: str, category: str, message: str, 
                    recommendation: str, cve: Optional[str] = None, 
                    owasp: Optional[str] = None, score_impact: int = 0):
        """Add a security warning and update security score"""
        self.warnings.append(SecurityWarning(
            severity=severity,
            category=category,
            message=message,
            recommendation=recommendation,
            cve=cve,
            owasp=owasp
        ))
        self.security_score -= score_impact
    
    def _analyze_algorithm(self, algorithm: str, algorithm_type: str, header: Dict):
        """Comprehensive algorithm security analysis"""
        alg_upper = algorithm.upper()
        
        # CRITICAL: None algorithm (CVE-2015-9235)
        if algorithm_type == "none":
            self._add_warning(
                severity="critical",
                category="Algorithm",
                message="Token uses 'none' algorithm - signature verification is completely disabled!",
                recommendation="NEVER use 'none' algorithm in production. This allows trivial token forgery. Use HS256 minimum or RS256 recommended.",
                cve="CVE-2015-9235",
                owasp="A02:2021 – Cryptographic Failures",
                score_impact=50
            )
        
        # CRITICAL: Algorithm confusion vulnerability
        if algorithm_type == "asymmetric" and 'jwk' not in header and 'jku' not in header:
            self._add_warning(
                severity="high",
                category="Algorithm",
                message=f"Asymmetric algorithm ({algorithm}) without embedded key - verify server validates algorithm type",
                recommendation="Ensure server enforces expected algorithm and doesn't accept HS256 when RS256 is expected (algorithm confusion attack).",
                cve="CVE-2016-5431",
                owasp="A02:2021 – Cryptographic Failures",
                score_impact=15
            )
        
        # HIGH: Weak symmetric algorithm
        if alg_upper in self.WEAK_ALGORITHMS:
            self._add_warning(
                severity="medium",
                category="Algorithm",
                message=f"Token uses weak symmetric algorithm ({algorithm}) - vulnerable to brute-force attacks",
                recommendation="Use HS384 or HS512 for symmetric, or switch to RS256/ES256 for better security. Ensure secret is at least 256 bits of random data.",
                score_impact=10
            )
        
        # MEDIUM: Deprecated algorithm
        if alg_upper in self.DEPRECATED_ALGORITHMS:
            self._add_warning(
                severity="low",
                category="Algorithm",
                message=f"Token uses deprecated algorithm ({algorithm})",
                recommendation="Consider migrating to ES256 (ECDSA) or EdDSA for better performance and security.",
                score_impact=5
            )
        
        # Unknown algorithm
        if algorithm_type == "unknown":
            self._add_warning(
                severity="medium",
                category="Algorithm",
                message=f"Unknown or non-standard algorithm: {algorithm}",
                recommendation="Verify this algorithm is supported and secure. Use standard algorithms (HS256, RS256, ES256).",
                score_impact=15
            )
        
        # INFO: Symmetric algorithm usage
        if algorithm_type == "symmetric":
            self._add_warning(
                severity="info",
                category="Algorithm",
                message=f"Token uses symmetric algorithm ({algorithm}) - secret must be shared between issuer and verifier",
                recommendation="Consider asymmetric algorithms (RS256, ES256) for better key management in distributed systems.",
                score_impact=0
            )
    
    def _analyze_header(self, header: Dict):
        """Analyze JWT header for security issues"""
        
        # HIGH: 'jku' (JWK Set URL) - SSRF vulnerability
        if 'jku' in header:
            self._add_warning(
                severity="high",
                category="Header - JKU",
                message=f"Token contains 'jku' (JWK Set URL): {header['jku']}",
                recommendation="Strictly validate 'jku' URL against whitelist. This can be exploited for SSRF attacks or to load attacker-controlled keys.",
                owasp="A10:2021 – Server-Side Request Forgery",
                score_impact=20
            )
        
        # HIGH: 'jwk' (embedded public key) - key confusion
        if 'jwk' in header:
            self._add_warning(
                severity="high",
                category="Header - JWK",
                message="Token contains embedded 'jwk' (public key) in header",
                recommendation="Only accept keys from trusted sources. Embedded keys can enable algorithm confusion attacks. Validate key against known good keys.",
                score_impact=20
            )
        
        # HIGH: 'kid' manipulation
        if 'kid' in header:
            kid = str(header['kid'])
            
            # Path traversal
            if '../' in kid or '..\\'in kid or kid.startswith('/') or kid.startswith('\\'):
                self._add_warning(
                    severity="high",
                    category="Header - KID",
                    message=f"Suspicious 'kid' value with path traversal patterns: {kid}",
                    recommendation="Validate 'kid' parameter strictly. Use whitelist of allowed key IDs. Prevent path traversal attacks.",
                    owasp="A01:2021 – Broken Access Control",
                    score_impact=25
                )
            
            # SQL injection patterns
            sql_patterns = ["'", '"', '--', ';', 'union', 'select', 'drop', 'insert', 'update', 'delete']
            if any(pattern in kid.lower() for pattern in sql_patterns):
                self._add_warning(
                    severity="high",
                    category="Header - KID",
                    message=f"Suspicious 'kid' value with SQL injection patterns: {kid}",
                    recommendation="Sanitize 'kid' parameter. Use parameterized queries. Never concatenate 'kid' directly into SQL.",
                    owasp="A03:2021 – Injection",
                    score_impact=25
                )
            
            # Command injection patterns
            cmd_patterns = ['|', '&', ';', '`', '$', '(', ')', '{', '}']
            if any(char in kid for char in cmd_patterns):
                self._add_warning(
                    severity="high",
                    category="Header - KID",
                    message=f"Suspicious 'kid' value with command injection characters: {kid}",
                    recommendation="Validate 'kid' strictly. Never use in system commands. Use whitelist validation.",
                    owasp="A03:2021 – Injection",
                    score_impact=25
                )
        
        # MEDIUM: 'x5u' (X.509 URL) - similar to jku
        if 'x5u' in header:
            self._add_warning(
                severity="high",
                category="Header - X5U",
                message=f"Token contains 'x5u' (X.509 URL): {header['x5u']}",
                recommendation="Validate 'x5u' URL against whitelist. Can be exploited for SSRF or to load malicious certificates.",
                owasp="A10:2021 – Server-Side Request Forgery",
                score_impact=20
            )
        
        # LOW: 'typ' header
        if 'typ' not in header:
            self._add_warning(
                severity="info",
                category="Header - Type",
                message="Token missing 'typ' header",
                recommendation="Include 'typ': 'JWT' header for clarity and to prevent token confusion.",
                score_impact=2
            )
        elif header.get('typ') != 'JWT':
            self._add_warning(
                severity="low",
                category="Header - Type",
                message=f"Non-standard 'typ' value: {header['typ']}",
                recommendation="Use 'typ': 'JWT' for standard JWT tokens.",
                score_impact=3
            )
        
        # INFO: 'cty' (content type)
        if 'cty' in header:
            self._add_warning(
                severity="info",
                category="Header - Content Type",
                message=f"Token has 'cty' (content type): {header['cty']}",
                recommendation="Ensure 'cty' is validated if used for nested JWTs.",
                score_impact=0
            )
    
    def _analyze_payload(self, payload: Dict):
        """Analyze JWT payload for security issues"""
        
        # MEDIUM: Missing expiration
        if 'exp' not in payload:
            self._add_warning(
                severity="medium",
                category="Payload - Expiration",
                message="Token has no expiration time ('exp' claim)",
                recommendation="Always set expiration time. Tokens without expiration can be used indefinitely if compromised. Recommended: 15min-1hour for access tokens.",
                owasp="A07:2021 – Identification and Authentication Failures",
                score_impact=15
            )
        
        # Analyze token lifetime
        if 'exp' in payload and 'iat' in payload:
            lifetime = payload['exp'] - payload['iat']
            
            if lifetime > self.EXTREME_LIFETIME:
                self._add_warning(
                    severity="high",
                    category="Payload - Lifetime",
                    message=f"Token has extremely long lifetime: {lifetime // 86400} days ({lifetime // (86400*365)} years)",
                    recommendation="Use much shorter token lifetimes. Access tokens: 15min-1hour. Refresh tokens: max 30 days with rotation.",
                    score_impact=20
                )
            elif lifetime > self.VERY_LONG_LIFETIME:
                self._add_warning(
                    severity="medium",
                    category="Payload - Lifetime",
                    message=f"Token has very long lifetime: {lifetime // 86400} days",
                    recommendation="Reduce token lifetime to hours or days. Long-lived tokens increase security risk if compromised.",
                    score_impact=15
                )
            elif lifetime > self.LONG_LIFETIME_WARNING:
                self._add_warning(
                    severity="low",
                    category="Payload - Lifetime",
                    message=f"Token lifetime exceeds 24 hours: {lifetime // 3600} hours",
                    recommendation="Consider shorter lifetimes for access tokens (15min-1hour). Use refresh tokens for longer sessions.",
                    score_impact=8
                )
        
        # LOW: Missing 'iat' (issued at)
        if 'iat' not in payload:
            self._add_warning(
                severity="low",
                category="Payload - Issued At",
                message="Token missing 'iat' (issued at) claim",
                recommendation="Include 'iat' claim to track token age and detect token replay attacks.",
                score_impact=5
            )
        
        # LOW: Missing 'nbf' (not before) for future tokens
        if 'nbf' in payload:
            nbf_time = payload['nbf']
            current_time = datetime.now(timezone.utc).timestamp()
            if nbf_time > current_time:
                time_diff = nbf_time - current_time
                self._add_warning(
                    severity="info",
                    category="Payload - Not Before",
                    message=f"Token not yet valid - 'nbf' is {int(time_diff)} seconds in the future",
                    recommendation="Ensure system clocks are synchronized. Token will be valid after nbf time.",
                    score_impact=0
                )
        
        # MEDIUM: Missing 'iss' (issuer)
        if 'iss' not in payload:
            self._add_warning(
                severity="low",
                category="Payload - Issuer",
                message="Token missing 'iss' (issuer) claim",
                recommendation="Include 'iss' claim to identify token issuer and prevent token confusion attacks.",
                score_impact=5
            )
        
        # MEDIUM: Missing 'aud' (audience)
        if 'aud' not in payload:
            self._add_warning(
                severity="low",
                category="Payload - Audience",
                message="Token missing 'aud' (audience) claim",
                recommendation="Include 'aud' claim to specify intended recipients and prevent token misuse.",
                score_impact=5
            )
        
        # HIGH: Sensitive data in payload
        sensitive_found = []
        for key, value in payload.items():
            key_lower = key.lower()
            for sensitive_name, pattern in self.SENSITIVE_PATTERNS.items():
                if re.search(pattern, key_lower):
                    sensitive_found.append(f"{key} (matches: {sensitive_name})")
                    break
        
        if sensitive_found:
            self._add_warning(
                severity="high",
                category="Payload - Sensitive Data",
                message=f"Token may contain sensitive data: {', '.join(sensitive_found)}",
                recommendation="NEVER store sensitive data in JWT payload. It's only base64-encoded, not encrypted. Anyone can decode and read it. Use opaque tokens for sensitive data.",
                owasp="A02:2021 – Cryptographic Failures",
                score_impact=25
            )
        
        # MEDIUM: Large payload
        import json
        payload_size = len(json.dumps(payload))
        if payload_size > 1024:  # 1KB
            self._add_warning(
                severity="low",
                category="Payload - Size",
                message=f"Large payload size: {payload_size} bytes",
                recommendation="Keep JWT payload small. Large tokens increase bandwidth and may cause issues with URL length limits. Consider using references instead of embedding data.",
                score_impact=5
            )
    
    def _analyze_claims(self, payload: Dict):
        """Analyze standard and custom claims"""
        
        # Check for common custom claims that might be security-relevant
        security_claims = ['role', 'roles', 'permissions', 'scope', 'scopes', 'admin', 'isAdmin', 'superuser']
        found_security_claims = [claim for claim in payload.keys() if claim in security_claims]
        
        if found_security_claims:
            self._add_warning(
                severity="info",
                category="Claims - Authorization",
                message=f"Token contains authorization claims: {', '.join(found_security_claims)}",
                recommendation="Ensure these claims are validated server-side. Never trust client-provided tokens without verification.",
                score_impact=0
            )
        
        # Check for 'sub' (subject)
        if 'sub' not in payload:
            self._add_warning(
                severity="low",
                category="Claims - Subject",
                message="Token missing 'sub' (subject) claim",
                recommendation="Include 'sub' claim to identify the token subject (usually user ID).",
                score_impact=3
            )
    
    def _analyze_signature(self, signature: str):
        """Analyze signature characteristics"""
        
        # Check for empty signature (none algorithm)
        if not signature or signature == '':
            self._add_warning(
                severity="critical",
                category="Signature",
                message="Token has empty signature",
                recommendation="Token is not signed. This is extremely dangerous and allows trivial forgery.",
                score_impact=50
            )
        
        # Check signature length (informational)
        sig_length = len(signature)
        if sig_length < 20:
            self._add_warning(
                severity="medium",
                category="Signature",
                message=f"Unusually short signature: {sig_length} characters",
                recommendation="Verify signature is valid. Short signatures may indicate weak keys or tampering.",
                score_impact=10
            )
    
    def _sort_warnings(self):
        """Sort warnings by severity"""
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        self.warnings.sort(key=lambda w: severity_order.get(w.severity, 99))
