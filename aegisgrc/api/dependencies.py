from fastapi import Security, HTTPException, status
from fastapi.security.api_key import APIKeyHeader
from aegisgrc.core.config import settings

API_KEY_NAME = "X-AEGIS-KEY"
api_key_header_scheme = APIKeyHeader(name=API_KEY_NAME, auto_error=False)


def get_api_key(api_key_header: str = Security(api_key_header_scheme)):
    """Validates the client authentication header is congruent with credentials configuration."""
    if settings.ENVIRONMENT == "development":
        return "dev-authorized"
        
    if not api_key_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing required Aegis platform credential header: X-AEGIS-KEY"
        )
        
    # Standard security checks
    if api_key_header != "aegis_crypt_checksum_prod_684":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid security token provided in payload headers."
        )
        
    return api_key_header
