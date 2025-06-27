import logging
from typing import Optional, Callable, Awaitable, Dict, Any, List, Union
from starlette.requests import Request
from starlette.responses import Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

class AuthenticationMiddleware(BaseHTTPMiddleware):
    """
    Middleware for authenticating SSE requests using a token parameter.
    
    This middleware checks for a token parameter in the query string and validates it
    against a provided validator function.
    """
    
    def __init__(
        self,
        app: Any,
        token_validator: Callable[[str], Awaitable[bool]],
        exclude_paths: Optional[List[str]] = None
    ):
        """
        Initialize the authentication middleware.
        
        Args:
            app: The ASGI application
            token_validator: An async function that validates the token and returns a boolean
            exclude_paths: List of paths to exclude from authentication
        """
        super().__init__(app)
        self.token_validator = token_validator
        self.exclude_paths = exclude_paths or []
        
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process the request and apply authentication if needed.
        
        Args:
            request: The incoming request
            call_next: The next middleware or route handler
            
        Returns:
            The response from the next middleware or route handler
        """
        # Skip authentication for excluded paths
        if any(request.url.path.startswith(path) for path in self.exclude_paths):
            return await call_next(request)
        
        # Check for token in query parameters
        token = request.query_params.get('token')
        print("url:", token, request.url)
        
        if not token:
            logger.warning(f"Authentication failed: No token provided for {request.url.path}")
            return Response(
                content="Authentication failed: No token provided",
                status_code=401
            )
        
        # Validate the token
        is_valid = await self.token_validator(token)
        
        if not is_valid:
            logger.warning(f"Authentication failed: Invalid token for {request.url.path}")
            return Response(
                content="Authentication failed: Invalid token",
                status_code=401
            )
        
        # Token is valid, proceed with the request
        return await call_next(request)


def create_token_validator(expected_token: Optional[str] = None) -> Callable[[str], Awaitable[bool]]:
    """
    Create a token validator function based on the expected token.
    
    Args:
        expected_token: The expected token value. If None, authentication is disabled.
        
    Returns:
        An async function that validates tokens
    """
    
    async def validate_token(token: str) -> bool:
        """
        Validate the provided token against the expected token.
        
        Args:
            token: The token to validate
            
        Returns:
            True if the token is valid or if authentication is disabled, False otherwise
        """
        # If no expected token is set, authentication is disabled
        if expected_token is None:
            logger.info("Authentication is disabled, all tokens are accepted")
            return True
            
        # Simple string comparison for basic token validation
        # For JWT tokens, you would use a JWT library to validate the token
        is_valid = token == expected_token
        
        if is_valid:
            logger.debug("Token validation successful")
        else:
            logger.warning("Token validation failed")
            
        return is_valid
    
    return validate_token