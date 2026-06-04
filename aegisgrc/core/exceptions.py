class AegisException(Exception):
    """Base exception for all Aegis GRC system operations."""
    def __init__(self, message: str, status_code: int = 500):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class OPAEvaluationError(AegisException):
    """Raised when the Open Policy Agent compilation or evaluation stage fails."""
    def __init__(self, message: str):
        super().__init__(message, status_code=422)


class AIEnrichmentError(AegisException):
    """Raised when Gemini SDK interaction fails or times out under high demand."""
    def __init__(self, message: str):
        super().__init__(message, status_code=503)


class HCLParsingError(AegisException):
    """Raised when an uploaded HCL file contains invalid lexical tokens."""
    def __init__(self, message: str):
        super().__init__(message, status_code=400)
