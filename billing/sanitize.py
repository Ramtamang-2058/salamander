import re

def sanitize_input(text: str) -> str:
    """Sanitize input to prevent injection attacks."""
    # Remove HTML tags
    text = re.sub(r'<[^>]+>', '', text)
    # Remove excessive whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    # Limit length to prevent abuse
    return text[:10000]