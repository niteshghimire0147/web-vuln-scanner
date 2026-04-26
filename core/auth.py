"""
core/auth.py — Authentication and Session Handler

Manages form-based login, cookie injection, and session maintenance
so that authenticated scanner modules can operate under a valid session.

Supports:
  - Form-based login (HTML form detection + POST)
  - Manual cookie string injection
  - Bearer / API-key token headers
  - Session persistence across the scan lifecycle
"""
import re
import time
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


class AuthHandler:
    """
    Handles authentication for web application scans.

    Usage:
        handler = AuthHandler(session, login_url="http://target/login",
                              username="admin", password="admin")
        if handler.authenticate():
            # session now carries valid auth cookies
            ...
    """

    def __init__(
        self,
        session:       requests.Session,
        login_url:     Optional[str]  = None,
        username:      Optional[str]  = None,
        password:      Optional[str]  = None,
        cookie_string: Optional[str]  = None,
        token:         Optional[str]  = None,
        token_header:  str            = "Authorization",
        timeout:       int            = 10,
    ) -> None:
        self.session       = session
        self.login_url     = login_url
        self.username      = username
        self.password      = password
        self.cookie_string = cookie_string
        self.token         = token
        self.token_header  = token_header
        self.timeout       = timeout
        self._authenticated = False
        self._auth_method   = "none"

    # ── Public interface ──────────────────────────────────────────────────

    def authenticate(self) -> bool:
        """
        Run the appropriate authentication flow based on provided credentials.

        Returns True if authentication appears to have succeeded.
        """
        if self.cookie_string:
            self._inject_cookies()
            return True

        if self.token:
            self._inject_token()
            return True

        if self.login_url and self.username and self.password:
            return self._form_login()

        return False   # No auth configured — proceed unauthenticated

    @property
    def is_authenticated(self) -> bool:
        return self._authenticated

    @property
    def auth_method(self) -> str:
        return self._auth_method

    # ── Cookie injection ──────────────────────────────────────────────────

    def _inject_cookies(self) -> None:
        """Parse and inject a raw cookie string into the session."""
        for pair in self.cookie_string.split(";"):
            pair = pair.strip()
            if "=" in pair:
                name, _, value = pair.partition("=")
                self.session.cookies.set(name.strip(), value.strip())
        self._authenticated = True
        self._auth_method   = "cookie"

    # ── Token injection ───────────────────────────────────────────────────

    def _inject_token(self) -> None:
        """Set a Bearer or custom token in the session's default headers."""
        if self.token_header.lower() == "authorization":
            value = (
                self.token if self.token.lower().startswith("bearer ")
                else f"Bearer {self.token}"
            )
        else:
            value = self.token
        self.session.headers[self.token_header] = value
        self._authenticated = True
        self._auth_method   = "token"

    # ── Form-based login ──────────────────────────────────────────────────

    def _form_login(self) -> bool:
        """
        Discover and submit the login form on login_url.

        Strategy:
        1. GET the login page and parse the HTML for <form> elements.
        2. Identify the username and password fields by name/type heuristics.
        3. POST the form with supplied credentials.
        4. Determine success by checking for redirect away from the login URL
           or presence of dashboard/logout content in the response.
        """
        try:
            resp = self.session.get(self.login_url, timeout=self.timeout)
        except requests.RequestException as exc:
            return False

        soup    = BeautifulSoup(resp.text, "html.parser")
        form    = self._find_login_form(soup)
        if form is None:
            # Fall back to a raw POST with common field names
            return self._raw_post_login()

        action  = form.get("action", self.login_url)
        if not action.startswith("http"):
            action = urljoin(self.login_url, action)

        method  = form.get("method", "POST").upper()
        data    = self._build_form_data(form)

        try:
            post_resp = self.session.request(
                method, action, data=data,
                timeout=self.timeout, allow_redirects=True,
            )
        except requests.RequestException:
            return False

        return self._check_login_success(post_resp)

    def _find_login_form(self, soup: BeautifulSoup) -> Optional[object]:
        """
        Return the <form> element most likely to be a login form.
        Priority: form containing a password input.
        """
        for form in soup.find_all("form"):
            if form.find("input", {"type": "password"}):
                return form
        return None

    def _build_form_data(self, form) -> dict:
        """
        Build the POST data dict from a BeautifulSoup form element,
        substituting the username and password into detected fields.
        """
        USER_FIELD_NAMES = {
            "username", "user", "email", "login", "uname",
            "user_name", "user_login", "email_address",
        }
        PASS_FIELD_NAMES = {
            "password", "pass", "passwd", "pwd",
            "user_password", "pass_word",
        }

        data: dict = {}
        for inp in form.find_all(["input", "select", "textarea"]):
            name  = inp.get("name")
            value = inp.get("value", "")
            if not name:
                continue

            name_lower = name.lower()
            if name_lower in USER_FIELD_NAMES or inp.get("type") == "email":
                data[name] = self.username
            elif (name_lower in PASS_FIELD_NAMES
                  or inp.get("type") == "password"):
                data[name] = self.password
            else:
                data[name] = value   # Keep hidden fields, CSRF tokens, etc.

        return data

    def _raw_post_login(self) -> bool:
        """
        Last-resort login attempt using common field-name guesses.
        """
        candidate_payloads = [
            {"username": self.username, "password": self.password},
            {"email":    self.username, "password": self.password},
            {"user":     self.username, "pass":     self.password},
            {"login":    self.username, "password": self.password},
        ]
        for payload in candidate_payloads:
            try:
                resp = self.session.post(
                    self.login_url, data=payload,
                    timeout=self.timeout, allow_redirects=True,
                )
                if self._check_login_success(resp):
                    return True
                time.sleep(0.2)
            except requests.RequestException:
                continue
        return False

    def _check_login_success(self, resp: requests.Response) -> bool:
        """
        Heuristically determine whether a login response indicates success.
        """
        # URL changed away from the login page
        login_hostname = urlparse(self.login_url).path.rstrip("/")
        resp_path      = urlparse(resp.url).path.rstrip("/")
        if resp_path != login_hostname and resp.status_code in (200, 302):
            body_lower = resp.text.lower()
            # Check for authenticated-state indicators
            if any(kw in body_lower for kw in (
                "dashboard", "logout", "sign out", "welcome",
                "my account", "profile", "account settings",
            )):
                self._authenticated = True
                self._auth_method   = "form"
                return True

        # Check for error indicators — if present, login failed
        body_lower = resp.text.lower()
        if any(kw in body_lower for kw in (
            "invalid credentials", "incorrect password",
            "login failed", "authentication failed",
            "wrong password", "invalid email",
        )):
            return False

        # Ambiguous — treat as success if cookies were set
        if resp.cookies:
            self._authenticated = True
            self._auth_method   = "form"
            return True

        return False
