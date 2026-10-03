"""PyQt6 example client for the server's encrypted client protocol.

This example defaults to the software-scoped v2 API implemented by
``server/src/crypto.js`` and ``server/src/server.js``.  It deliberately does
not contain a URL, license, or key belonging to a production deployment.
Provide a per-client exported key at runtime (or inject it from a secure
configuration system) instead.

Install for running the GUI::

    pip install PyQt6 cryptography requests

V2 configuration fields are represented by ``V2ClientConfig``::

    V2ClientConfig(base_url, software_slot, key_version, key)

``base_url`` is the server origin, for example ``http://127.0.0.1:3000``.
The client adds ``/api/v2/client/{software_slot}``.  A complete v2 endpoint is
also accepted, which is useful when a reverse proxy already supplies a path.
``key`` is the 32-byte AES key in unpadded base64url form, as returned by the
server's key export operation.  Never put that value in source control.

The old v1 wire format is retained below as explicitly named compatibility
helpers.  It is never selected by the GUI and must only be used with a
separately provisioned legacy-compatible key.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import secrets
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import quote, urlsplit, urlunsplit

import requests
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QComboBox,
    QLineEdit,
    QMainWindow,
    QPushButton,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


PROTOCOL = "jur10n-client-v2"
AES_KEY_BYTES = 32
AES_GCM_IV_BYTES = 12
AES_GCM_TAG_BYTES = 16
MIN_PACKET_BYTES = AES_GCM_IV_BYTES + AES_GCM_TAG_BYTES
MAX_PACKET_BYTES = 256 * 1024
MAX_FILE_CHUNK_BYTES = 64 * 1024
DEFAULT_TIMEOUT = (10, 20)
NONCE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,256}$")
BASE64URL_PATTERN = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")

# These are the exact AAD values used by the current legacy v1 server path.
# They are intentionally separate from the v2, software-scoped AAD.
LEGACY_V1_REQUEST_AAD = b"jur10n:server:v1:request"
LEGACY_V1_RESPONSE_AAD = b"jur10n:server:v1:response"


class ClientError(Exception):
    """Base class for errors raised by this client."""


class ConfigurationError(ClientError):
    """The local client configuration is invalid."""


class TransportError(ClientError):
    """The HTTP request could not be completed or was not an API response."""


class ProtocolError(ClientError):
    """The encrypted packet or its JSON envelope is invalid."""


class SessionError(ClientError):
    """An authenticated operation was requested before login."""


class DownloadError(ClientError):
    """A file download failed validation."""


class ApiError(ClientError):
    """An encrypted server response with ``ok: false``.

    ``code`` is one of the server error codes, such as ``INVALID_CREDENTIALS``
    or ``SESSION_EXPIRED``.  The server's logical HTTP status is available as
    ``status`` even though the encrypted endpoint normally uses HTTP 200.
    """

    def __init__(self, code: str, status: int = 400, payload: Optional[dict] = None):
        self.code = str(code)
        self.status = int(status)
        self.payload = payload or {}
        super().__init__(f"{self.code} (status {self.status})")


def timestamp_ms() -> int:
    """Return the Unix timestamp in milliseconds required by the v2 envelope."""

    return int(time.time() * 1000)


def new_nonce() -> str:
    """Return a server-compatible, URL-safe nonce for one request."""

    # token_urlsafe(24) is 32 characters and therefore meets the server's
    # 16..256 character constraint without punctuation outside its allow-list.
    return secrets.token_urlsafe(24)


def _decode_key_base64url(value: str, field_name: str = "key") -> bytes:
    """Decode and strictly validate an unpadded (or padded) base64url key."""

    if not isinstance(value, str) or not BASE64URL_PATTERN.fullmatch(value):
        raise ConfigurationError(f"{field_name} must be a base64url string")
    unpadded = value.rstrip("=")
    if len(unpadded) % 4 == 1:
        raise ConfigurationError(f"{field_name} has invalid base64url length")
    padded = unpadded + "=" * (-len(unpadded) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, binascii.Error) as error:
        raise ConfigurationError(f"{field_name} is not valid base64url") from error
    canonical = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    if canonical != unpadded or len(raw) != AES_KEY_BYTES:
        raise ConfigurationError(f"{field_name} must decode to exactly 32 bytes")
    return raw


def _pack_json(raw_key: bytes, payload: dict, aad: bytes) -> bytes:
    """Encode JSON and return ``IV || ciphertext || GCM tag``."""

    if len(raw_key) != AES_KEY_BYTES:
        raise ConfigurationError("AES-256-GCM key must be exactly 32 bytes")
    try:
        plaintext = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ProtocolError(f"request JSON cannot be encoded: {error}") from error
    iv = secrets.token_bytes(AES_GCM_IV_BYTES)
    return iv + AESGCM(raw_key).encrypt(iv, plaintext, aad)


def _unpack_json(raw_key: bytes, packet: bytes, aad: bytes) -> dict:
    """Decrypt and decode a packet emitted by the Node AES-GCM implementation."""

    if len(raw_key) != AES_KEY_BYTES:
        raise ConfigurationError("AES-256-GCM key must be exactly 32 bytes")
    if len(packet) < MIN_PACKET_BYTES or len(packet) > MAX_PACKET_BYTES:
        raise ProtocolError("encrypted packet has an invalid length")
    iv, encrypted = packet[:AES_GCM_IV_BYTES], packet[AES_GCM_IV_BYTES:]
    try:
        plaintext = AESGCM(raw_key).decrypt(iv, encrypted, aad)
    except InvalidTag as error:
        raise ProtocolError("encrypted packet authentication failed") from error
    try:
        value = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProtocolError("decrypted packet is not valid JSON") from error
    if not isinstance(value, dict):
        raise ProtocolError("decrypted envelope must be a JSON object")
    return value


@dataclass(frozen=True)
class V2ClientConfig:
    """Runtime configuration for one software-scoped v2 client."""

    base_url: str
    software_slot: str
    key_version: int
    key: str

    def __post_init__(self) -> None:
        if not isinstance(self.base_url, str) or not self.base_url.strip():
            raise ConfigurationError("base_url is required")
        if not isinstance(self.software_slot, str) or not re.fullmatch(
            r"[a-z0-9][a-z0-9-]{0,62}", self.software_slot
        ):
            raise ConfigurationError("software_slot must be a lowercase slug")
        if isinstance(self.key_version, bool) or not isinstance(self.key_version, int):
            raise ConfigurationError("key_version must be an integer")
        if self.key_version < 1:
            raise ConfigurationError("key_version must be positive")
        _decode_key_base64url(self.key)

    @property
    def raw_key(self) -> bytes:
        """Return the decoded AES key held only in process memory."""

        return _decode_key_base64url(self.key)

    @property
    def endpoint(self) -> str:
        """Build the v2 endpoint without putting the slot in a query string."""

        raw = self.base_url.strip().rstrip("/")
        parsed = urlsplit(raw)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ConfigurationError("base_url must be an absolute http(s) URL")
        path = parsed.path.rstrip("/")
        marker = "/api/v2/client/"
        if path.startswith(marker) and len(path) > len(marker):
            # A complete endpoint is accepted for reverse-proxy deployments.
            return urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, ""))
        if path.endswith("/api/v2/client"):
            path = f"{path}/{quote(self.software_slot, safe='')}"
        else:
            path = f"{path}/api/v2/client/{quote(self.software_slot, safe='')}"
        return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


class V2Client:
    """Synchronous client for all operations in ``ALLOWED_OPS`` on the server."""

    def __init__(self, config: V2ClientConfig, session: Optional[requests.Session] = None):
        self.config = config
        self.http = session or requests.Session()
        self.session_token: Optional[str] = None
        self.session_id: Optional[str] = None
        self.machine_proof: Optional[str] = None
        self.session_info: Optional[dict] = None

    @property
    def authenticated(self) -> bool:
        return bool(self.session_token and self.session_id)

    def clear_session(self) -> None:
        """Forget the client session held by this process."""

        self.session_token = None
        self.session_id = None
        self.machine_proof = None
        self.session_info = None

    def _envelope(self, operation: str, **fields: Any) -> dict:
        if not isinstance(operation, str) or not operation:
            raise ConfigurationError("operation is required")
        payload = {
            "protocol": PROTOCOL,
            "key_version": self.config.key_version,
            "timestamp": timestamp_ms(),
            "nonce": new_nonce(),
            "op": operation,
        }
        payload.update(fields)
        return payload

    def _post(self, payload: dict) -> dict:
        """Encrypt one request, post it, decrypt its response, and raise API errors."""

        aad = (
            f"jur10n:client:v2:{self.config.software_slot}:"
            f"{self.config.key_version}:request"
        ).encode("utf-8")
        packet = _pack_json(self.config.raw_key, payload, aad)
        headers = {
            "Content-Type": "application/octet-stream",
            "Accept": "application/octet-stream",
            "Accept-Encoding": "identity",
            "X-Key-Version": str(self.config.key_version),
            "User-Agent": "jur10n-client-v2-pyqt-example/1.0",
        }
        try:
            response = self.http.post(
                self.config.endpoint,
                data=packet,
                headers=headers,
                timeout=DEFAULT_TIMEOUT,
            )
        except requests.exceptions.RequestException as error:
            raise TransportError(f"network connection failed: {error}") from error

        if response.headers.get("Cf-Mitigated", "").lower() == "challenge":
            raise TransportError(
                "Cloudflare returned a browser challenge; configure an API/WAF "
                "skip rule instead of trying to solve it with requests"
            )
        content_type = response.headers.get("Content-Type", "").split(";", 1)[0].lower()
        if response.status_code != 200:
            raise TransportError(f"HTTP transport status {response.status_code}")
        if content_type != "application/octet-stream":
            raise ProtocolError(
                f"expected application/octet-stream, received {content_type or 'none'}"
            )

        response_aad = (
            f"jur10n:client:v2:{self.config.software_slot}:"
            f"{self.config.key_version}:response"
        ).encode("utf-8")
        envelope = _unpack_json(self.config.raw_key, response.content, response_aad)
        if not isinstance(envelope.get("ok"), bool):
            raise ProtocolError("response envelope is missing boolean 'ok'")
        try:
            status = int(envelope.get("status", 200))
        except (TypeError, ValueError) as error:
            raise ProtocolError("response envelope has an invalid status") from error
        if not envelope["ok"]:
            raise ApiError(envelope.get("error", "UNKNOWN_ERROR"), status, envelope)
        return envelope

    def request(self, operation: str, **fields: Any) -> Any:
        """Send a raw v2 operation and return its decrypted ``data`` value."""

        envelope = self._post(self._envelope(operation, **fields))
        return envelope.get("data")

    def _session_fields(self) -> dict:
        if not self.authenticated:
            raise SessionError("login is required before this operation")
        fields = {
            "session_token": self.session_token,
            "session_id": self.session_id,
        }
        if self.machine_proof is not None:
            fields["machine_proof"] = self.machine_proof
        return fields

    def login(self, code: str, machine_proof: Optional[str] = None) -> dict:
        """Create a session using a software-scoped license code."""

        if not isinstance(code, str) or not code:
            raise ConfigurationError("license code is required")
        fields: dict[str, Any] = {"code": code}
        if machine_proof is not None and machine_proof != "":
            fields["machine_proof"] = machine_proof
        data = self.request("login", **fields)
        if not isinstance(data, dict):
            raise ProtocolError("login response data must be an object")
        token = data.get("sessionToken")
        session_id = data.get("sessionId")
        if not isinstance(token, str) or not token or not isinstance(session_id, str) or not session_id:
            raise ProtocolError("login response did not contain sessionToken/sessionId")
        self.session_token = token
        self.session_id = session_id
        self.machine_proof = fields.get("machine_proof")
        self.session_info = data
        return data

    def heartbeat(self) -> dict:
        """Refresh the server-side session heartbeat."""

        data = self.request("heartbeat", **self._session_fields())
        return data if isinstance(data, dict) else {"data": data}

    def pull_variables(self, since_version: int = 0) -> Any:
        """Fetch enabled software variables newer than ``since_version``."""

        if isinstance(since_version, bool) or not isinstance(since_version, int) or since_version < 0:
            raise ConfigurationError("since_version must be a non-negative integer")
        return self.request(
            "pull_variables", since_version=since_version, **self._session_fields()
        )

    def report(self, data: Any, data_slot: str = "legacy", mode: str = "overwrite") -> Any:
        """Overwrite or append the per-license value stored in one data slot."""

        if not isinstance(data_slot, str) or not data_slot:
            raise ConfigurationError("data_slot is required")
        if mode not in {"overwrite", "append"}:
            raise ConfigurationError("mode must be overwrite or append")
        return self.request(
            "report", data_slot=data_slot, data=data, mode=mode, **self._session_fields()
        )

    def announcement(self) -> Any:
        """Read the public software announcement without a login session."""

        return self.request("announcement")

    def manifest(self) -> Any:
        """Return the latest published release manifest."""

        return self.request("manifest", **self._session_fields())

    def file_chunk(
        self, file_id: int, offset: int = 0, length: int = MAX_FILE_CHUNK_BYTES
    ) -> dict:
        """Fetch one file chunk and decode its standard-base64 ``chunk`` field."""

        if isinstance(file_id, bool) or not isinstance(file_id, int) or file_id < 1:
            raise ConfigurationError("file_id must be a positive integer")
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise ConfigurationError("offset must be a non-negative integer")
        if isinstance(length, bool) or not isinstance(length, int) or length < 1:
            raise ConfigurationError("length must be a positive integer")
        data = self.request(
            "file_chunk",
            file_id=file_id,
            offset=offset,
            length=min(length, MAX_FILE_CHUNK_BYTES),
            **self._session_fields(),
        )
        if not isinstance(data, dict) or not isinstance(data.get("chunk"), str):
            raise ProtocolError("file_chunk response is missing base64 chunk data")
        try:
            chunk = base64.b64decode(data["chunk"], validate=True)
        except (ValueError, binascii.Error) as error:
            raise ProtocolError("file_chunk response contains invalid base64") from error
        declared_length = data.get("length")
        if not isinstance(declared_length, int) or declared_length != len(chunk):
            raise ProtocolError("file_chunk response length does not match its data")
        result = dict(data)
        result["chunk"] = chunk
        return result

    def download_file(
        self,
        file_id: int,
        destination: str | Path,
        chunk_size: int = MAX_FILE_CHUNK_BYTES,
    ) -> dict:
        """Download and hash-check a manifest file through repeated ``file_chunk`` calls."""

        if isinstance(chunk_size, bool) or not isinstance(chunk_size, int) or chunk_size < 1:
            raise ConfigurationError("chunk_size must be a positive integer")
        chunk_size = min(chunk_size, MAX_FILE_CHUNK_BYTES)
        target = Path(destination)
        offset = 0
        total_size: Optional[int] = None
        expected_sha256: Optional[str] = None
        digest = hashlib.sha256()
        try:
            with target.open("wb") as output:
                while True:
                    info = self.file_chunk(file_id, offset, chunk_size)
                    chunk = info["chunk"]
                    if not isinstance(chunk, bytes) or not chunk:
                        raise DownloadError("server returned an empty file chunk")
                    if info.get("offset") != offset:
                        raise DownloadError("server returned a chunk at an unexpected offset")
                    if total_size is None:
                        total_size = info.get("totalSize")
                        expected_sha256 = info.get("sha256")
                    output.write(chunk)
                    digest.update(chunk)
                    offset += len(chunk)
                    if info.get("eof"):
                        break
                    if not isinstance(total_size, int) or offset >= total_size:
                        raise DownloadError("file chunk stream ended without eof")
        except ClientError:
            try:
                target.unlink(missing_ok=True)
            except OSError:
                pass
            raise
        except OSError as error:
            raise DownloadError(f"cannot write {target}: {error}") from error

        if total_size != offset:
            raise DownloadError(f"download size mismatch: got {offset}, expected {total_size}")
        actual_sha256 = digest.hexdigest()
        if expected_sha256 and actual_sha256 != expected_sha256:
            raise DownloadError("download SHA-256 does not match the manifest")
        return {
            "fileId": file_id,
            "path": str(target),
            "size": offset,
            "sha256": actual_sha256,
        }


# ---------------------------------------------------------------------------
# Explicit legacy v1 compatibility.  The GUI never calls these helpers.
# ---------------------------------------------------------------------------


def encrypt_legacy_v1_packet(key: bytes, payload: dict) -> bytes:
    """Pack a legacy ``/api/v1/client`` request using the current server AAD."""

    return _pack_json(key, payload, LEGACY_V1_REQUEST_AAD)


def decrypt_legacy_v1_response(key: bytes, packet: bytes) -> dict:
    """Unpack a legacy v1 response; v2 remains the default client path."""

    return _unpack_json(key, packet, LEGACY_V1_RESPONSE_AAD)


class LegacyV1Client:
    """Small opt-in legacy helper; it is not used by ``Window``.

    The current server's v1 endpoint is ``POST /api/v1/client`` and expects the
    shared v1 key directly.  Supply that key at runtime only when maintaining
    an existing legacy deployment.  This class intentionally has no embedded
    configuration and does not read privileged server configuration.
    """

    def __init__(self, base_url: str, key: bytes, session: Optional[requests.Session] = None):
        if not isinstance(key, bytes) or len(key) != AES_KEY_BYTES:
            raise ConfigurationError("legacy v1 key must be exactly 32 bytes")
        self.base_url = base_url.rstrip("/")
        self.key = key
        self.http = session or requests.Session()

    @property
    def endpoint(self) -> str:
        parsed = urlsplit(self.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ConfigurationError("base_url must be an absolute http(s) URL")
        if parsed.path.rstrip("/").endswith("/api/v1/client"):
            path = parsed.path.rstrip("/")
        else:
            path = f"{parsed.path.rstrip('/')}/api/v1/client"
        return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))

    def request(self, payload: dict) -> dict:
        """Send a legacy payload with timestamp and nonce if they are absent."""

        body = dict(payload)
        body.setdefault("timestamp", timestamp_ms())
        body.setdefault("nonce", new_nonce())
        try:
            response = self.http.post(
                self.endpoint,
                data=encrypt_legacy_v1_packet(self.key, body),
                headers={
                    "Content-Type": "application/octet-stream",
                    "Accept": "application/octet-stream",
                    "Accept-Encoding": "identity",
                    "User-Agent": "jur10n-client-v1-compat-example/1.0",
                },
                timeout=DEFAULT_TIMEOUT,
            )
        except requests.exceptions.RequestException as error:
            raise TransportError(f"legacy v1 network connection failed: {error}") from error
        if response.status_code != 200:
            raise TransportError(f"legacy v1 HTTP transport status {response.status_code}")
        envelope = decrypt_legacy_v1_response(self.key, response.content)
        if not envelope.get("ok"):
            raise ApiError(envelope.get("error", "UNKNOWN_ERROR"), envelope.get("status", 400), envelope)
        return envelope


class ApiWorker(QThread):
    """Run blocking requests outside the Qt GUI thread."""

    completed = pyqtSignal(object)
    failed = pyqtSignal(object)

    def __init__(self, operation: Callable[[], Any]):
        super().__init__()
        self.operation = operation

    def run(self) -> None:
        try:
            self.completed.emit(self.operation())
        except Exception as error:  # Surface typed client errors in the GUI.
            self.failed.emit(error)


def _json_default(value: Any) -> Any:
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    if isinstance(value, Path):
        return str(value)
    return str(value)

class Window(QMainWindow):
    """Tabbed tester covering every v2 client operation against the server."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("jur10n v2 服务器功能测试台")
        self.setMinimumSize(860, 640)
        self.client: "V2Client | None" = None
        self.worker: "ApiWorker | None" = None
        self.tabs = QTabWidget()
        self.tabs.addTab(self.build_session_tab(), "会话")
        self.tabs.addTab(self.build_variables_tab(), "变量")
        self.tabs.addTab(self.build_report_tab(), "上报")
        self.tabs.addTab(self.build_files_tab(), "文件")
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setMinimumHeight(140)
        self.output.setPlaceholderText("请求结果与错误会显示在这里（session token 不会完整展示）")
        layout = QVBoxLayout()
        layout.addWidget(self.tabs)
        layout.addWidget(QLabel("输出"))
        layout.addWidget(self.output)
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def log(self, value) -> None:
        self.output.setPlainText(json.dumps(value, ensure_ascii=False, indent=2, default=_json_default))

    def show_result(self, result) -> None:
        self.log(result)

    def show_error(self, error) -> None:
        if isinstance(error, ApiError):
            self.log({"type": type(error).__name__, "error": error.code, "status": error.status})
        else:
            self.output.setPlainText(f"{type(error).__name__}: {error}")

    def run_async(self, operation, on_success=None) -> None:
        if self.worker is not None and self.worker.isRunning():
            self.output.setPlainText("上一个请求仍在执行，请稍候")
            return
        self.worker = ApiWorker(operation)
        self.worker.completed.connect(on_success or self.show_result)
        self.worker.failed.connect(self.show_error)
        self.worker.start()

    def config_from_form(self) -> V2ClientConfig:
        try:
            version = int(self.key_version.text().strip())
        except ValueError as error:
            raise ConfigurationError("key version 必须是整数") from error
        return V2ClientConfig(
            base_url=self.base_url.text().strip(),
            software_slot=self.software_slot.text().strip(),
            key_version=version,
            key=self.key.text().strip(),
        )

    def require_client(self) -> V2Client:
        if self.client is None or not self.client.authenticated:
            raise SessionError("请先在「会话」标签登录")
        return self.client

    def build_session_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        self.base_url = QLineEdit("http://127.0.0.1:3000")
        self.software_slot = QLineEdit("legacy")
        self.key_version = QLineEdit("1")
        self.key = QLineEdit()
        self.key.setEchoMode(QLineEdit.EchoMode.Password)
        self.key.setPlaceholderText("32 字节软件密钥（base64url），由管理端一次性导出")
        self.license_code = QLineEdit()
        self.machine_proof = QLineEdit()
        self.machine_proof.setPlaceholderText("启用机器校验时必填的机器证明")
        form = QFormLayout()
        form.addRow("Base URL", self.base_url)
        form.addRow("Software slot", self.software_slot)
        form.addRow("Key version", self.key_version)
        form.addRow("软件密钥", self.key)
        form.addRow("卡密", self.license_code)
        form.addRow("机器证明", self.machine_proof)
        layout.addLayout(form)
        buttons = QHBoxLayout()
        for label, handler in (("登录", self.login), ("心跳", self.heartbeat), ("退出本地会话", self.logout_local)):
            button = QPushButton(label)
            button.clicked.connect(handler)
            buttons.addWidget(button)
        layout.addLayout(buttons)
        layout.addStretch(1)
        return page

    def login(self) -> None:
        try:
            client = V2Client(self.config_from_form())
            code = self.license_code.text().strip()
            proof = self.machine_proof.text().strip() or None
            if not code:
                raise ConfigurationError("卡密不能为空")
        except Exception as error:
            self.show_error(error)
            return

        def completed(result):
            self.client = client
            masked = dict(result)
            if masked.get("sessionToken"):
                masked["sessionToken"] = str(masked["sessionToken"])[:6] + "…(已保存，不完整展示)"
            self.log(masked)

        self.run_async(lambda: client.login(code, proof), completed)

    def heartbeat(self) -> None:
        try:
            client = self.require_client()
        except Exception as error:
            self.show_error(error)
            return
        self.run_async(client.heartbeat)

    def logout_local(self) -> None:
        if self.client is None:
            self.output.setPlainText("当前没有本地会话")
            return
        self.client.clear_session()
        self.client = None
        self.output.setPlainText("本地会话已清除")

    def build_variables_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        self.since_version = QLineEdit("0")
        form = QFormLayout()
        form.addRow("since_version（增量游标）", self.since_version)
        layout.addLayout(form)
        pull = QPushButton("拉取变量")
        pull.clicked.connect(self.pull_variables)
        layout.addWidget(pull)
        layout.addStretch(1)
        return page

    def pull_variables(self) -> None:
        try:
            client = self.require_client()
            since = int(self.since_version.text().strip() or "0")
        except Exception as error:
            self.show_error(error)
            return
        self.run_async(lambda: client.pull_variables(since))

    def build_report_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        self.data_slot = QLineEdit("legacy")
        self.report_mode = QComboBox()
        self.report_mode.addItem("覆写 overwrite", "overwrite")
        self.report_mode.addItem("追加 append", "append")
        self.report_data = QTextEdit('{"event": "ping"}')
        form = QFormLayout()
        form.addRow("数据槽 slug", self.data_slot)
        form.addRow("写入模式", self.report_mode)
        layout.addLayout(form)
        layout.addWidget(QLabel("上报 JSON"))
        layout.addWidget(self.report_data)
        report = QPushButton("上报数据")
        report.clicked.connect(self.report)
        layout.addWidget(report)
        return page

    def report(self) -> None:
        try:
            client = self.require_client()
            data = json.loads(self.report_data.toPlainText())
            slot = self.data_slot.text().strip()
            mode = str(self.report_mode.currentData() or "overwrite")
        except (json.JSONDecodeError, ClientError, ValueError) as error:
            self.show_error(error)
            return
        self.run_async(lambda: client.report(data, slot, mode))

    def build_files_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        manifest = QPushButton("获取文件清单（manifest）")
        manifest.clicked.connect(self.manifest)
        announcement = QPushButton("读取公开公告")
        announcement.clicked.connect(self.announcement)
        layout.addWidget(manifest)
        layout.addWidget(announcement)
        self.file_id = QLineEdit()
        self.file_id.setPlaceholderText("manifest 返回的资源 id")
        self.destination = QLineEdit()
        browse = QPushButton("浏览…")
        browse.clicked.connect(self.choose_destination)
        destination_row = QWidget()
        destination_layout = QHBoxLayout(destination_row)
        destination_layout.setContentsMargins(0, 0, 0, 0)
        destination_layout.addWidget(self.destination)
        destination_layout.addWidget(browse)
        form = QFormLayout()
        form.addRow("文件 ID", self.file_id)
        form.addRow("保存到", destination_row)
        layout.addLayout(form)
        download = QPushButton("下载并校验 SHA-256")
        download.clicked.connect(self.download_file)
        layout.addWidget(download)
        layout.addStretch(1)
        return page

    def manifest(self) -> None:
        try:
            client = self.require_client()
        except Exception as error:
            self.show_error(error)
            return
        self.run_async(client.manifest)

    def announcement(self) -> None:
        try:
            config = self.config_from_form()
            client = V2Client(config)
        except Exception as error:
            self.show_error(error)
            return
        self.run_async(client.announcement)

    def choose_destination(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "选择保存位置")
        if path:
            self.destination.setText(path)

    def download_file(self) -> None:
        try:
            client = self.require_client()
            file_id = int(self.file_id.text().strip())
            destination = self.destination.text().strip()
            if not destination:
                raise ConfigurationError("请选择保存路径")
        except (ClientError, ValueError) as error:
            self.show_error(error)
            return
        self.run_async(lambda: client.download_file(file_id, destination))


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = Window()
    window.show()
    sys.exit(app.exec())
