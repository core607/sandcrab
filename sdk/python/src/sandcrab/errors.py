"""Structured errors for the native Sandcrab Python client."""
from __future__ import annotations


class SandcrabError(RuntimeError):
    """HTTP error returned by the Sandcrab daemon."""

    def __init__(self, status: int, code: str, *, recovery_id: str | None = None):
        self.status = status
        self.code = code
        self.recovery_id = recovery_id
        suffix = f" (recoveryId={recovery_id})" if recovery_id else ""
        super().__init__(f"Sandcrab API: HTTP {status} {code}{suffix}")


class TransportUncertainError(RuntimeError):
    """Transport failed after submitting a mutating request; inspect `recovery_id` instead of reposting."""

    def __init__(self, operation: str, recovery_id: str, cause: BaseException | None = None):
        self.operation = operation
        self.recovery_id = recovery_id
        self.cause = cause
        super().__init__(
            f"{operation} reply was lost; inspect {recovery_id} instead of submitting a new ID"
        )


class CommandFailedError(RuntimeError):
    """Raised when `check=True` and a run completes in a non-succeeded terminal state."""

    def __init__(self, run: dict):
        self.run = run
        state = run.get("state", "failed")
        result = run.get("result") or {}
        exit_code = result.get("exitCode")
        detail = f"exitCode={exit_code}" if exit_code is not None else f"code={result.get('code', state)}"
        super().__init__(f"Sandbox command {run.get('id')} ended with state={state} ({detail})")


class ProtocolError(RuntimeError):
    """Wire framing, epoch, checksum or host-call identity mismatch."""
