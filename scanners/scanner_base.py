"""Scanner Base Class and Execution Framework for VulnX."""
from __future__ import annotations
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ScannerResult:
    scanner_name: str
    status: str  # 'Completed', 'Failed', 'Timed Out', 'Skipped'
    target: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    raw_output: Any = None
    execution_time: float = 0.0
    error: str = ""
    scanner_version: str = "Unknown"
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_success(self) -> bool:
        return self.status == "Completed" and not self.error


class ScannerBase(ABC):
    """Abstract base class for all security scanner adapters."""

    def __init__(self, name: str, default_timeout: int = 120):
        self.name = name
        self.default_timeout = default_timeout

    @abstractmethod
    def is_available(self) -> bool:
        """Check whether the scanner executable or service is available."""
        pass

    @abstractmethod
    def get_version(self) -> str:
        """Return the installed version of the scanner."""
        pass

    @abstractmethod
    def scan(self, target: str, **kwargs) -> ScannerResult:
        """Execute a security scan against the target."""
        pass

    def run_command(
        self,
        args: List[str],
        timeout: Optional[int] = None,
        cwd: Optional[str] = None
    ) -> tuple[int, str, str, float]:
        """
        Execute an external tool securely using argument arrays (never shell=True).
        Returns (returncode, stdout, stderr, elapsed_seconds).
        """
        effective_timeout = timeout or self.default_timeout
        start_time = time.time()
        try:
            process = subprocess.run(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=effective_timeout,
                cwd=cwd,
                shell=False
            )
            elapsed = time.time() - start_time
            return process.returncode, process.stdout, process.stderr, elapsed
        except subprocess.TimeoutExpired as exc:
            elapsed = time.time() - start_time
            stdout = exc.stdout or ""
            stderr = exc.stderr or f"Command timed out after {effective_timeout}s"
            return -1, stdout, stderr, elapsed
        except FileNotFoundError:
            elapsed = time.time() - start_time
            return 127, "", f"Executable not found: {args[0]}", elapsed
        except Exception as exc:
            elapsed = time.time() - start_time
            return 1, "", str(exc), elapsed

