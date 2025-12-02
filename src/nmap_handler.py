import subprocess
from typing import Iterable, List, Optional


class NmapExecutionError(RuntimeError):
    """Raised when the nmap subprocess fails."""


class NmapHandler:
    """Thin wrapper around the nmap CLI.

    It always runs nmap with XML output to stdout (-oX -) so that it can be
    parsed by :class:`NmapParser`.
    """

    def __init__(
        self,
        targets: Iterable[str],
        ports: Optional[str] = None,
        rate_limit: Optional[int] = None,
        extra_args: Optional[List[str]] = None,
        excludes: Optional[Iterable[str]] = None,
    ) -> None:
        self.targets = list(targets)
        self.ports = ports
        self.rate_limit = rate_limit
        self.extra_args = extra_args or []
        self.excludes = list(excludes) if excludes else []

    def build_command(self) -> List[str]:
        cmd: List[str] = ["nmap", "-oX", "-"]

        # Reasonable defaults: service detection + OS detection in one pass
        # can be slow, but good for a final project.
        if not any(a in ("-sS", "-sT", "-sU", "-sV") for a in self.extra_args):
            cmd.extend(["-sS", "-sV"])
        if "-O" not in self.extra_args and "-A" not in self.extra_args:
            cmd.append("-O")

        if self.ports:
            cmd.extend(["-p", self.ports])

        if self.rate_limit is not None:
            # -T2 is "polite", -T3 normal, -T4 faster; we keep it simple.
            if self.rate_limit <= 2000:
                cmd.append("-T2")
            else:
                cmd.append("-T3")

        if self.excludes:
            cmd.extend(["--exclude", ",".join(self.excludes)])

        cmd.extend(self.extra_args)
        cmd.extend(self.targets)
        return cmd

    def run_scan(self, timeout: int = 0) -> str:
        """Execute nmap and return raw XML output as text.

        :param timeout: Optional timeout in seconds (0 = no timeout).
        """
        cmd = self.build_command()

        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout or None,
                check=False,
            )
        except FileNotFoundError as e:
            raise NmapExecutionError(
                "nmap executable not found. Please install Nmap and ensure it is "
                "on your PATH."
            ) from e
        except subprocess.TimeoutExpired as e:
            raise NmapExecutionError(
                f"nmap scan timed out after {timeout} seconds."
            ) from e

        if completed.returncode != 0 or not completed.stdout.strip():
            raise NmapExecutionError(
                f"nmap failed with code {completed.returncode}: {completed.stderr}"
            )

        return completed.stdout
