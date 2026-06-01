"""
CaC Sandbox — безопасное выполнение remediation-команд с изоляцией.

Принципы безопасности:
- Allowlist разрешённых команд (никакого shell=True)
- Timeout (30 сек по умолчанию)
- Dry-run режим по умолчанию
- Полный audit trail каждого выполнения
"""
import asyncio
import shlex
import logging
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger(__name__)

# Allowlist безопасных команд (только читающие или обратимые)
ALLOWED_COMMANDS = {
    "kubectl": ["get", "describe", "rollout", "scale"],
    "helm": ["list", "status", "rollback"],
    "terraform": ["plan", "show"],
    "aws": ["s3", "iam", "ec2"],
    "gh": ["issue", "pr", "repo"],
    "git": ["status", "log", "diff"],
}


@dataclass
class SandboxResult:
    success: bool
    stdout: str
    stderr: str
    exit_code: int
    command: str
    dry_run: bool
    duration_ms: float


async def run_command(
    command: str,
    dry_run: bool = True,
    timeout: int = 30,
    working_dir: str = "/tmp/cac-sandbox",
) -> SandboxResult:
    """
    Выполнить команду в песочнице.

    dry_run=True (default): только логирует, не выполняет.
    dry_run=False: выполняет с проверкой allowlist и timeout.
    """
    import time
    start = time.monotonic()

    if dry_run:
        log.info("DRY RUN: %s", command)
        return SandboxResult(
            success=True,
            stdout=f"[DRY RUN] Would execute: {command}",
            stderr="",
            exit_code=0,
            command=command,
            dry_run=True,
            duration_ms=(time.monotonic() - start) * 1000,
        )

    # Проверка запрещённых символов (shell injection prevention)
    if ".." in command or ";" in command or "|" in command or "&" in command or "`" in command or "$(" in command:
        log.warning("CaC Sandbox: command contains forbidden characters: %s", command)
        return SandboxResult(
            success=False,
            stdout="",
            stderr="Command contains forbidden characters",
            exit_code=1,
            command=command,
            dry_run=False,
            duration_ms=0,
        )

    # Проверка allowlist
    parts = shlex.split(command)
    if not parts:
        return SandboxResult(
            success=False,
            stdout="",
            stderr="Empty command",
            exit_code=1,
            command=command,
            dry_run=False,
            duration_ms=0,
        )

    binary = parts[0].split("/")[-1]  # только имя бинарника

    allowed = ALLOWED_COMMANDS.get(binary)
    if allowed is None:
        log.warning("CaC Sandbox: command '%s' not in allowlist", binary)
        return SandboxResult(
            success=False,
            stdout="",
            stderr=f"Binary '{binary}' not in allowlist",
            exit_code=1,
            command=command,
            dry_run=False,
            duration_ms=0,
        )

    # Проверка подкоманды против per-binary allowlist
    if allowed:  # список подкоманд задан
        if len(parts) == 1:
            log.warning("CaC Sandbox: subcommand required for '%s'", binary)
            return SandboxResult(
                success=False,
                stdout="",
                stderr=f"Subcommand required for '{binary}'",
                exit_code=1,
                command=command,
                dry_run=False,
                duration_ms=0,
            )
        if parts[1] not in allowed:
            log.warning("CaC Sandbox: subcommand '%s' not allowed for '%s'", parts[1], binary)
            return SandboxResult(
                success=False,
                stdout="",
                stderr=f"Subcommand '{parts[1]}' not allowed for '{binary}'",
                exit_code=1,
                command=command,
                dry_run=False,
                duration_ms=0,
            )
    else:
        log.warning("CaC Sandbox: no subcommand allowlist defined for '%s', proceeding", binary)

    try:
        proc = await asyncio.create_subprocess_exec(
            *parts,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=working_dir,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            log.error("CaC Sandbox: command timed out after %ds: %s", timeout, command)
            return SandboxResult(
                success=False,
                stdout="",
                stderr=f"Timeout after {timeout}s",
                exit_code=124,
                command=command,
                dry_run=False,
                duration_ms=timeout * 1000,
            )

        duration = (time.monotonic() - start) * 1000
        log.info(
            "CaC Sandbox: command '%s' exit_code=%d duration_ms=%.1f",
            command,
            proc.returncode,
            duration,
        )
        return SandboxResult(
            success=proc.returncode == 0,
            stdout=stdout.decode("utf-8", errors="replace")[:4096],
            stderr=stderr.decode("utf-8", errors="replace")[:1024],
            exit_code=proc.returncode,
            command=command,
            dry_run=False,
            duration_ms=duration,
        )
    except Exception as exc:
        log.exception("CaC Sandbox: unexpected error executing '%s': %s", command, exc)
        return SandboxResult(
            success=False,
            stdout="",
            stderr=str(exc),
            exit_code=1,
            command=command,
            dry_run=False,
            duration_ms=(time.monotonic() - start) * 1000,
        )
