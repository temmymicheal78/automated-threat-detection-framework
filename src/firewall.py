from __future__ import annotations

import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import paramiko

from src.config import Config

logger = logging.getLogger(__name__)


@dataclass
class FirewallAction:
    ip_address: str
    action: str           # "block" | "unblock" | "list"
    dry_run: bool
    success: bool
    command: str          # exact command string
    output: str
    timestamp: datetime
    error: Optional[str] = None


class FirewallController:
    def __init__(self, config: Config) -> None:
        self.dry_run: bool = config.dry_run
        self.firewall_host: str = config.firewall_host   # if set, use SSH remote mode
        self.firewall_user: str = config.firewall_user
        self.firewall_ssh_key: str = config.firewall_ssh_key
        # IPS mode blocks on FORWARD chain (prevents traffic reaching endpoint)
        # IDS mode blocks on INPUT chain (protects firewall only)
        self.firewall_mode: str = getattr(config, "firewall_mode", "ids")
        self._action_log: list[FirewallAction] = []
        self._blocked_ips: set[str] = set()  # in-memory tracking to prevent duplicates

    @property
    def _chain(self) -> str:
        """Return the iptables chain to use based on firewall mode."""
        return "FORWARD" if self.firewall_mode == "ips" else "INPUT"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def block_ip(self, ip_address: str) -> FirewallAction:
        """Block an IP address using iptables."""
        if ip_address in self._blocked_ips:
            logger.warning("IP %s is already blocked — skipping duplicate block", ip_address)
            action = FirewallAction(
                ip_address=ip_address,
                action="block",
                dry_run=self.dry_run,
                success=True,
                command="",
                output="already blocked",
                timestamp=datetime.now(),
                error=None,
            )
            self._action_log.append(action)
            return action

        # IPS mode: -I (insert at top) on FORWARD chain so DROP takes priority
        # IDS mode: -A (append) on INPUT chain
        flag = "-I" if self.firewall_mode == "ips" else "-A"
        cmd: list[str] = ["sudo", "iptables", flag, self._chain, "-s", ip_address, "-j", "DROP"]

        if self.firewall_host:
            action = self._run_remote(cmd, ip_address, "block")
        else:
            action = self._run_local(cmd, ip_address, "block")

        if action.success:
            self._blocked_ips.add(ip_address)

        self._action_log.append(action)
        return action

    def unblock_ip(self, ip_address: str) -> FirewallAction:
        """Unblock a previously blocked IP address."""
        cmd: list[str] = ["sudo", "iptables", "-D", self._chain, "-s", ip_address, "-j", "DROP"]

        if self.dry_run:
            action = FirewallAction(
                ip_address=ip_address,
                action="unblock",
                dry_run=True,
                success=True,
                command=str(cmd),
                output="dry-run",
                timestamp=datetime.now(),
                error=None,
            )
            self._action_log.append(action)
            return action

        if self.firewall_host:
            action = self._run_remote(cmd, ip_address, "unblock")
        else:
            action = self._run_local(cmd, ip_address, "unblock")

        if action.success:
            self._blocked_ips.discard(ip_address)

        self._action_log.append(action)
        return action

    def list_blocked(self) -> list[str]:
        """Return all currently blocked IPs."""
        if self.dry_run:
            return list(self._blocked_ips)

        cmd: list[str] = ["sudo", "iptables", "-L", self._chain, "-n"]

        if self.firewall_host:
            action = self._run_remote(cmd, "", "list")
        else:
            action = self._run_local(cmd, "", "list")

        if not action.success:
            logger.error("Failed to list iptables rules: %s", action.error)
            return []

        ips: list[str] = []
        for line in action.output.splitlines():
            if "DROP" in line:
                match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
                if match:
                    ips.append(match.group(1))
        return ips

    def get_action_log(self) -> list[FirewallAction]:
        """Return a copy of the action log."""
        return list(self._action_log)

    def is_blocked(self, ip: str) -> bool:
        """Check whether an IP is tracked as blocked in memory."""
        return ip in self._blocked_ips

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_local(self, cmd: list[str], ip_address: str, action: str) -> FirewallAction:
        """Execute an iptables command on the local machine."""
        if self.dry_run:
            logger.info("[DRY-RUN] Would execute: %s", cmd)
            return FirewallAction(
                ip_address=ip_address,
                action=action,
                dry_run=True,
                success=True,
                command=str(cmd),
                output="dry-run",
                timestamp=datetime.now(),
                error=None,
            )

        geteuid = getattr(os, "geteuid", None)
        if geteuid is not None and geteuid() != 0:
            raise PermissionError("Must run as root for live firewall commands")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
            )
            success = result.returncode == 0
            combined_output = result.stdout + result.stderr
            return FirewallAction(
                ip_address=ip_address,
                action=action,
                dry_run=False,
                success=success,
                command=str(cmd),
                output=combined_output,
                timestamp=datetime.now(),
                error=result.stderr if not success else None,
            )
        except FileNotFoundError as exc:
            logger.error("iptables not found: %s", exc)
            return FirewallAction(
                ip_address=ip_address,
                action=action,
                dry_run=False,
                success=False,
                command=str(cmd),
                output="",
                timestamp=datetime.now(),
                error=str(exc),
            )
        except subprocess.TimeoutExpired as exc:
            logger.error("iptables command timed out: %s", exc)
            return FirewallAction(
                ip_address=ip_address,
                action=action,
                dry_run=False,
                success=False,
                command=str(cmd),
                output="",
                timestamp=datetime.now(),
                error=str(exc),
            )

    def _run_remote(self, cmd: list[str], ip_address: str, action: str) -> FirewallAction:
        """Execute an iptables command on a remote host via SSH."""
        host = self.firewall_host

        if self.dry_run:
            logger.info("[DRY-RUN] Would SSH to %s and run: %s", host, cmd)
            return FirewallAction(
                ip_address=ip_address,
                action=action,
                dry_run=True,
                success=True,
                command=str(cmd),
                output="dry-run",
                timestamp=datetime.now(),
                error=None,
            )

        command_str = " ".join(cmd)

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connect_kwargs: dict = {
                "hostname": host,
                "username": self.firewall_user,
            }
            if self.firewall_ssh_key:
                connect_kwargs["key_filename"] = self.firewall_ssh_key

            client.connect(**connect_kwargs)

            _stdin, stdout, stderr = client.exec_command(command_str)
            out_data = stdout.read().decode("utf-8", errors="replace")
            err_data = stderr.read().decode("utf-8", errors="replace")
            exit_status = stdout.channel.recv_exit_status()
            client.close()

            success = exit_status == 0
            return FirewallAction(
                ip_address=ip_address,
                action=action,
                dry_run=False,
                success=success,
                command=command_str,
                output=out_data + err_data,
                timestamp=datetime.now(),
                error=err_data if not success else None,
            )
        except paramiko.SSHException as exc:
            logger.error("SSH error connecting to %s: %s", host, exc)
            return FirewallAction(
                ip_address=ip_address,
                action=action,
                dry_run=False,
                success=False,
                command=command_str,
                output="",
                timestamp=datetime.now(),
                error=str(exc),
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Unexpected error during remote firewall command: %s", exc)
            return FirewallAction(
                ip_address=ip_address,
                action=action,
                dry_run=False,
                success=False,
                command=command_str,
                output="",
                timestamp=datetime.now(),
                error=str(exc),
            )
