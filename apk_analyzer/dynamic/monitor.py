"""
Application Monitor

Monitors the application during dynamic testing for:
- Crashes and exceptions
- Sensitive data in logs
- Network traffic indicators
- Security-relevant events
"""

import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Callable
from queue import Queue
from datetime import datetime


@dataclass
class SecurityEvent:
    """A security-relevant event detected during monitoring."""
    timestamp: datetime
    event_type: str  # 'crash', 'sensitive_log', 'network', 'permission', 'exception'
    severity: str    # 'critical', 'high', 'medium', 'low', 'info'
    description: str
    raw_data: str = ""
    context: Dict = field(default_factory=dict)


class AppMonitor:
    """
    Monitors an Android application for security-relevant events during testing.
    """

    # Patterns for sensitive data in logs
    SENSITIVE_PATTERNS = [
        (r'password["\s:=]+[^\s]{4,}', 'password'),
        (r'token["\s:=]+[^\s]{10,}', 'token'),
        (r'api[_-]?key["\s:=]+[^\s]{10,}', 'api_key'),
        (r'secret["\s:=]+[^\s]{4,}', 'secret'),
        (r'bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+', 'bearer_token'),
        (r'session[_-]?id["\s:=]+[^\s]{10,}', 'session'),
        (r'auth["\s:=]+[^\s]{10,}', 'auth'),
        (r'credit[_-]?card["\s:=]+\d{13,19}', 'credit_card'),
        (r'ssn["\s:=]+\d{3}-?\d{2}-?\d{4}', 'ssn'),
        (r'private[_-]?key', 'private_key'),
    ]

    # Patterns for crashes/exceptions
    CRASH_PATTERNS = [
        r'FATAL EXCEPTION',
        r'AndroidRuntime.*Error',
        r'java\.lang\.\w+Exception',
        r'Process.*has died',
        r'ANR in',
        r'Native crash',
        r'SIGSEGV',
        r'SIGABRT',
    ]

    def __init__(self, controller, package_name: str):
        self.controller = controller
        self.package_name = package_name
        self.events: List[SecurityEvent] = []
        self._monitoring = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._log_queue: Queue = Queue()
        self._callbacks: List[Callable[[SecurityEvent], None]] = []

    def start(self) -> bool:
        """Start monitoring the application."""
        if self._monitoring:
            return True

        self._monitoring = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()

        print(f"[+] Started monitoring {self.package_name}")
        return True

    def stop(self) -> List[SecurityEvent]:
        """Stop monitoring and return collected events."""
        self._monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=2)
        return self.events

    def add_callback(self, callback: Callable[[SecurityEvent], None]):
        """Add callback to be called when security event is detected."""
        self._callbacks.append(callback)

    def _monitor_loop(self):
        """Main monitoring loop."""
        # Start logcat process
        cmd = [
            self.controller.adb_path, "-s", self.controller.current_device.serial,
            "logcat", "-v", "time"
        ]

        try:
            # Get PID for filtering
            pid_result = subprocess.run(
                [self.controller.adb_path, "-s", self.controller.current_device.serial,
                 "shell", "pidof", self.package_name],
                capture_output=True, text=True, timeout=5
            )
            pid = pid_result.stdout.strip()
            if pid:
                cmd.extend(["--pid", pid])
        except:
            pass

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )

        try:
            while self._monitoring and process.poll() is None:
                line = process.stdout.readline()
                if line:
                    self._process_log_line(line.strip())
        finally:
            process.terminate()

    def _process_log_line(self, line: str):
        """Process a single log line for security events."""
        if not line:
            return

        # Check for crashes
        for pattern in self.CRASH_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                event = SecurityEvent(
                    timestamp=datetime.now(),
                    event_type='crash',
                    severity='critical',
                    description=f"Application crash detected",
                    raw_data=line,
                )
                self._add_event(event)
                return

        # Check for sensitive data
        for pattern, data_type in self.SENSITIVE_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                event = SecurityEvent(
                    timestamp=datetime.now(),
                    event_type='sensitive_log',
                    severity='high',
                    description=f"Sensitive data ({data_type}) found in logs",
                    raw_data=line[:200],  # Truncate to avoid storing actual secrets
                    context={'data_type': data_type},
                )
                self._add_event(event)
                return

        # Check for security-relevant system events
        if self.package_name in line:
            # Permission denied
            if 'Permission Denial' in line or 'permission denied' in line.lower():
                event = SecurityEvent(
                    timestamp=datetime.now(),
                    event_type='permission',
                    severity='info',
                    description="Permission denial logged",
                    raw_data=line,
                )
                self._add_event(event)

            # Security exceptions
            elif 'SecurityException' in line:
                event = SecurityEvent(
                    timestamp=datetime.now(),
                    event_type='exception',
                    severity='medium',
                    description="Security exception thrown",
                    raw_data=line,
                )
                self._add_event(event)

    def _add_event(self, event: SecurityEvent):
        """Add event to list and notify callbacks."""
        self.events.append(event)

        # Notify callbacks
        for callback in self._callbacks:
            try:
                callback(event)
            except:
                pass

    def get_events_by_type(self, event_type: str) -> List[SecurityEvent]:
        """Get all events of a specific type."""
        return [e for e in self.events if e.event_type == event_type]

    def get_events_by_severity(self, severity: str) -> List[SecurityEvent]:
        """Get all events of a specific severity."""
        return [e for e in self.events if e.severity == severity]

    def has_crashes(self) -> bool:
        """Check if any crashes were detected."""
        return any(e.event_type == 'crash' for e in self.events)

    def has_sensitive_leaks(self) -> bool:
        """Check if sensitive data was logged."""
        return any(e.event_type == 'sensitive_log' for e in self.events)

    def get_summary(self) -> Dict:
        """Get summary of monitored events."""
        summary = {
            'total_events': len(self.events),
            'crashes': len(self.get_events_by_type('crash')),
            'sensitive_leaks': len(self.get_events_by_type('sensitive_log')),
            'permission_issues': len(self.get_events_by_type('permission')),
            'exceptions': len(self.get_events_by_type('exception')),
            'by_severity': {
                'critical': len(self.get_events_by_severity('critical')),
                'high': len(self.get_events_by_severity('high')),
                'medium': len(self.get_events_by_severity('medium')),
                'low': len(self.get_events_by_severity('low')),
                'info': len(self.get_events_by_severity('info')),
            }
        }
        return summary


class NetworkMonitor:
    """
    Monitor network traffic during testing.
    Requires root or tcpdump on device.
    """

    def __init__(self, controller, output_path: str):
        self.controller = controller
        self.output_path = output_path
        self._process: Optional[subprocess.Popen] = None

    def start_capture(self) -> bool:
        """Start capturing network traffic."""
        # Check if tcpdump is available
        success, output = self.controller.execute_command("which tcpdump")
        if not success or not output.strip():
            print("[!] tcpdump not available on device (requires root)")
            return False

        # Start tcpdump
        device_pcap = "/sdcard/capture.pcap"
        cmd = [
            self.controller.adb_path, "-s", self.controller.current_device.serial,
            "shell", "tcpdump", "-w", device_pcap, "-s", "0"
        ]

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            return True
        except Exception as e:
            print(f"[!] Failed to start network capture: {e}")
            return False

    def stop_capture(self) -> Optional[str]:
        """Stop capture and pull pcap file."""
        if self._process:
            self._process.terminate()
            time.sleep(1)

            # Pull pcap file
            device_pcap = "/sdcard/capture.pcap"
            try:
                subprocess.run(
                    [self.controller.adb_path, "-s", self.controller.current_device.serial,
                     "pull", device_pcap, self.output_path],
                    capture_output=True, timeout=30
                )

                # Clean up
                subprocess.run(
                    [self.controller.adb_path, "-s", self.controller.current_device.serial,
                     "shell", "rm", device_pcap],
                    capture_output=True, timeout=5
                )

                return self.output_path
            except:
                pass

        return None
