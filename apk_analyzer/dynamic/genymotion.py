"""
Genymotion Emulator Controller

Handles connection and control of Genymotion emulators for dynamic analysis.
Also supports standard Android emulators and physical devices via ADB.
"""

import subprocess
import time
import os
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple
from pathlib import Path


@dataclass
class Device:
    """Represents a connected Android device/emulator."""
    serial: str
    model: str
    state: str
    is_emulator: bool
    is_genymotion: bool = False
    api_level: Optional[int] = None


class GenymotionController:
    """
    Controls Genymotion emulator for dynamic testing.
    Falls back to standard ADB for other emulators/devices.
    """

    def __init__(self, adb_path: str = "adb", genymotion_path: Optional[str] = None):
        self.adb_path = adb_path
        self.genymotion_path = genymotion_path or self._find_genymotion()
        self.current_device: Optional[Device] = None
        self._logcat_process: Optional[subprocess.Popen] = None

    def _find_genymotion(self) -> Optional[str]:
        """Find Genymotion installation path."""
        common_paths = [
            "/Applications/Genymotion.app/Contents/MacOS",
            "/opt/genymotion",
            os.path.expanduser("~/genymotion"),
            "C:\\Program Files\\Genymobile\\Genymotion",
        ]
        for path in common_paths:
            if os.path.exists(path):
                return path
        return None

    def list_devices(self) -> List[Device]:
        """List all connected devices and emulators."""
        devices = []
        try:
            result = subprocess.run(
                [self.adb_path, "devices", "-l"],
                capture_output=True, text=True, timeout=10
            )

            for line in result.stdout.strip().split('\n')[1:]:
                if not line.strip() or 'offline' in line:
                    continue

                parts = line.split()
                if len(parts) < 2:
                    continue

                serial = parts[0]
                state = parts[1]

                # Parse device info
                model = "Unknown"
                for part in parts[2:]:
                    if part.startswith("model:"):
                        model = part.split(":")[1]
                        break

                is_emulator = serial.startswith("emulator-") or "vbox" in serial.lower()
                is_genymotion = "vbox" in serial.lower() or self._check_genymotion(serial)

                # Get API level
                api_level = self._get_api_level(serial)

                devices.append(Device(
                    serial=serial,
                    model=model,
                    state=state,
                    is_emulator=is_emulator,
                    is_genymotion=is_genymotion,
                    api_level=api_level,
                ))

        except subprocess.TimeoutExpired:
            print("[!] ADB timeout - is the daemon running?")
        except FileNotFoundError:
            print(f"[!] ADB not found at {self.adb_path}")

        return devices

    def _check_genymotion(self, serial: str) -> bool:
        """Check if device is a Genymotion emulator."""
        try:
            result = subprocess.run(
                [self.adb_path, "-s", serial, "shell", "getprop", "ro.genymotion.version"],
                capture_output=True, text=True, timeout=5
            )
            return bool(result.stdout.strip())
        except:
            return False

    def _get_api_level(self, serial: str) -> Optional[int]:
        """Get Android API level of device."""
        try:
            result = subprocess.run(
                [self.adb_path, "-s", serial, "shell", "getprop", "ro.build.version.sdk"],
                capture_output=True, text=True, timeout=5
            )
            return int(result.stdout.strip())
        except:
            return None

    def connect(self, serial: Optional[str] = None) -> bool:
        """Connect to a device/emulator."""
        devices = self.list_devices()

        if not devices:
            print("[!] No devices found. Start Genymotion or connect a device.")
            return False

        if serial:
            # Find specific device
            for device in devices:
                if device.serial == serial:
                    self.current_device = device
                    break
            if not self.current_device:
                print(f"[!] Device {serial} not found")
                return False
        else:
            # Prefer Genymotion, then emulator, then physical
            geny_devices = [d for d in devices if d.is_genymotion and d.state == 'device']
            emu_devices = [d for d in devices if d.is_emulator and d.state == 'device']
            all_devices = [d for d in devices if d.state == 'device']

            if geny_devices:
                self.current_device = geny_devices[0]
            elif emu_devices:
                self.current_device = emu_devices[0]
            elif all_devices:
                self.current_device = all_devices[0]
            else:
                print("[!] No ready devices found")
                return False

        print(f"[+] Connected to: {self.current_device.serial} ({self.current_device.model})")
        if self.current_device.is_genymotion:
            print("[+] Genymotion emulator detected")
        return True

    def install_apk(self, apk_path: str, reinstall: bool = True) -> bool:
        """Install APK on the connected device.

        Supports:
        - Single APK files (.apk)
        - Split APK bundles (.apkm, .xapk)
        - Directories containing split APKs
        """
        if not self.current_device:
            print("[!] No device connected")
            return False

        if not os.path.exists(apk_path):
            print(f"[!] APK not found: {apk_path}")
            return False

        # Check if this is a split APK bundle
        apk_files = []
        temp_dir = None

        if apk_path.lower().endswith(('.apkm', '.xapk')):
            # Extract split APK bundle
            import zipfile
            import tempfile

            temp_dir = tempfile.mkdtemp(prefix="apk_install_")
            try:
                print(f"[*] Extracting split APK bundle: {os.path.basename(apk_path)}")
                with zipfile.ZipFile(apk_path, 'r') as zf:
                    for name in zf.namelist():
                        if name.endswith('.apk'):
                            extracted = os.path.join(temp_dir, os.path.basename(name))
                            with zf.open(name) as src, open(extracted, 'wb') as dst:
                                dst.write(src.read())
                            apk_files.append(extracted)

                if not apk_files:
                    print("[!] No APK files found in bundle")
                    return False

                print(f"[+] Extracted {len(apk_files)} APK files")
            except Exception as e:
                print(f"[!] Failed to extract bundle: {e}")
                if temp_dir:
                    import shutil
                    shutil.rmtree(temp_dir, ignore_errors=True)
                return False

        elif os.path.isdir(apk_path):
            # Directory with split APKs
            apk_files = [os.path.join(apk_path, f) for f in os.listdir(apk_path) if f.endswith('.apk')]
            if not apk_files:
                print("[!] No APK files found in directory")
                return False
        else:
            # Single APK file
            apk_files = [apk_path]

        # Install using appropriate method
        try:
            if len(apk_files) == 1:
                # Single APK - standard install
                cmd = [self.adb_path, "-s", self.current_device.serial, "install"]
                if reinstall:
                    cmd.append("-r")
                cmd.append(apk_files[0])
                print(f"[*] Installing APK: {os.path.basename(apk_files[0])}")
            else:
                # Multiple APKs - use install-multiple
                cmd = [self.adb_path, "-s", self.current_device.serial, "install-multiple"]
                if reinstall:
                    cmd.append("-r")
                cmd.extend(apk_files)
                print(f"[*] Installing split APKs ({len(apk_files)} files)...")

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            if "Success" in result.stdout:
                print("[+] APK installed successfully")
                return True
            else:
                print(f"[!] Install failed: {result.stdout} {result.stderr}")
                return False
        except subprocess.TimeoutExpired:
            print("[!] Install timeout")
            return False
        finally:
            # Cleanup temp directory
            if temp_dir:
                import shutil
                shutil.rmtree(temp_dir, ignore_errors=True)

    def uninstall_app(self, package_name: str) -> bool:
        """Uninstall an app from the device."""
        if not self.current_device:
            return False

        try:
            result = subprocess.run(
                [self.adb_path, "-s", self.current_device.serial, "uninstall", package_name],
                capture_output=True, text=True, timeout=30
            )
            return "Success" in result.stdout
        except:
            return False

    def launch_app(self, package_name: str, activity: Optional[str] = None) -> bool:
        """Launch an app on the device."""
        if not self.current_device:
            return False

        if activity:
            cmd = [
                self.adb_path, "-s", self.current_device.serial,
                "shell", "am", "start", "-n", f"{package_name}/{activity}"
            ]
        else:
            # Use monkey to launch main activity
            cmd = [
                self.adb_path, "-s", self.current_device.serial,
                "shell", "monkey", "-p", package_name,
                "-c", "android.intent.category.LAUNCHER", "1"
            ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except:
            return False

    def stop_app(self, package_name: str) -> bool:
        """Force stop an app."""
        if not self.current_device:
            return False

        try:
            subprocess.run(
                [self.adb_path, "-s", self.current_device.serial,
                 "shell", "am", "force-stop", package_name],
                capture_output=True, timeout=10
            )
            return True
        except:
            return False

    def clear_app_data(self, package_name: str) -> bool:
        """Clear app data and cache."""
        if not self.current_device:
            return False

        try:
            subprocess.run(
                [self.adb_path, "-s", self.current_device.serial,
                 "shell", "pm", "clear", package_name],
                capture_output=True, timeout=10
            )
            return True
        except:
            return False

    def execute_command(self, command: str, timeout: int = 30) -> Tuple[bool, str]:
        """Execute an ADB shell command."""
        if not self.current_device:
            return False, "No device connected"

        # Handle full adb commands vs shell commands
        if command.startswith("adb shell "):
            # Full adb shell command - pass the shell part as a single string
            shell_cmd = command[10:]  # Remove "adb shell "
            cmd = [self.adb_path, "-s", self.current_device.serial, "shell", shell_cmd]
        elif command.startswith("adb "):
            # Other adb command (not shell) - need to parse carefully
            # Remove "adb " prefix and use shlex for proper parsing
            import shlex
            try:
                cmd_parts = shlex.split(command[4:])  # Remove "adb "
                cmd = [self.adb_path, "-s", self.current_device.serial] + cmd_parts
            except ValueError:
                # Fallback to simple split if shlex fails
                cmd_parts = command[4:].split()
                cmd = [self.adb_path, "-s", self.current_device.serial] + cmd_parts
        else:
            # Plain shell command - pass as single string to shell
            cmd = [self.adb_path, "-s", self.current_device.serial, "shell", command]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            output = result.stdout + result.stderr
            return result.returncode == 0, output
        except subprocess.TimeoutExpired:
            return False, "Command timeout"
        except Exception as e:
            return False, str(e)

    def take_screenshot(self, output_path: str) -> bool:
        """Take a screenshot and save to local file."""
        if not self.current_device:
            return False

        device_path = "/sdcard/screenshot.png"
        try:
            # Take screenshot on device
            subprocess.run(
                [self.adb_path, "-s", self.current_device.serial,
                 "shell", "screencap", "-p", device_path],
                capture_output=True, timeout=10
            )

            # Pull to local
            subprocess.run(
                [self.adb_path, "-s", self.current_device.serial,
                 "pull", device_path, output_path],
                capture_output=True, timeout=10
            )

            # Clean up
            subprocess.run(
                [self.adb_path, "-s", self.current_device.serial,
                 "shell", "rm", device_path],
                capture_output=True, timeout=5
            )

            return os.path.exists(output_path)
        except:
            return False

    def start_logcat(self, output_path: str, package_filter: Optional[str] = None) -> bool:
        """Start capturing logcat to file."""
        if not self.current_device:
            return False

        # Clear existing logs
        subprocess.run(
            [self.adb_path, "-s", self.current_device.serial, "logcat", "-c"],
            capture_output=True, timeout=5
        )

        cmd = [self.adb_path, "-s", self.current_device.serial, "logcat"]

        # Add package filter if specified
        if package_filter:
            # Get PID of package
            try:
                result = subprocess.run(
                    [self.adb_path, "-s", self.current_device.serial,
                     "shell", "pidof", package_filter],
                    capture_output=True, text=True, timeout=5
                )
                pid = result.stdout.strip()
                if pid:
                    cmd.extend(["--pid", pid])
            except:
                pass

        # Start logcat process
        try:
            with open(output_path, 'w') as f:
                self._logcat_process = subprocess.Popen(
                    cmd, stdout=f, stderr=subprocess.STDOUT
                )
            return True
        except:
            return False

    def stop_logcat(self) -> bool:
        """Stop logcat capture."""
        if self._logcat_process:
            self._logcat_process.terminate()
            self._logcat_process = None
            return True
        return False

    def get_installed_packages(self) -> List[str]:
        """Get list of installed packages."""
        if not self.current_device:
            return []

        try:
            result = subprocess.run(
                [self.adb_path, "-s", self.current_device.serial,
                 "shell", "pm", "list", "packages"],
                capture_output=True, text=True, timeout=30
            )
            packages = []
            for line in result.stdout.strip().split('\n'):
                if line.startswith("package:"):
                    packages.append(line[8:])
            return packages
        except:
            return []

    def is_app_running(self, package_name: str) -> bool:
        """Check if an app is currently running."""
        if not self.current_device:
            return False

        try:
            result = subprocess.run(
                [self.adb_path, "-s", self.current_device.serial,
                 "shell", "pidof", package_name],
                capture_output=True, text=True, timeout=5
            )
            return bool(result.stdout.strip())
        except:
            return False

    def set_proxy(self, host: str, port: int) -> bool:
        """Set HTTP proxy on device (for traffic interception)."""
        if not self.current_device:
            return False

        try:
            subprocess.run(
                [self.adb_path, "-s", self.current_device.serial,
                 "shell", "settings", "put", "global", "http_proxy", f"{host}:{port}"],
                capture_output=True, timeout=10
            )
            return True
        except:
            return False

    def clear_proxy(self) -> bool:
        """Clear HTTP proxy setting."""
        if not self.current_device:
            return False

        try:
            subprocess.run(
                [self.adb_path, "-s", self.current_device.serial,
                 "shell", "settings", "put", "global", "http_proxy", ":0"],
                capture_output=True, timeout=10
            )
            return True
        except:
            return False

    def input_text(self, text: str) -> bool:
        """Input text on device."""
        if not self.current_device:
            return False

        # Escape special characters
        escaped = text.replace(" ", "%s").replace("'", "\\'").replace('"', '\\"')

        try:
            subprocess.run(
                [self.adb_path, "-s", self.current_device.serial,
                 "shell", "input", "text", escaped],
                capture_output=True, timeout=10
            )
            return True
        except:
            return False

    def tap(self, x: int, y: int) -> bool:
        """Tap at coordinates."""
        if not self.current_device:
            return False

        try:
            subprocess.run(
                [self.adb_path, "-s", self.current_device.serial,
                 "shell", "input", "tap", str(x), str(y)],
                capture_output=True, timeout=10
            )
            return True
        except:
            return False

    def press_back(self) -> bool:
        """Press back button."""
        return self._key_event(4)

    def press_home(self) -> bool:
        """Press home button."""
        return self._key_event(3)

    def _key_event(self, keycode: int) -> bool:
        """Send key event."""
        if not self.current_device:
            return False

        try:
            subprocess.run(
                [self.adb_path, "-s", self.current_device.serial,
                 "shell", "input", "keyevent", str(keycode)],
                capture_output=True, timeout=10
            )
            return True
        except:
            return False
