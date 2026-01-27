"""Screen navigation and exploration for dynamic analysis."""

import time
import logging
import hashlib
from collections import deque
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple, Any, Callable

from ..device.base import DeviceInterface, Element, ScreenState
from .element_finder import ElementFinder

logger = logging.getLogger(__name__)


@dataclass
class ScreenSignature:
    """Unique signature for a screen state."""
    activity: str
    package: str
    element_hash: str
    clickable_count: int
    input_count: int

    def __hash__(self):
        return hash((self.activity, self.element_hash))

    def __eq__(self, other):
        if not isinstance(other, ScreenSignature):
            return False
        return self.activity == other.activity and self.element_hash == other.element_hash


@dataclass
class NavigationAction:
    """Represents a navigation action."""
    action_type: str  # 'click', 'scroll', 'back', 'input', 'swipe'
    element: Optional[Element] = None
    x: Optional[int] = None
    y: Optional[int] = None
    text: Optional[str] = None
    direction: Optional[str] = None


@dataclass
class ExplorationResult:
    """Result of app exploration."""
    screens_visited: int = 0
    unique_screens: int = 0
    clickables_found: int = 0
    inputs_found: int = 0
    webviews_found: int = 0
    activities_discovered: List[str] = field(default_factory=list)
    navigation_graph: Dict[str, List[str]] = field(default_factory=dict)
    screenshots: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class AppNavigator:
    """Navigate and explore Android applications."""

    # Common dialog dismissal patterns
    DISMISSAL_PATTERNS = [
        {"text": "OK"},
        {"text": "Allow"},
        {"text": "ALLOW"},
        {"text": "Accept"},
        {"text": "Got it"},
        {"text": "GOT IT"},
        {"text": "Continue"},
        {"text": "Skip"},
        {"text": "SKIP"},
        {"text": "Later"},
        {"text": "Not Now"},
        {"text": "No Thanks"},
        {"text": "Close"},
        {"contentDescription": "Close"},
        {"resourceId": "android:id/button1"},  # Positive button
    ]

    def __init__(self, device: DeviceInterface, package: str):
        self._device = device
        self._package = package
        self._finder = ElementFinder(device)
        self._visited_screens: Set[ScreenSignature] = set()
        self._navigation_history: List[NavigationAction] = []
        self._screen_graph: Dict[ScreenSignature, List[Tuple[NavigationAction, ScreenSignature]]] = {}

    def _get_screen_signature(self, state: ScreenState) -> ScreenSignature:
        """Generate unique signature for current screen."""
        # Create hash from key elements
        elements_str = "|".join([
            f"{e.resource_id or ''},{e.text or ''},{e.class_name or ''}"
            for e in state.elements[:20]  # Limit to prevent huge strings
        ])
        element_hash = hashlib.md5(elements_str.encode()).hexdigest()[:8]

        return ScreenSignature(
            activity=state.activity,
            package=state.package,
            element_hash=element_hash,
            clickable_count=len(state.clickables),
            input_count=len(state.input_fields)
        )

    def get_current_screen(self) -> ScreenState:
        """Get current screen state."""
        return self._device.get_screen_state()

    def is_in_target_app(self) -> bool:
        """Check if we're still in the target app."""
        package, _ = self._device.get_current_activity()
        return package == self._package

    def navigate_back(self) -> bool:
        """Press back and check if still in app."""
        self._device.press_back()
        time.sleep(0.5)
        return self.is_in_target_app()

    def navigate_home(self) -> None:
        """Return to app's main activity."""
        self._device.stop_app(self._package)
        time.sleep(0.3)
        self._device.launch_app(self._package)
        time.sleep(1.0)

    def dismiss_dialog(self) -> bool:
        """Try to dismiss any visible dialog.

        Returns:
            True if a dialog was dismissed.
        """
        for pattern in self.DISMISSAL_PATTERNS:
            elem = self._device.find_element(**pattern)
            if elem and elem.clickable:
                self._device.click(elem)
                time.sleep(0.5)
                return True

        # Try pressing back as last resort
        state_before = self._get_screen_signature(self.get_current_screen())
        self._device.press_back()
        time.sleep(0.3)
        state_after = self._get_screen_signature(self.get_current_screen())

        return state_before != state_after

    def find_clickables(self) -> List[Element]:
        """Find all clickable elements on current screen."""
        return self._finder.find_clickable()

    def find_inputs(self) -> List[Element]:
        """Find all input fields on current screen."""
        return self._finder.find_input_fields()

    def find_webviews(self) -> List[Element]:
        """Find all WebView elements."""
        return self._finder.find_webviews()

    def navigate_to_activity(self, activity: str) -> bool:
        """Navigate to specific activity.

        Args:
            activity: Activity class name (with or without package).

        Returns:
            True if navigation successful.
        """
        if not activity.startswith(self._package):
            if activity.startswith("."):
                activity = self._package + activity
            else:
                activity = f"{self._package}.{activity}"

        success = self._device.start_activity(self._package, activity)
        if success:
            time.sleep(1.0)
            _, current = self._device.get_current_activity()
            return activity in current

        return False

    def explore(self, max_depth: int = 5, max_screens: int = 50,
                screenshot_dir: Optional[str] = None,
                on_screen: Optional[Callable[[ScreenState], None]] = None) -> ExplorationResult:
        """Explore app screens using BFS.

        Args:
            max_depth: Maximum exploration depth.
            max_screens: Maximum screens to visit.
            screenshot_dir: Directory for screenshots (optional).
            on_screen: Callback for each screen visited.

        Returns:
            ExplorationResult with discovered screens and elements.
        """
        result = ExplorationResult()
        queue = deque([(0, self._navigation_history.copy())])  # (depth, path)
        initial_state = self.get_current_screen()
        initial_sig = self._get_screen_signature(initial_state)
        self._visited_screens.add(initial_sig)

        while queue and result.unique_screens < max_screens:
            depth, path = queue.popleft()

            if depth > max_depth:
                continue

            # Reset to initial state and replay path
            if path:
                self.navigate_home()
                time.sleep(0.5)
                for action in path:
                    self._execute_action(action)
                    time.sleep(0.3)

            state = self.get_current_screen()
            signature = self._get_screen_signature(state)

            # Record visit
            result.screens_visited += 1
            if state.activity and state.activity not in result.activities_discovered:
                result.activities_discovered.append(state.activity)

            # Count elements
            clickables = state.clickables
            inputs = state.input_fields
            webviews = state.webviews

            result.clickables_found += len(clickables)
            result.inputs_found += len(inputs)
            result.webviews_found += len(webviews)

            # Take screenshot if requested
            if screenshot_dir:
                screenshot_path = f"{screenshot_dir}/screen_{result.screens_visited}.png"
                if self._device.take_screenshot(screenshot_path):
                    result.screenshots.append(screenshot_path)

            # Callback
            if on_screen:
                try:
                    on_screen(state)
                except Exception as e:
                    result.errors.append(f"Callback error: {e}")

            # Try to dismiss any dialogs
            self.dismiss_dialog()

            # Explore clickable elements
            for elem in clickables[:10]:  # Limit per screen
                if not self.is_in_target_app():
                    self.navigate_home()
                    break

                action = NavigationAction(
                    action_type="click",
                    element=elem,
                    x=elem.bounds.center[0] if elem.bounds else None,
                    y=elem.bounds.center[1] if elem.bounds else None
                )

                # Execute action
                self._execute_action(action)
                time.sleep(0.5)

                # Check new screen
                if self.is_in_target_app():
                    new_state = self.get_current_screen()
                    new_sig = self._get_screen_signature(new_state)

                    if new_sig not in self._visited_screens:
                        self._visited_screens.add(new_sig)
                        result.unique_screens += 1

                        # Record navigation
                        if signature.activity not in result.navigation_graph:
                            result.navigation_graph[signature.activity] = []
                        if new_sig.activity not in result.navigation_graph[signature.activity]:
                            result.navigation_graph[signature.activity].append(new_sig.activity)

                        # Add to queue for further exploration
                        new_path = path + [action]
                        queue.append((depth + 1, new_path))

                    # Go back
                    self.navigate_back()
                else:
                    # Return to app
                    self.navigate_home()

            # Try scrolling to reveal more content
            self._device.scroll("down", 0.5)
            time.sleep(0.3)

        logger.info(f"Exploration complete: {result.unique_screens} unique screens, "
                   f"{result.screens_visited} total visits")

        return result

    def _execute_action(self, action: NavigationAction) -> bool:
        """Execute a navigation action."""
        try:
            if action.action_type == "click":
                if action.element:
                    return self._device.click(action.element)
                elif action.x is not None and action.y is not None:
                    return self._device.click(x=action.x, y=action.y)

            elif action.action_type == "scroll":
                return self._device.scroll(action.direction or "down")

            elif action.action_type == "back":
                return self._device.press_back()

            elif action.action_type == "input":
                if action.element and action.text:
                    return self._device.input_text(action.text, action.element)

            elif action.action_type == "swipe":
                if action.direction:
                    return self._device.scroll(action.direction)

            return False

        except Exception as e:
            logger.error(f"Action failed: {e}")
            return False

    def find_attack_surfaces(self) -> Dict[str, List[Element]]:
        """Find potential attack surfaces on current screen.

        Returns:
            Dictionary of attack surface type to elements.
        """
        surfaces = {
            "webviews": [],
            "input_fields": [],
            "deep_link_handlers": [],
            "file_pickers": [],
            "permission_requesters": [],
        }

        state = self.get_current_screen()

        # WebViews
        surfaces["webviews"] = state.webviews

        # Input fields
        surfaces["input_fields"] = state.input_fields

        # Look for file/image pickers
        for elem in state.elements:
            if elem.text:
                text_lower = elem.text.lower()
                if any(kw in text_lower for kw in ["attach", "upload", "pick", "choose file", "select image"]):
                    surfaces["file_pickers"].append(elem)
            if elem.content_desc:
                desc_lower = elem.content_desc.lower()
                if any(kw in desc_lower for kw in ["attach", "upload", "pick", "choose"]):
                    surfaces["file_pickers"].append(elem)

        return surfaces

    def get_screen_text(self) -> List[str]:
        """Get all text visible on current screen."""
        return self._finder.find_visible_text()

    def wait_for_screen(self, activity: Optional[str] = None,
                        text: Optional[str] = None,
                        timeout: float = 10.0) -> bool:
        """Wait for specific screen to appear.

        Args:
            activity: Expected activity name (partial match).
            text: Expected text on screen.
            timeout: Maximum wait time.

        Returns:
            True if screen appeared within timeout.
        """
        start = time.time()

        while time.time() - start < timeout:
            state = self.get_current_screen()

            if activity and activity in state.activity:
                return True

            if text:
                for elem in state.elements:
                    if elem.text and text in elem.text:
                        return True

            time.sleep(0.5)

        return False

    def scroll_to_find(self, **selectors) -> Optional[Element]:
        """Scroll to find element.

        Scrolls down up to 5 times looking for element.
        """
        for _ in range(5):
            elem = self._device.find_element(**selectors)
            if elem:
                return elem

            self._device.scroll("down", 0.4)
            time.sleep(0.5)

        return None

    def click_and_wait(self, element: Element, wait_activity: Optional[str] = None,
                       timeout: float = 5.0) -> bool:
        """Click element and wait for result.

        Args:
            element: Element to click.
            wait_activity: Activity to wait for (optional).
            timeout: Wait timeout.

        Returns:
            True if click was successful and wait condition met.
        """
        state_before = self._get_screen_signature(self.get_current_screen())

        if not self._device.click(element):
            return False

        if wait_activity:
            return self.wait_for_screen(activity=wait_activity, timeout=timeout)

        # Wait for screen change
        time.sleep(0.5)
        state_after = self._get_screen_signature(self.get_current_screen())

        return state_before != state_after
