"""App structure analyzer - parses decompiled code to build structural model."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from xml.etree import ElementTree as ET


@dataclass
class ClassInfo:
    """Information about a Java/Kotlin class."""
    name: str
    package: str
    full_name: str
    file_path: str
    extends: Optional[str] = None
    implements: List[str] = field(default_factory=list)
    methods: List['MethodInfo'] = field(default_factory=list)
    fields: List['FieldInfo'] = field(default_factory=list)
    is_activity: bool = False
    is_service: bool = False
    is_receiver: bool = False
    is_provider: bool = False
    is_fragment: bool = False
    is_abstract: bool = False
    is_interface: bool = False
    inner_classes: List[str] = field(default_factory=list)
    annotations: List[str] = field(default_factory=list)


@dataclass
class MethodInfo:
    """Information about a method."""
    name: str
    class_name: str
    return_type: str
    parameters: List[Tuple[str, str]]  # (type, name)
    modifiers: List[str] = field(default_factory=list)
    calls: List[str] = field(default_factory=list)  # Methods this method calls
    called_by: List[str] = field(default_factory=list)
    annotations: List[str] = field(default_factory=list)
    line_number: int = 0


@dataclass
class FieldInfo:
    """Information about a field."""
    name: str
    type: str
    modifiers: List[str] = field(default_factory=list)
    initial_value: Optional[str] = None


@dataclass
class ComponentInfo:
    """Android component information from manifest."""
    name: str
    type: str  # activity, service, receiver, provider
    exported: bool = False
    permission: Optional[str] = None
    intent_filters: List[Dict] = field(default_factory=list)
    authorities: Optional[str] = None  # For providers
    meta_data: Dict[str, str] = field(default_factory=dict)


@dataclass
class IntentInfo:
    """Information about an Intent usage."""
    source_class: str
    source_method: str
    target: Optional[str] = None  # Explicit target class
    action: Optional[str] = None
    data_uri: Optional[str] = None
    extras: List[str] = field(default_factory=list)
    is_implicit: bool = False
    line_number: int = 0


@dataclass
class DataFlowInfo:
    """Information about data flow."""
    source: str  # Where data comes from
    sink: str    # Where data goes
    data_type: str  # Type of data (user_input, file, network, etc.)
    path: List[str] = field(default_factory=list)  # Methods in the flow


@dataclass
class AppStructure:
    """Complete application structure."""
    package_name: str
    classes: Dict[str, ClassInfo] = field(default_factory=dict)
    components: Dict[str, ComponentInfo] = field(default_factory=dict)
    intents: List[IntentInfo] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    data_flows: List[DataFlowInfo] = field(default_factory=list)
    entry_points: List[str] = field(default_factory=list)


class AppStructureAnalyzer:
    """Analyzes decompiled APK to build structural model."""

    # Android component base classes
    ACTIVITY_CLASSES = {
        'Activity', 'AppCompatActivity', 'FragmentActivity',
        'ListActivity', 'PreferenceActivity', 'ActionBarActivity',
        'ComponentActivity', 'BaseActivity'
    }
    SERVICE_CLASSES = {
        'Service', 'IntentService', 'JobService', 'JobIntentService',
        'LifecycleService', 'BaseService'
    }
    RECEIVER_CLASSES = {
        'BroadcastReceiver', 'WakefulBroadcastReceiver', 'BaseBroadcastReceiver'
    }
    PROVIDER_CLASSES = {
        'ContentProvider', 'FileProvider', 'DocumentsProvider',
        'SearchRecentSuggestionsProvider', 'BaseContentProvider'
    }
    FRAGMENT_CLASSES = {
        'Fragment', 'DialogFragment', 'ListFragment', 'PreferenceFragment',
        'PreferenceFragmentCompat', 'BottomSheetDialogFragment'
    }

    # Data source patterns (sensitive data entry points)
    DATA_SOURCES = {
        'user_input': [
            r'getText\(\)', r'getEditableText\(\)', r'EditText',
            r'getStringExtra', r'getIntent\(\)', r'onActivityResult',
        ],
        'file': [
            r'FileInputStream', r'FileReader', r'BufferedReader',
            r'openFileInput', r'getSharedPreferences',
        ],
        'network': [
            r'HttpURLConnection', r'OkHttpClient', r'Retrofit',
            r'getInputStream\(\)', r'URLConnection',
        ],
        'database': [
            r'rawQuery', r'query\(', r'Cursor', r'SQLiteDatabase',
        ],
    }

    # Data sink patterns (where sensitive data goes)
    DATA_SINKS = {
        'network': [
            r'OutputStream', r'HttpURLConnection', r'write\(',
            r'sendBroadcast', r'startActivity',
        ],
        'file': [
            r'FileOutputStream', r'FileWriter', r'openFileOutput',
        ],
        'log': [
            r'Log\.[diwev]', r'println', r'System\.out',
        ],
        'database': [
            r'insert\(', r'update\(', r'execSQL',
        ],
    }

    def __init__(self, decompiled_dir: str):
        self.decompiled_dir = Path(decompiled_dir)
        self.sources_dir = self.decompiled_dir / "sources"
        self.resources_dir = self.decompiled_dir / "resources"
        self.manifest_path = self.resources_dir / "AndroidManifest.xml"

    def analyze(self) -> AppStructure:
        """Perform complete analysis of the application."""
        structure = AppStructure(package_name="")

        # Parse manifest first
        if self.manifest_path.exists():
            self._parse_manifest(structure)

        # Analyze source code
        if self.sources_dir.exists():
            self._analyze_sources(structure)

        # Build relationships
        self._analyze_intents(structure)
        self._analyze_data_flows(structure)
        self._identify_entry_points(structure)

        return structure

    def _parse_manifest(self, structure: AppStructure) -> None:
        """Parse AndroidManifest.xml."""
        try:
            tree = ET.parse(self.manifest_path)
            root = tree.getroot()

            # Get namespace
            ns = {'android': 'http://schemas.android.com/apk/res/android'}

            # Package name
            structure.package_name = root.get('package', '')

            # Permissions
            for perm in root.findall('.//uses-permission'):
                perm_name = perm.get(f'{{{ns["android"]}}}name', '')
                if perm_name:
                    structure.permissions.append(perm_name)

            # Components
            for component_type in ['activity', 'service', 'receiver', 'provider']:
                for elem in root.findall(f'.//{component_type}'):
                    comp = self._parse_component(elem, component_type, ns)
                    if comp:
                        structure.components[comp.name] = comp

        except Exception as e:
            print(f"[!] Failed to parse manifest: {e}")

    def _parse_component(self, elem: ET.Element, comp_type: str, ns: Dict) -> Optional[ComponentInfo]:
        """Parse a component element from manifest."""
        android_ns = ns['android']
        name = elem.get(f'{{{android_ns}}}name', '')

        if not name:
            return None

        exported_attr = elem.get(f'{{{android_ns}}}exported')
        exported = exported_attr == 'true' if exported_attr else None

        # Check for intent-filters (implies exported=true by default)
        intent_filters = []
        for intent_filter in elem.findall('intent-filter'):
            filter_info = {'actions': [], 'categories': [], 'data': []}

            for action in intent_filter.findall('action'):
                action_name = action.get(f'{{{android_ns}}}name', '')
                if action_name:
                    filter_info['actions'].append(action_name)

            for category in intent_filter.findall('category'):
                cat_name = category.get(f'{{{android_ns}}}name', '')
                if cat_name:
                    filter_info['categories'].append(cat_name)

            for data in intent_filter.findall('data'):
                data_info = {}
                for attr in ['scheme', 'host', 'path', 'pathPrefix', 'pathPattern', 'mimeType']:
                    val = data.get(f'{{{android_ns}}}{attr}')
                    if val:
                        data_info[attr] = val
                if data_info:
                    filter_info['data'].append(data_info)

            intent_filters.append(filter_info)

        # If has intent-filter and exported not explicitly set, default to true
        if exported is None and intent_filters:
            exported = True
        elif exported is None:
            exported = False

        # Provider authorities
        authorities = elem.get(f'{{{android_ns}}}authorities')

        # Permission
        permission = elem.get(f'{{{android_ns}}}permission')

        # Meta-data
        meta_data = {}
        for meta in elem.findall('meta-data'):
            meta_name = meta.get(f'{{{android_ns}}}name', '')
            meta_value = meta.get(f'{{{android_ns}}}value', '')
            if meta_name:
                meta_data[meta_name] = meta_value

        return ComponentInfo(
            name=name,
            type=comp_type,
            exported=exported,
            permission=permission,
            intent_filters=intent_filters,
            authorities=authorities,
            meta_data=meta_data,
        )

    def _analyze_sources(self, structure: AppStructure) -> None:
        """Analyze source code files."""
        for root, dirs, files in os.walk(self.sources_dir):
            for file in files:
                if file.endswith(('.java', '.kt')):
                    file_path = Path(root) / file
                    self._analyze_source_file(file_path, structure)

    def _analyze_source_file(self, file_path: Path, structure: AppStructure) -> None:
        """Analyze a single source file."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Extract class info
            class_info = self._parse_class(content, str(file_path))
            if class_info:
                structure.classes[class_info.full_name] = class_info

        except Exception as e:
            pass  # Skip files that can't be parsed

    def _parse_class(self, content: str, file_path: str) -> Optional[ClassInfo]:
        """Parse class information from source code."""
        # Extract package
        package_match = re.search(r'package\s+([\w.]+)\s*;', content)
        package = package_match.group(1) if package_match else ""

        # Extract class declaration
        class_pattern = r'(?:public\s+)?(?:(abstract)\s+)?(?:(interface)\s+)?class\s+(\w+)(?:\s+extends\s+([\w.]+))?(?:\s+implements\s+([\w.,\s]+))?'
        class_match = re.search(class_pattern, content)

        if not class_match:
            # Try interface pattern
            interface_pattern = r'(?:public\s+)?interface\s+(\w+)(?:\s+extends\s+([\w.,\s]+))?'
            interface_match = re.search(interface_pattern, content)
            if interface_match:
                class_name = interface_match.group(1)
                extends_raw = interface_match.group(2)
                is_interface = True
                is_abstract = False
            else:
                return None
        else:
            is_abstract = class_match.group(1) is not None
            is_interface = class_match.group(2) is not None
            class_name = class_match.group(3)
            extends_raw = class_match.group(4)

        full_name = f"{package}.{class_name}" if package else class_name

        # Determine component type
        extends_class = extends_raw.split('.')[-1] if extends_raw else None
        is_activity = extends_class in self.ACTIVITY_CLASSES
        is_service = extends_class in self.SERVICE_CLASSES
        is_receiver = extends_class in self.RECEIVER_CLASSES
        is_provider = extends_class in self.PROVIDER_CLASSES
        is_fragment = extends_class in self.FRAGMENT_CLASSES

        # Extract implements
        implements = []
        if not is_interface:
            impl_match = re.search(r'implements\s+([\w.,\s]+)', content)
            if impl_match:
                implements = [i.strip() for i in impl_match.group(1).split(',')]

        # Extract methods
        methods = self._extract_methods(content, full_name)

        # Extract fields
        fields = self._extract_fields(content)

        # Extract annotations
        annotations = re.findall(r'@(\w+)', content[:500])  # Check class-level annotations

        # Extract inner classes
        inner_classes = re.findall(r'(?:public|private|protected)?\s*(?:static)?\s*class\s+(\w+)\s+', content)
        inner_classes = [ic for ic in inner_classes if ic != class_name]

        return ClassInfo(
            name=class_name,
            package=package,
            full_name=full_name,
            file_path=file_path,
            extends=extends_raw,
            implements=implements,
            methods=methods,
            fields=fields,
            is_activity=is_activity,
            is_service=is_service,
            is_receiver=is_receiver,
            is_provider=is_provider,
            is_fragment=is_fragment,
            is_abstract=is_abstract,
            is_interface=is_interface,
            inner_classes=inner_classes,
            annotations=annotations,
        )

    def _extract_methods(self, content: str, class_name: str) -> List[MethodInfo]:
        """Extract method information from source code."""
        methods = []

        # Method pattern (simplified)
        method_pattern = r'(?:(@\w+)\s+)?(?:(public|private|protected)\s+)?(?:(static)\s+)?(?:(synchronized)\s+)?(?:([\w<>\[\],\s]+)\s+)?(\w+)\s*\(([^)]*)\)\s*(?:throws\s+[\w,\s]+)?\s*\{'

        for match in re.finditer(method_pattern, content):
            annotation = match.group(1)
            modifier = match.group(2) or 'package'
            is_static = match.group(3) is not None
            return_type = match.group(5) or 'void'
            method_name = match.group(6)
            params_str = match.group(7)

            # Skip constructors shown as methods
            if method_name in ['if', 'while', 'for', 'switch', 'try', 'catch']:
                continue

            # Parse parameters
            parameters = []
            if params_str.strip():
                for param in params_str.split(','):
                    param = param.strip()
                    if param:
                        parts = param.split()
                        if len(parts) >= 2:
                            parameters.append((parts[-2], parts[-1]))

            modifiers = [modifier]
            if is_static:
                modifiers.append('static')

            annotations = [annotation] if annotation else []

            methods.append(MethodInfo(
                name=method_name,
                class_name=class_name,
                return_type=return_type.strip(),
                parameters=parameters,
                modifiers=modifiers,
                annotations=annotations,
            ))

        return methods

    def _extract_fields(self, content: str) -> List[FieldInfo]:
        """Extract field information from source code."""
        fields = []

        # Field pattern
        field_pattern = r'(?:(private|public|protected)\s+)?(?:(static)\s+)?(?:(final)\s+)?([\w<>\[\],]+)\s+(\w+)\s*(?:=\s*([^;]+))?\s*;'

        for match in re.finditer(field_pattern, content):
            modifier = match.group(1) or 'package'
            is_static = match.group(2) is not None
            is_final = match.group(3) is not None
            field_type = match.group(4)
            field_name = match.group(5)
            initial_value = match.group(6)

            # Skip common false positives
            if field_name in ['class', 'this', 'super', 'new', 'return']:
                continue

            modifiers = [modifier]
            if is_static:
                modifiers.append('static')
            if is_final:
                modifiers.append('final')

            fields.append(FieldInfo(
                name=field_name,
                type=field_type,
                modifiers=modifiers,
                initial_value=initial_value.strip() if initial_value else None,
            ))

        return fields

    def _analyze_intents(self, structure: AppStructure) -> None:
        """Analyze Intent usage throughout the app."""
        for class_info in structure.classes.values():
            try:
                with open(class_info.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                # Find Intent creations
                intent_patterns = [
                    # Explicit intent: new Intent(context, Target.class)
                    r'new\s+Intent\s*\([^,)]+,\s*([\w.]+)\.class\)',
                    # Implicit intent: new Intent("action")
                    r'new\s+Intent\s*\(\s*["\']([^"\']+)["\']\s*\)',
                    # setClass/setComponent
                    r'\.setClass\s*\([^,]+,\s*([\w.]+)\.class\)',
                    r'\.setComponent\s*\([^)]+\)',
                ]

                for pattern in intent_patterns:
                    for match in re.finditer(pattern, content):
                        target = match.group(1) if match.lastindex >= 1 else None

                        intent_info = IntentInfo(
                            source_class=class_info.full_name,
                            source_method="",  # Would need more parsing
                            target=target,
                            is_implicit=target is None or not target.endswith('.class'),
                        )
                        structure.intents.append(intent_info)

                # Find startActivity/startService calls
                start_patterns = [
                    r'startActivity\s*\(',
                    r'startActivityForResult\s*\(',
                    r'startService\s*\(',
                    r'bindService\s*\(',
                    r'sendBroadcast\s*\(',
                    r'sendOrderedBroadcast\s*\(',
                ]

            except Exception:
                pass

    def _analyze_data_flows(self, structure: AppStructure) -> None:
        """Analyze data flow through the application."""
        for class_info in structure.classes.values():
            try:
                with open(class_info.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                # Check for data sources and sinks
                for source_type, patterns in self.DATA_SOURCES.items():
                    for pattern in patterns:
                        if re.search(pattern, content):
                            # Found a data source, look for corresponding sinks
                            for sink_type, sink_patterns in self.DATA_SINKS.items():
                                for sink_pattern in sink_patterns:
                                    if re.search(sink_pattern, content):
                                        structure.data_flows.append(DataFlowInfo(
                                            source=source_type,
                                            sink=sink_type,
                                            data_type=source_type,
                                            path=[class_info.full_name],
                                        ))
                                        break

            except Exception:
                pass

    def _identify_entry_points(self, structure: AppStructure) -> None:
        """Identify application entry points."""
        # Exported components are entry points
        for name, comp in structure.components.items():
            if comp.exported:
                structure.entry_points.append(f"{comp.type}:{name}")

        # Main activity (with MAIN action and LAUNCHER category)
        for name, comp in structure.components.items():
            for intent_filter in comp.intent_filters:
                if ('android.intent.action.MAIN' in intent_filter.get('actions', []) and
                    'android.intent.category.LAUNCHER' in intent_filter.get('categories', [])):
                    if f"launcher:{name}" not in structure.entry_points:
                        structure.entry_points.insert(0, f"launcher:{name}")

        # DeepLinks
        for name, comp in structure.components.items():
            for intent_filter in comp.intent_filters:
                for data in intent_filter.get('data', []):
                    if 'scheme' in data:
                        scheme = data.get('scheme', '')
                        host = data.get('host', '*')
                        path = data.get('path', data.get('pathPrefix', '/*'))
                        structure.entry_points.append(f"deeplink:{scheme}://{host}{path} -> {name}")
