"""Visualization renderer - generates HTML reports with interactive diagrams."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from .analyzer import AppStructure
from .graphs import (
    Graph,
    ComponentGraph,
    CallGraph,
    DataFlowGraph,
    ClassHierarchyGraph,
    EntryPointGraph,
)


@dataclass
class VisualizationConfig:
    """Configuration for visualization rendering."""
    include_component_graph: bool = True
    include_call_graph: bool = True
    include_data_flow: bool = True
    include_class_hierarchy: bool = True
    include_entry_points: bool = True
    include_statistics: bool = True
    dark_mode: bool = False
    max_classes_in_hierarchy: int = 50


class VisualizationRenderer:
    """Renders application visualizations as HTML."""

    def __init__(self, structure: AppStructure, config: Optional[VisualizationConfig] = None):
        self.structure = structure
        self.config = config or VisualizationConfig()
        self.graphs: Dict[str, Graph] = {}

    def build_graphs(self) -> None:
        """Build all configured graphs."""
        if self.config.include_component_graph:
            self.graphs['components'] = ComponentGraph(self.structure)

        if self.config.include_call_graph:
            self.graphs['calls'] = CallGraph(self.structure)

        if self.config.include_data_flow:
            self.graphs['data_flow'] = DataFlowGraph(self.structure)

        if self.config.include_class_hierarchy:
            self.graphs['hierarchy'] = ClassHierarchyGraph(self.structure)

        if self.config.include_entry_points:
            self.graphs['entry_points'] = EntryPointGraph(self.structure)

    def render_html(self, output_path: str) -> str:
        """Render complete HTML visualization."""
        self.build_graphs()

        html = self._generate_html()

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)

        return output_path

    def _generate_html(self) -> str:
        """Generate HTML content."""
        stats = self._calculate_statistics()

        # Build sections
        sections = []

        # Statistics section
        if self.config.include_statistics:
            sections.append(self._render_statistics_section(stats))

        # Entry Points section
        if 'entry_points' in self.graphs:
            sections.append(self._render_graph_section(
                'entry_points',
                'Attack Surface & Entry Points',
                'Shows all external entry points an attacker could use to interact with the application.',
                self.graphs['entry_points'],
            ))

        # Component Graph section
        if 'components' in self.graphs:
            sections.append(self._render_graph_section(
                'components',
                'Component Interactions',
                'Shows Android components (Activities, Services, Receivers, Providers) and their interactions.',
                self.graphs['components'],
            ))

        # Data Flow section
        if 'data_flow' in self.graphs:
            sections.append(self._render_graph_section(
                'data_flow',
                'Data Flow Analysis',
                'Shows how data flows through the application from sources to sinks.',
                self.graphs['data_flow'],
            ))

        # Call Graph section
        if 'calls' in self.graphs:
            sections.append(self._render_graph_section(
                'calls',
                'Call Graph',
                'Shows method call relationships between classes.',
                self.graphs['calls'],
            ))

        # Class Hierarchy section
        if 'hierarchy' in self.graphs:
            sections.append(self._render_graph_section(
                'hierarchy',
                'Class Hierarchy',
                'Shows class inheritance and interface implementations.',
                self.graphs['hierarchy'],
            ))

        # Component details section
        sections.append(self._render_component_details())

        # Entry points details section
        sections.append(self._render_entry_points_details())

        return self._html_template(
            title=f"Application Visualization - {self.structure.package_name}",
            sections='\n'.join(sections),
            stats=stats,
        )

    def _calculate_statistics(self) -> Dict:
        """Calculate application statistics."""
        stats = {
            'package_name': self.structure.package_name,
            'total_classes': len(self.structure.classes),
            'activities': sum(1 for c in self.structure.classes.values() if c.is_activity),
            'services': sum(1 for c in self.structure.classes.values() if c.is_service),
            'receivers': sum(1 for c in self.structure.classes.values() if c.is_receiver),
            'providers': sum(1 for c in self.structure.classes.values() if c.is_provider),
            'fragments': sum(1 for c in self.structure.classes.values() if c.is_fragment),
            'total_methods': sum(len(c.methods) for c in self.structure.classes.values()),
            'exported_components': sum(1 for c in self.structure.components.values() if c.exported),
            'total_components': len(self.structure.components),
            'permissions': len(self.structure.permissions),
            'entry_points': len(self.structure.entry_points),
            'data_flows': len(self.structure.data_flows),
            'intents': len(self.structure.intents),
        }
        return stats

    def _render_statistics_section(self, stats: Dict) -> str:
        """Render statistics section."""
        return f'''
        <section id="statistics" class="section">
            <h2>Application Overview</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">{stats['total_classes']}</div>
                    <div class="stat-label">Classes</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['activities']}</div>
                    <div class="stat-label">Activities</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['services']}</div>
                    <div class="stat-label">Services</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['receivers']}</div>
                    <div class="stat-label">Receivers</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['providers']}</div>
                    <div class="stat-label">Providers</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['fragments']}</div>
                    <div class="stat-label">Fragments</div>
                </div>
                <div class="stat-card warning">
                    <div class="stat-value">{stats['exported_components']}</div>
                    <div class="stat-label">Exported Components</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['entry_points']}</div>
                    <div class="stat-label">Entry Points</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['permissions']}</div>
                    <div class="stat-label">Permissions</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['total_methods']}</div>
                    <div class="stat-label">Methods</div>
                </div>
            </div>
        </section>
        '''

    def _render_graph_section(self, graph_id: str, title: str, description: str, graph: Graph) -> str:
        """Render a graph section."""
        mermaid_code = graph.to_mermaid()

        return f'''
        <section id="{graph_id}" class="section">
            <h2>{title}</h2>
            <p class="description">{description}</p>
            <div class="diagram-container">
                <pre class="mermaid">
{mermaid_code}
                </pre>
            </div>
        </section>
        '''

    def _render_component_details(self) -> str:
        """Render detailed component information."""
        rows = []

        for name, comp in sorted(self.structure.components.items()):
            short_name = name.split('.')[-1]
            exported_badge = '<span class="badge danger">EXPORTED</span>' if comp.exported else '<span class="badge">internal</span>'
            permission_badge = f'<span class="badge info">{comp.permission}</span>' if comp.permission else ''

            # Intent filters
            filters = []
            for f in comp.intent_filters:
                actions = ', '.join(f.get('actions', []))
                if actions:
                    filters.append(f"Actions: {actions}")
                for data in f.get('data', []):
                    scheme = data.get('scheme', '')
                    host = data.get('host', '')
                    if scheme:
                        filters.append(f"URI: {scheme}://{host}")

            filter_html = '<br>'.join(filters) if filters else '-'

            rows.append(f'''
                <tr>
                    <td><code>{short_name}</code></td>
                    <td>{comp.type}</td>
                    <td>{exported_badge} {permission_badge}</td>
                    <td class="small">{filter_html}</td>
                </tr>
            ''')

        return f'''
        <section id="component-details" class="section">
            <h2>Component Details</h2>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Component</th>
                            <th>Type</th>
                            <th>Status</th>
                            <th>Intent Filters</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows)}
                    </tbody>
                </table>
            </div>
        </section>
        '''

    def _render_entry_points_details(self) -> str:
        """Render entry points details."""
        rows = []

        for entry in self.structure.entry_points:
            parts = entry.split(':', 1)
            entry_type = parts[0]
            entry_name = parts[1] if len(parts) > 1 else entry

            type_badges = {
                'launcher': '<span class="badge success">LAUNCHER</span>',
                'activity': '<span class="badge warning">ACTIVITY</span>',
                'service': '<span class="badge info">SERVICE</span>',
                'receiver': '<span class="badge">RECEIVER</span>',
                'provider': '<span class="badge danger">PROVIDER</span>',
                'deeplink': '<span class="badge warning">DEEPLINK</span>',
            }

            badge = type_badges.get(entry_type, f'<span class="badge">{entry_type}</span>')

            rows.append(f'''
                <tr>
                    <td>{badge}</td>
                    <td><code>{entry_name}</code></td>
                </tr>
            ''')

        return f'''
        <section id="entry-points-details" class="section">
            <h2>Entry Points</h2>
            <p class="description">These are the external entry points where attackers can interact with the application.</p>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>Entry Point</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows)}
                    </tbody>
                </table>
            </div>
        </section>
        '''

    def _html_template(self, title: str, sections: str, stats: Dict) -> str:
        """Generate complete HTML template."""
        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
    <style>
        :root {{
            --bg-primary: #ffffff;
            --bg-secondary: #f8f9fa;
            --text-primary: #212529;
            --text-secondary: #6c757d;
            --border-color: #dee2e6;
            --accent-color: #0d6efd;
            --danger-color: #dc3545;
            --warning-color: #ffc107;
            --success-color: #198754;
            --info-color: #0dcaf0;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background-color: var(--bg-secondary);
            color: var(--text-primary);
            line-height: 1.6;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }}

        header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 20px;
            margin-bottom: 30px;
        }}

        header h1 {{
            font-size: 2rem;
            margin-bottom: 10px;
        }}

        header .package {{
            opacity: 0.9;
            font-family: monospace;
            font-size: 1.1rem;
        }}

        .nav {{
            background: var(--bg-primary);
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }}

        .nav a {{
            color: var(--accent-color);
            text-decoration: none;
            padding: 8px 16px;
            border-radius: 4px;
            transition: background 0.2s;
        }}

        .nav a:hover {{
            background: var(--bg-secondary);
        }}

        .section {{
            background: var(--bg-primary);
            border-radius: 8px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}

        .section h2 {{
            color: var(--text-primary);
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--border-color);
        }}

        .description {{
            color: var(--text-secondary);
            margin-bottom: 20px;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
            gap: 15px;
        }}

        .stat-card {{
            background: var(--bg-secondary);
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}

        .stat-card.warning {{
            background: #fff3cd;
            border: 1px solid var(--warning-color);
        }}

        .stat-value {{
            font-size: 2rem;
            font-weight: bold;
            color: var(--accent-color);
        }}

        .stat-card.warning .stat-value {{
            color: #856404;
        }}

        .stat-label {{
            color: var(--text-secondary);
            font-size: 0.9rem;
            margin-top: 5px;
        }}

        .diagram-container {{
            overflow-x: auto;
            background: var(--bg-secondary);
            border-radius: 8px;
            padding: 20px;
        }}

        .mermaid {{
            display: flex;
            justify-content: center;
        }}

        .table-container {{
            overflow-x: auto;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
        }}

        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}

        th {{
            background: var(--bg-secondary);
            font-weight: 600;
        }}

        tr:hover {{
            background: var(--bg-secondary);
        }}

        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            background: var(--bg-secondary);
            color: var(--text-secondary);
        }}

        .badge.danger {{
            background: #f8d7da;
            color: #842029;
        }}

        .badge.warning {{
            background: #fff3cd;
            color: #856404;
        }}

        .badge.success {{
            background: #d1e7dd;
            color: #0f5132;
        }}

        .badge.info {{
            background: #cff4fc;
            color: #055160;
        }}

        code {{
            background: var(--bg-secondary);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 0.9em;
        }}

        .small {{
            font-size: 0.85rem;
        }}

        footer {{
            text-align: center;
            padding: 20px;
            color: var(--text-secondary);
            font-size: 0.9rem;
        }}

        @media (max-width: 768px) {{
            .stats-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}
        }}
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>Application Visualization</h1>
            <div class="package">{stats['package_name']}</div>
        </div>
    </header>

    <div class="container">
        <nav class="nav">
            <a href="#statistics">Overview</a>
            <a href="#entry_points">Entry Points</a>
            <a href="#components">Components</a>
            <a href="#data_flow">Data Flow</a>
            <a href="#calls">Call Graph</a>
            <a href="#hierarchy">Hierarchy</a>
            <a href="#component-details">Details</a>
        </nav>

        {sections}

        <footer>
            Generated by APK Analyzer on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </footer>
    </div>

    <script>
        mermaid.initialize({{
            startOnLoad: true,
            theme: 'default',
            securityLevel: 'loose',
            flowchart: {{
                useMaxWidth: true,
                htmlLabels: true,
                curve: 'basis'
            }}
        }});
    </script>
</body>
</html>'''
