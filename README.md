# CBOM Visualizer

A zero-dependency, browser-only tool for visualising **Cryptography Bill of Materials (CBOM)** files. Drop any CycloneDX 1.4–1.6 CBOM JSON file onto the page and instantly explore its cryptographic assets, library dependencies, and vulnerabilities through a set of interactive tabs and charts.

---

## Features

| Tab | What it shows |
|---|---|
| **Overview** | KPI summary cards, asset-type / crypto-function donut charts, top-libraries bar chart, interactive dependency tree, metadata table |
| **Crypto Assets** | Full table of every cryptographic-asset component — name, asset type, primitive, crypto functions, parent library, source location & line |
| **Libraries** | Depth distribution grid + sortable/searchable table of all library components with finding counts and reachability status |
| **Dependencies** | Adjacency-list view of the full dependency graph with ref preview tags |
| **Vulnerabilities** | Severity-tagged vulnerability table (CVE/CWE IDs, affected components, source links) |

Additional capabilities:

- **Expandable dependency tree** — lazy-rendered, supports expand-all / collapse-all, and in-tree search with parent-path highlighting. Repeated subtrees are shown with a `(*)` marker (Gradle-style) to avoid infinite expansion.
- **Sortable & filterable tables** — click any column header to sort; use the search box above each table for instant text filtering.
- **Pagination** — all large tables are paginated (15 or 20 rows per page).
- **Jump-to-tree** — click a parent-library tag in the Crypto Assets table to jump straight to that node in the dependency tree.
- **Vulnerability banner** — a warning notification is shown at the top of the dashboard whenever the CBOM contains vulnerability data.

---

## Getting Started

No build step, no package manager, no server required.

1. Clone or download the repository.
2. Open `cbom-visualizer.html` directly in any modern browser (Chrome, Firefox, Edge, Safari).
3. Drag and drop a CBOM JSON file onto the upload zone, or click **Select file** to browse.

```
CbomVisualizer/
├── cbom-visualizer.html   # Application shell (structure only)
├── cbom-visualizer.css    # IBM Carbon Design System tokens + all component styles
├── cbom-visualizer.js     # All application logic (upload, render, charts, tree, tables)
└── LICENSE                # Apache 2.0
```

> **Tip:** Because the tool runs entirely in the browser, your CBOM data never leaves your machine.

---

## CBOM Format Support

The visualiser understands **CycloneDX 1.4, 1.5, and 1.6** CBOM JSON files. All core CycloneDX fields are supported out of the box:

| Field | Used for |
|---|---|
| `components` | Cryptographic assets and library components |
| `dependencies` | Dependency graph and expandable tree |
| `vulnerabilities` | Vulnerability table and banner |
| `metadata` | File info bar and metadata panel |
| `cryptoProperties` | Asset type, primitive, and crypto functions |
| `evidence.occurrences` | Source file location and line number |


## Browser Compatibility

Any evergreen browser (Chrome 90+, Firefox 88+, Edge 90+, Safari 14+). No polyfills required. The tool uses only standard DOM APIs, `FileReader`, and ES2020 optional chaining (`?.`).

---

## License

[Apache 2.0](LICENSE)
