/* ═══════════════════════════════════════════════════════════════════════
   CBOM Visualizer — pure vanilla JS, no external libraries
   Supports CycloneDX 1.4–1.6 CBOM with QSE extensions
   ═══════════════════════════════════════════════════════════════════════ */

let cbom = null;
let fileName = '';

// ── Upload wiring ──────────────────────────────────────────────────────
const uploadZone = document.getElementById('upload-zone');
const fileInput  = document.getElementById('file-input');

uploadZone.addEventListener('dragover', e => { e.preventDefault(); uploadZone.classList.add('drag-over'); });
uploadZone.addEventListener('dragleave', () => uploadZone.classList.remove('drag-over'));
uploadZone.addEventListener('drop', e => {
  e.preventDefault(); uploadZone.classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file) readFile(file);
});
uploadZone.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') fileInput.click(); });
fileInput.addEventListener('change', e => { if (e.target.files[0]) readFile(e.target.files[0]); });

function readFile(file) {
  fileName = file.name;
  const reader = new FileReader();
  reader.onload = ev => {
    try {
      cbom = JSON.parse(ev.target.result);
      if (!cbom.components)     cbom.components     = [];
      if (!cbom.dependencies)   cbom.dependencies   = [];
      if (!cbom.vulnerabilities) cbom.vulnerabilities = [];
      showError(false);
      renderDashboard();
    } catch (err) {
      showError('Invalid JSON: ' + err.message);
    }
  };
  reader.readAsText(file);
}

function showError(msg) {
  const n = document.getElementById('error-notif');
  if (msg) { n.classList.remove('hidden'); document.getElementById('error-msg').textContent = msg; }
  else      { n.classList.add('hidden'); }
}

function resetTool() {
  cbom = null; fileName = '';
  document.getElementById('dashboard').style.display = 'none';
  document.getElementById('upload-zone').style.display = '';
  showError(false);
  fileInput.value = '';
}

// ── Tab switching ──────────────────────────────────────────────────────
function switchTab(name, btn) {
  document.querySelectorAll('.cds-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('panel-' + name).classList.add('active');
}

// ── Main render ────────────────────────────────────────────────────────
function renderDashboard() {
  document.getElementById('upload-zone').style.display = 'none';
  document.getElementById('dashboard').style.display  = 'block';

  const components = cbom.components     || [];
  const deps       = cbom.dependencies   || [];
  const vulns      = cbom.vulnerabilities || [];
  const meta       = cbom.metadata       || {};

  const cryptoAssets = components.filter(c => c.type === 'cryptographic-asset');
  const libraries    = components.filter(c => c.type === 'library');

  // Helper to extract QSE properties
  const qseProp = (comp, key) => {
    const p = (comp.properties || []).find(x => x.name === 'qse:dep.' + key);
    return p ? p.value : null;
  };

  // ── File info bar ──────────────────────────────────────────────────
  document.getElementById('file-name-display').textContent = fileName;
  const ts      = meta.timestamp ? new Date(meta.timestamp).toLocaleString() : '—';
  const tool    = (((meta.tools || {}).services || [])[0] || {});
  const appName = (meta.component || {}).name || '—';
  const specV   = cbom.specVersion || '—';
  document.getElementById('file-meta-display').textContent =
    `CycloneDX ${specV} · App: ${appName} · Scanned: ${ts}` +
    (tool.name ? ` · Tool: ${tool.name} ${tool.version || ''}` : '');

  // ── Vulnerability banner ───────────────────────────────────────────
  if (vulns.length > 0) {
    const banner = document.getElementById('vuln-banner');
    banner.classList.remove('hidden');
    document.getElementById('vuln-banner-title').textContent =
      `${vulns.length} vulnerabilit${vulns.length === 1 ? 'y' : 'ies'} found`;
    const highSev = vulns.filter(v => (v.ratings || []).some(r => r.severity === 'high')).length;
    document.getElementById('vuln-banner-body').textContent =
      `${highSev} high severity · CWE IDs: ${vulns.map(v => v.id).join(', ')}`;
  }

  // ── KPI cards ──────────────────────────────────────────────────────
  const maxDepth     = Math.max(0, ...libraries.map(l => parseInt(qseProp(l, 'depth') || 0)));
  const directLibs   = libraries.filter(l => qseProp(l, 'transitive') === 'false').length;
  const graphEntries = deps.length;
  const totalFindings = libraries.reduce((s, l) => s + parseInt(qseProp(l, 'findingCount') || 0), 0);

  document.getElementById('kpi-grid').innerHTML = [
    { n: components.length,              l: 'Total CBOM Components',        cls: 'blue'   },
    { n: cryptoAssets.length,            l: 'Cryptographic Assets',         cls: 'purple' },
    { n: libraries.length,               l: 'Library Components',           cls: 'teal'   },
    { n: graphEntries,                   l: 'Dependency Graph Entries',      cls: ''       },
    { n: directLibs,                     l: 'Direct Deps with Findings',     cls: 'green'  },
    { n: libraries.length - directLibs,  l: 'Transitive Deps with Findings', cls: ''       },
    { n: maxDepth,                       l: 'Max Tree Depth',               cls: ''       },
    { n: totalFindings,                  l: 'Total Crypto Findings (apis)',  cls: 'red'    },
  ].map(k => `
    <div class="kpi-card ${k.cls}">
      <div class="kpi-num">${k.n}</div>
      <div class="kpi-lbl">${k.l}</div>
    </div>`).join('');

  // ── Charts ─────────────────────────────────────────────────────────
  renderCharts(cryptoAssets, libraries);

  // ── Dependency tree ─────────────────────────────────────────────────
  renderDepTree(deps, components);

  // ── Metadata panel ─────────────────────────────────────────────────
  renderMeta(meta, vulns);

  // ── Tables ─────────────────────────────────────────────────────────
  renderCryptoTable(cryptoAssets, deps, components);
  renderLibraryTable(libraries, qseProp);
  renderDepTable(deps, components);
  renderVulnTable(vulns, components);
}

// ── Dependency Tree ────────────────────────────────────────────────────
function renderDepTree(deps, components) {
  const container = document.getElementById('dep-tree-container');
  if (!deps || deps.length === 0) {
    container.innerHTML = `<div class="notification" style="background:var(--cds-layer-01);border:1px solid var(--cds-border-subtle-01);padding:16px 20px;font-size:13px;color:var(--cds-text-secondary)">No dependency graph data in this CBOM.</div>`;
    return;
  }

  // Build lookup maps
  const compByRef = {};
  components.forEach(c => { compByRef[c['bom-ref']] = c; });

  // Inject the metadata root application component if it is missing from components[]
  // (QSE CBOMs often omit it from components but reference it as a dep root)
  const metaComp = (cbom.metadata || {}).component;
  if (metaComp) {
    const metaRef = metaComp['bom-ref'] || metaComp.name;
    if (metaRef && !compByRef[metaRef]) {
      compByRef[metaRef] = { ...metaComp, 'bom-ref': metaRef, type: 'application' };
    }
  }

  // adjacency: ref -> dependsOn[]
  const adjMap = {};
  deps.forEach(d => { adjMap[d.ref] = d.dependsOn || []; });

  // reverse map: child -> parents (for root detection)
  const hasParent = new Set();
  deps.forEach(d => (d.dependsOn || []).forEach(c => hasParent.add(c)));

  // Find root(s): nodes not referenced as children by anyone
  let roots = deps.map(d => d.ref).filter(r => !hasParent.has(r));
  // Fallback: if everything has a parent (circular / no true root), pick first
  if (roots.length === 0 && deps.length > 0) roots = [deps[0].ref];

  const uniqueNodeCount = new Set(deps.map(d => d.ref)).size;
  const libRefs = new Set(components.filter(c => c.type === 'library').map(c => c['bom-ref']));

  // Global dedup set: once a node's subtree has been fully rendered, subsequent
  // occurrences show a collapsed (*) marker instead of re-expanding the full subtree.
  const globalRendered = new Set();

  // ── Build DOM ────────────────────────────────────────────────────────
  const wrap = document.createElement('div');
  wrap.className = 'tree-wrap';

  const toolbar = document.createElement('div');
  toolbar.className = 'tree-toolbar';
  toolbar.innerHTML = `
    <div>
      <h3>Dependency Graph</h3>
      <div class="tree-meta">${uniqueNodeCount} unique nodes · ${deps.length} graph entries · ${roots.length} root${roots.length > 1 ? 's' : ''} · (*) = repeated subtree · click ▶ to expand</div>
    </div>
    <div class="tree-actions">
      <div class="search-box" style="min-width:180px">
        <svg width="14" height="14" viewBox="0 0 32 32" fill="var(--cds-icon-secondary)"><path d="M30 28.6l-7.2-7.2A11.9 11.9 0 1020.6 23l7.2 7.2zM6 18a10 10 0 1110 10A10 10 0 016 18z"/></svg>
        <input id="tree-search-input" type="text" placeholder="Search nodes…" autocomplete="off" />
      </div>
      <button class="cds-btn cds-btn-secondary" style="height:32px;font-size:12px;padding:0 12px" onclick="treeExpandAll()">Expand all</button>
      <button class="cds-btn cds-btn-secondary" style="height:32px;font-size:12px;padding:0 12px" onclick="treeCollapseAll()">Collapse all</button>
    </div>`;
  wrap.appendChild(toolbar);

  const body = document.createElement('div');
  body.className = 'tree-body';
  body.id = 'tree-body';
  wrap.appendChild(body);

  roots.forEach(rootRef => {
    body.appendChild(buildTreeNode(rootRef, adjMap, compByRef, libRefs, 0, true, new Set(), globalRendered));
  });

  container.innerHTML = '';
  container.appendChild(wrap);

  document.getElementById('tree-search-input').addEventListener('input', function () {
    treeSearch(this.value.trim().toLowerCase());
  });
}

const ICONS = {
  root:    `<svg width="14" height="14" viewBox="0 0 32 32" fill="currentColor"><path d="M28 6H4a2 2 0 00-2 2v20a2 2 0 002 2h24a2 2 0 002-2V8a2 2 0 00-2-2zM4 28V8h24v20z"/><path d="M6 11h20v2H6zm0 4h20v2H6zm0 4h12v2H6z"/></svg>`,
  library: `<svg width="14" height="14" viewBox="0 0 32 32" fill="currentColor"><path d="M12 2L2 7v2h28V7L22 2h-10zm0 2h8l6 3H6l6-3zM2 11v2h28v-2H2zm0 4v14h28V15H2zm2 2h24v10H4V17z"/></svg>`,
  crypto:  `<svg width="14" height="14" viewBox="0 0 32 32" fill="currentColor"><path d="M25 12h-1V9a8 8 0 00-16 0v3H7a2 2 0 00-2 2v14a2 2 0 002 2h18a2 2 0 002-2V14a2 2 0 00-2-2zm-15-3a6 6 0 0112 0v3H10V9zm15 19H7V14h18v14z"/><circle cx="16" cy="20" r="2"/></svg>`,
  leaf:    `<svg width="14" height="14" viewBox="0 0 32 32" fill="currentColor"><circle cx="16" cy="16" r="5"/></svg>`,
};
const CHEVRON = `<svg width="12" height="12" viewBox="0 0 32 32" fill="currentColor"><path d="M10 6L24 16 10 26z"/></svg>`;

function buildTreeNode(ref, adjMap, compByRef, libRefs, depth, isLast, visited, globalRendered) {
  const children = adjMap[ref] || [];
  const hasKids  = children.length > 0;
  const comp     = compByRef[ref];
  const isCrypto = comp && comp.type === 'cryptographic-asset';
  const isLib    = !isCrypto && (libRefs.has(ref) || (comp && comp.type === 'library'));
  const isRoot   = depth === 0;

  // Extract display name/group from ref or component
  let displayName, displayGroup, version, findingCount, depthVal, isTransitive, cryptoAssetType, cryptoPrimitive;
  if (comp) {
    displayName   = comp.name;
    displayGroup  = comp.group || '';
    version       = comp.version || '';
    findingCount  = parseInt((comp.properties || []).find(p => p.name === 'qse:dep.findingCount')?.value || '0');
    depthVal      = (comp.properties || []).find(p => p.name === 'qse:dep.depth')?.value || '';
    isTransitive  = (comp.properties || []).find(p => p.name === 'qse:dep.transitive')?.value === 'true';
    if (isCrypto) {
      const cp       = comp.cryptoProperties || {};
      cryptoAssetType = cp.assetType || 'crypto-asset';
      cryptoPrimitive = (cp.algorithmProperties || {}).primitive || '';
    }
  } else {
    // Parse from purl-style ref: pkg:maven/group.subgroup/artifact@version
    const m = ref.match(/^pkg:[^/]+\/([^/]+)\/([^@\s]+?)(?:@([^\s]+))?$/);
    if (m) {
      displayGroup = m[1];
      displayName  = m[2];
      version      = m[3] || '';
    } else {
      displayName = ref; displayGroup = ''; version = '';
    }
    findingCount = 0;
  }

  // Cycle guard (per branch — prevents infinite recursion in cyclic graphs)
  const visitedCopy = new Set(visited);
  const isCyclic    = visited.has(ref);
  visitedCopy.add(ref);

  // Global dedup: mark repeat occurrences like Gradle's (*) notation
  const isRepeat = !isRoot && !isCyclic && globalRendered.has(ref);
  if (!isRepeat && !isCyclic) globalRendered.add(ref);

  // A repeat node shows as a leaf — its subtree is already visible elsewhere
  const effectiveHasKids = hasKids && !isCyclic && !isRepeat;

  // ── Node row ──────────────────────────────────────────────────────
  const nodeEl = document.createElement('div');
  nodeEl.className = 'tree-node';
  if (isRepeat) nodeEl.classList.add('tree-node-repeat');
  nodeEl.dataset.ref    = ref;
  nodeEl.dataset.search = [displayName, displayGroup, version, ref].join(' ').toLowerCase();

  // Indent rails
  let railHtml = '';
  for (let i = 0; i < depth; i++) railHtml += `<div class="tree-rail"></div>`;

  // Toggle chevron
  const toggleClass = effectiveHasKids ? '' : 'leaf';
  const toggleHtml  = `<button class="tree-toggle ${toggleClass}" onclick="treeToggle(this)" aria-label="toggle">
    ${effectiveHasKids ? CHEVRON : ICONS.leaf}
  </button>`;

  // Icon
  const iconHtml = isRoot
    ? `<span class="tree-node-icon root-icon">${ICONS.root}</span>`
    : isCrypto
    ? `<span class="tree-node-icon crypto-icon">${ICONS.crypto}</span>`
    : `<span class="tree-node-icon">${isLib ? ICONS.library : ICONS.leaf}</span>`;

  // Name
  const groupShort = displayGroup ? displayGroup + ':' : '';
  const nameHtml   = `<span class="t-name" title="${ref}">${groupShort}${displayName}</span>`;
  const verHtml    = version ? `<span class="t-group">@${version}</span>` : '';

  // Badges
  let badges = '';
  if (isRoot)  badges += `<span class="tree-badge tb-blue">root</span>`;
  if (isCrypto) {
    badges += `<span class="tree-badge tb-purple">${cryptoAssetType}</span>`;
    if (cryptoPrimitive) badges += `<span class="tree-badge tb-teal">${cryptoPrimitive}</span>`;
  }
  if (isLib && !isTransitive && !isRoot) badges += `<span class="tree-badge tb-blue">direct</span>`;
  if (isLib && isTransitive)             badges += `<span class="tree-badge tb-gray">transitive</span>`;
  if (findingCount > 0) {
    const cls = findingCount >= 50 ? 'tb-red' : findingCount >= 10 ? 'tb-purple' : 'tb-teal';
    badges += `<span class="tree-badge ${cls}">${findingCount} findings</span>`;
  }
  if (effectiveHasKids) badges += `<span class="tree-badge tb-gray">${children.length} deps</span>`;
  if (isCyclic)  badges += `<span class="tree-badge tb-red">⟳ cyclic</span>`;
  if (isRepeat)  badges += `<span class="tree-badge tb-gray">(*)</span>`;

  nodeEl.innerHTML = `
    <div class="tree-indent">${railHtml}</div>
    ${toggleHtml}
    <div class="tree-label">
      ${iconHtml}
      ${nameHtml}${verHtml}
    </div>
    <div class="tree-badges">${badges}</div>`;

  // ── Children container ─────────────────────────────────────────────
  const wrapper = document.createElement('div');
  wrapper.appendChild(nodeEl);

  if (effectiveHasKids) {
    const childrenEl = document.createElement('div');
    childrenEl.className      = 'tree-children collapsed';
    childrenEl.dataset.built  = 'false'; // lazy
    childrenEl.dataset.ref    = ref;
    childrenEl.dataset.kids   = JSON.stringify(children);
    childrenEl.dataset.depth  = String(depth + 1);
    wrapper.appendChild(childrenEl);

    const toggle = nodeEl.querySelector('.tree-toggle');
    toggle.dataset.childrenId = '';
    toggle._childrenEl = childrenEl;
    toggle._meta = { ref, children, adjMap, compByRef, libRefs, depth, visitedCopy, globalRendered };
  }

  return wrapper;
}

function treeToggle(btn) {
  if (btn.classList.contains('leaf')) return;
  const childrenEl = btn._childrenEl;
  if (!childrenEl) return;
  const isOpen = btn.classList.toggle('open');
  childrenEl.classList.toggle('collapsed', !isOpen);

  // Lazy build children on first expand
  if (isOpen && childrenEl.dataset.built === 'false') {
    childrenEl.dataset.built = 'true';
    const { children, adjMap, compByRef, libRefs, depth, visitedCopy, globalRendered } = btn._meta;
    children.forEach((childRef, i) => {
      const isLast = i === children.length - 1;
      childrenEl.appendChild(
        buildTreeNode(childRef, adjMap, compByRef, libRefs, depth + 1, isLast, visitedCopy, globalRendered)
      );
    });
  }
}

function treeExpandAll() {
  const doExpand = (root) => {
    root.querySelectorAll('.tree-toggle:not(.leaf):not(.open)').forEach(btn => treeToggle(btn));
    const remaining = root.querySelectorAll('.tree-toggle:not(.leaf):not(.open)').length;
    if (remaining > 0) doExpand(root);
  };
  doExpand(document.getElementById('tree-body'));
}

function treeCollapseAll() {
  document.getElementById('tree-body').querySelectorAll('.tree-toggle.open').forEach(btn => {
    btn.classList.remove('open');
    if (btn._childrenEl) btn._childrenEl.classList.add('collapsed');
  });
}

function treeSearch(q) {
  const body = document.getElementById('tree-body');
  if (!body) return;
  if (!q) {
    body.querySelectorAll('.tree-node').forEach(n => {
      n.classList.remove('tree-node--match', 'tree-node--hidden');
    });
    return;
  }
  // Force-expand everything so all nodes exist in DOM
  treeExpandAll();
  body.querySelectorAll('.tree-node').forEach(n => {
    const match = (n.dataset.search || '').includes(q);
    n.classList.toggle('tree-node--match', match);
    n.classList.toggle('tree-node--hidden', !match);
  });
  // Unhide parents of matching nodes so context is visible
  body.querySelectorAll('.tree-node--match').forEach(n => {
    let el = n.parentElement;
    while (el && el.id !== 'tree-body') {
      if (el.classList.contains('tree-children')) el.classList.remove('collapsed');
      if (el.classList.contains('tree-node'))     el.classList.remove('tree-node--hidden');
      el = el.parentElement;
    }
  });
}

// ── Charts ─────────────────────────────────────────────────────────────
function renderCharts(cryptoAssets, libraries) {
  const container = document.getElementById('charts-row');
  container.innerHTML = '';

  // 1. Asset type donut
  const assetTypes = {};
  cryptoAssets.forEach(c => {
    const t = (c.cryptoProperties || {}).assetType || 'unknown';
    assetTypes[t] = (assetTypes[t] || 0) + 1;
  });
  const assetColors = ['#0f62fe', '#8a3ffc', '#009d9a', '#198038', '#da1e28', '#f1c21b', '#fa4d56'];
  container.appendChild(buildDonutCard(
    'Asset Types', cryptoAssets.length, 'Crypto Assets',
    Object.entries(assetTypes), assetColors
  ));

  // 2. Crypto functions donut
  const fnCounts = {};
  cryptoAssets.forEach(c => {
    const fns = ((c.cryptoProperties || {}).algorithmProperties || {}).cryptoFunctions || [];
    fns.forEach(f => { fnCounts[f] = (fnCounts[f] || 0) + 1; });
  });
  const fnColors  = ['#8a3ffc', '#009d9a', '#0f62fe', '#198038', '#da1e28', '#f1c21b'];
  const fnEntries = Object.entries(fnCounts);
  container.appendChild(buildDonutCard(
    'Crypto Functions', fnEntries.reduce((s, [, v]) => s + v, 0), 'Occurrences',
    fnEntries, fnColors
  ));

  // 3. Top libs bar chart
  const topLibs = [...libraries]
    .map(l => ({
      name:  l.name,
      group: l.group || '',
      depth: l.properties?.find(p => p.name === 'qse:dep.depth')?.value || '?',
      trans: l.properties?.find(p => p.name === 'qse:dep.transitive')?.value,
      fc:    parseInt(l.properties?.find(p => p.name === 'qse:dep.findingCount')?.value || 0),
    }))
    .sort((a, b) => b.fc - a.fc)
    .slice(0, 12);
  const maxFc    = topLibs.length ? topLibs[0].fc : 1;
  const wideCard = document.createElement('div');
  wideCard.className = 'chart-card chart-card-wide';
  wideCard.innerHTML = `
    <h3>Top Libraries by Crypto Finding Count</h3>
    <div style="font-size:11px;color:var(--cds-text-secondary);margin-bottom:12px">
      Showing top ${topLibs.length} of ${libraries.length} library components · sorted by finding count descending
    </div>
    <div class="bar-chart">${topLibs.map(l => {
      const fcStyle   = l.fc >= 50 ? 'color:var(--ibm-red-60)' : l.fc >= 20 ? 'color:#8a4700' : 'color:var(--cds-text-primary)';
      const typeLabel = l.trans === 'false'
        ? `<span style="display:inline-block;padding:0 5px;background:var(--cds-tag-blue-bg);color:var(--cds-tag-blue-text);font-size:10px;margin-left:4px">direct</span>`
        : `<span style="display:inline-block;padding:0 5px;background:var(--cds-tag-gray-bg);color:var(--cds-tag-gray-text);font-size:10px;margin-left:4px">d${l.depth}</span>`;
      return `<div class="bc-row">
        <div class="bc-lbl" title="${l.group}:${l.name}">
          <span style="color:var(--cds-text-placeholder)">${l.group ? l.group.split('.').pop() + ':' : ''}</span>${l.name}${typeLabel}
        </div>
        <div class="bc-track">
          <div class="bc-fill" style="width:${Math.round(l.fc / maxFc * 100)}%"></div>
        </div>
        <div class="bc-val" style="${fcStyle}">${l.fc}</div>
      </div>`;
    }).join('')}
    </div>`;
  container.appendChild(wideCard);
}

function buildDonutCard(title, total, centerLabel, entries, colors) {
  const card        = document.createElement('div');
  card.className    = 'chart-card';
  const svgSize     = 120, r = 44, cx = 60, cy = 60;
  const circumference = 2 * Math.PI * r;
  const tot         = entries.reduce((s, [, v]) => s + v, 0) || 1;
  let offset        = 0;
  const segments    = entries.map(([, value], i) => {
    const pct  = value / tot;
    const dash = pct * circumference;
    const gap  = circumference - dash;
    const seg  = `<circle cx="${cx}" cy="${cy}" r="${r}"
      fill="none" stroke="${colors[i % colors.length]}" stroke-width="18"
      stroke-dasharray="${dash} ${gap}"
      stroke-dashoffset="${-offset}"
      transform="rotate(-90 ${cx} ${cy})" />`;
    offset += dash;
    return seg;
  });

  const legend = entries.map(([label, value], i) => `
    <div class="legend-item">
      <div class="legend-dot" style="background:${colors[i % colors.length]}"></div>
      <span>${label}</span>
      <span style="margin-left:auto;font-weight:600;color:var(--cds-text-primary)">${value}</span>
    </div>`).join('');

  card.innerHTML = `
    <h3>${title}</h3>
    <div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap">
      <div class="donut-wrap" style="width:${svgSize}px;height:${svgSize}px;flex-shrink:0">
        <svg width="${svgSize}" height="${svgSize}" viewBox="0 0 ${svgSize} ${svgSize}">
          <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="var(--cds-layer-01)" stroke-width="18"/>
          ${segments.join('')}
        </svg>
        <div class="donut-center">
          <div class="big">${total}</div>
          <div class="sml">${centerLabel}</div>
        </div>
      </div>
      <div class="donut-legend" style="flex:1;min-width:100px">${legend}</div>
    </div>`;
  return card;
}

// ── Metadata panel ─────────────────────────────────────────────────────
function renderMeta(meta, vulns) {
  const comp  = meta.component   || {};
  const props = meta.properties  || [];
  const tool  = (((meta.tools || {}).services || [])[0]) || {};
  const rows  = [
    ['Application',   comp.name    || '—'],
    ['Version',       comp.version || '—'],
    ['Language',      props.find(p => p.name === 'language')?.value || '—'],
    ['Git URL',       props.find(p => p.name === 'gitUrl')?.value   || '—'],
    ['Scan Timestamp', meta.timestamp || '—'],
    ['Tool',          tool.name ? `${tool.name} v${tool.version}` : '—'],
    ['Tool Provider', (tool.provider || {}).name || '—'],
    ['Serial Number', cbom.serialNumber || '—'],
    ['Spec Version',  cbom.specVersion  || '—'],
    ['BOM Version',   cbom.version      || '—'],
    ['Vulnerabilities', vulns.length > 0
      ? vulns.length + ' (CWE IDs: ' + vulns.map(v => v.id).join(', ') + ')'
      : 'None'],
  ];
  document.getElementById('meta-grid').innerHTML = `
    <div class="data-table-wrap" style="grid-column:1/-1">
      <table class="cds-table">
        <tbody>
          ${rows.map(([k, v]) => `<tr>
            <td style="font-weight:600;color:var(--cds-text-secondary);width:180px;font-size:12px;text-transform:uppercase;letter-spacing:.04em">${k}</td>
            <td class="mono">${v}</td>
          </tr>`).join('')}
        </tbody>
      </table>
    </div>`;
}

// ── Crypto table ───────────────────────────────────────────────────────
function renderCryptoTable(assets, deps, components) {
  document.getElementById('crypto-count').textContent = `(${assets.length})`;
  const compByRef = {};
  (components || []).forEach(c => { compByRef[c['bom-ref']] = c; });

  // Inverted lookup: crypto bom-ref -> list of parent library refs
  const parentsByRef = {};
  (deps || []).forEach(d => {
    (d.dependsOn || []).forEach(childRef => {
      if (!parentsByRef[childRef]) parentsByRef[childRef] = [];
      parentsByRef[childRef].push(d.ref);
    });
  });

  const rows = assets.map(c => {
    const cp      = c.cryptoProperties || {};
    const alg     = cp.algorithmProperties || {};
    const occ     = (c.evidence?.occurrences || [])[0] || {};
    const loc     = occ.location ? occ.location.split('/').pop() : '—';
    const fullLoc = occ.location || '—';
    const line    = occ.line || '—';
    const fns     = (alg.cryptoFunctions || []).map(f => `<span class="tag tag-blue">${f}</span>`).join(' ');
    const prim    = alg.primitive ? `<span class="tag tag-purple">${alg.primitive}</span>` : '<span class="tag tag-gray">—</span>';
    const typeTag = cp.assetType  ? `<span class="tag tag-teal">${cp.assetType}</span>`    : '—';

    const parents = parentsByRef[c['bom-ref']] || [];
    let linkedParentHtml = '<span class="tag tag-gray">—</span>';
    let parentSearchText = '';
    if (parents.length > 0) {
      linkedParentHtml = parents.map(pRef => {
        const pComp = compByRef[pRef];
        const pName = pComp ? pComp.name : (pRef.split('/').pop().split('@')[0] || pRef);
        parentSearchText += ' ' + pName + ' ' + pRef;
        return `<a href="javascript:void(0)" class="tag tag-blue" style="cursor:pointer;text-decoration:none" title="View in Dependency Graph: ${pRef}" onclick="jumpToDepNode('${c['bom-ref']}')">${pName} ↗</a>`;
      }).join(' ');
    }

    return `<tr data-search="${[c.name, c['bom-ref'], cp.assetType, alg.primitive, ...(alg.cryptoFunctions || []), fullLoc, parentSearchText].join(' ').toLowerCase()}">
      <td><strong>${c.name}</strong></td>
      <td>${typeTag}</td>
      <td>${prim}</td>
      <td>${fns || '<span class="tag tag-gray">—</span>'}</td>
      <td>${linkedParentHtml}</td>
      <td class="mono" title="${fullLoc}">${loc}</td>
      <td>${line}</td>
    </tr>`;
  });
  buildPaginatedTable('crypto-tbody', 'crypto-pag', rows, 15);
}

function jumpToDepNode(nodeRef) {
  const depTabBtn = Array.from(document.querySelectorAll('.cds-tab')).find(b => b.textContent.includes('Dependencies'));
  if (depTabBtn) switchTab('dependencies', depTabBtn);
  const searchInput = document.getElementById('tree-search-input');
  if (searchInput) {
    searchInput.value = nodeRef;
    treeSearch(nodeRef.toLowerCase());
  }
}

// ── Library table ──────────────────────────────────────────────────────
function renderLibraryTable(libs, qseProp) {
  document.getElementById('lib-count').textContent = `(${libs.length})`;

  // Depth distribution
  const depthMap = {};
  libs.forEach(l => {
    const d = parseInt(qseProp(l, 'depth') || 0);
    depthMap[d] = (depthMap[d] || 0) + 1;
  });
  const maxD = Math.max(0, ...Object.keys(depthMap).map(Number));
  let depthHtml = '';
  for (let d = 1; d <= maxD; d++) {
    depthHtml += `<div class="depth-cell">
      <div class="d-num">${depthMap[d] || 0}</div>
      <div class="d-lbl">Depth ${d}</div>
    </div>`;
  }
  document.getElementById('depth-grid').innerHTML =
    depthHtml || '<p style="color:var(--cds-text-secondary);font-size:13px">No library depth data.</p>';

  const rows = libs
    .sort((a, b) => parseInt(qseProp(b, 'findingCount') || 0) - parseInt(qseProp(a, 'findingCount') || 0))
    .map(l => {
      const fc    = parseInt(qseProp(l, 'findingCount') || 0);
      const depth = qseProp(l, 'depth') || '—';
      const trans = qseProp(l, 'transitive');
      const reach = qseProp(l, 'reachabilityStatus') || '—';
      const typeTag  = trans === 'false'
        ? `<span class="tag tag-blue">direct</span>`
        : `<span class="tag tag-gray">transitive</span>`;
      const fcClass  = fc >= 50 ? 'fc-hi' : fc >= 20 ? 'fc-mid' : 'fc-lo';
      const reachTag = reach === 'has_crypto_findings'
        ? `<span class="tag tag-red">findings</span>`
        : `<span class="tag tag-gray">${reach}</span>`;
      const scopeTag = l.scope === 'required'
        ? `<span class="tag tag-teal">required</span>`
        : `<span class="tag tag-gray">${l.scope || '—'}</span>`;
      return `<tr data-search="${[l.name, l.group, l.version, l.scope, depth, trans, reach].join(' ').toLowerCase()}">
        <td><strong class="mono">${l.name}</strong></td>
        <td class="mono" style="color:var(--cds-text-secondary)">${l.group || '—'}</td>
        <td class="mono">${l.version || '—'}</td>
        <td>${scopeTag}</td>
        <td style="text-align:center"><strong>${depth}</strong></td>
        <td>${typeTag}</td>
        <td style="text-align:right"><span class="${fcClass}">${fc}</span></td>
        <td>${reachTag}</td>
      </tr>`;
    });
  buildPaginatedTable('lib-tbody', 'lib-pag', rows, 15);
}

// ── Dependency table ───────────────────────────────────────────────────
function renderDepTable(deps, components) {
  document.getElementById('dep-count').textContent = `(${deps.length})`;
  const compByRef = {};
  (components || []).forEach(c => { compByRef[c['bom-ref']] = c; });

  const rows = deps.map(d => {
    const depsOn   = d.dependsOn || [];
    const previews = depsOn.slice(0, 4).map(r => {
      const comp = compByRef[r];
      if (comp && comp.type === 'cryptographic-asset') {
        const cp   = comp.cryptoProperties || {};
        const type = cp.assetType ? `[${cp.assetType}] ` : '';
        return `<span class="tag tag-purple" style="margin:1px" title="${r}">${type}${comp.name}</span>`;
      }
      const shortName = r.split('/').pop().split('@')[0];
      return `<span class="tag tag-gray" style="margin:1px" title="${r}">${shortName}</span>`;
    }).join('');
    const more = depsOn.length > 4 ? `<span class="tag tag-blue" style="margin:1px">+${depsOn.length - 4} more</span>` : '';
    return `<tr data-search="${d.ref.toLowerCase()}">
      <td class="mono">${d.ref}</td>
      <td style="text-align:center"><strong>${depsOn.length}</strong></td>
      <td style="max-width:380px">${previews}${more}</td>
    </tr>`;
  });
  buildPaginatedTable('dep-tbody', 'dep-pag', rows, 20);
}

// ── Vulnerability table ────────────────────────────────────────────────
function renderVulnTable(vulns, components) {
  if (vulns.length === 0) {
    document.getElementById('vuln-empty').classList.remove('hidden');
    return;
  }
  document.getElementById('vuln-table-wrap').classList.remove('hidden');
  document.getElementById('vuln-count').textContent = `(${vulns.length})`;
  const tbody = document.getElementById('vuln-tbody');
  tbody.innerHTML = vulns.map(v => {
    const sev    = ((v.ratings || [])[0] || {}).severity || '—';
    const sevTag = `<span class="tag ${sev === 'high' ? 'tag-red' : sev === 'medium' ? 'tag-gray' : 'tag-green'}">${sev}</span>`;
    const cwes   = (v.cwes || []).map(c => `<span class="tag tag-purple">CWE-${c}</span>`).join(' ');
    const affected = (v.affects || []).map(a => {
      const comp = components.find(c => c['bom-ref'] === a.ref);
      return comp
        ? `<span class="tag tag-blue">${comp.name}</span>`
        : `<span class="tag tag-gray">${a.ref.slice(0, 12)}…</span>`;
    }).join(' ');
    const srcLink = v.source?.url
      ? `<a href="${v.source.url}" style="color:var(--cds-link-primary)">${v.source.name || v.source.url}</a>`
      : (v.source?.name || '—');
    return `<tr>
      <td><strong>${v.id}</strong></td>
      <td>${sevTag}</td>
      <td>${srcLink}</td>
      <td>${cwes}</td>
      <td style="max-width:360px">${affected}</td>
    </tr>`;
  }).join('');
}

/* ─── Pagination helper ───────────────────────────────────────────────── */
const PAGE_DATA = {};

function buildPaginatedTable(tbodyId, pagId, allRows, pageSize) {
  PAGE_DATA[tbodyId] = { allRows, pageSize, page: 1, filtered: allRows };
  renderPage(tbodyId, pagId);
}

function renderPage(tbodyId, pagId) {
  const state = PAGE_DATA[tbodyId];
  if (!state) return;
  const { filtered, pageSize } = state;
  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  state.page = Math.min(state.page, totalPages);
  const start = (state.page - 1) * pageSize;
  const slice = filtered.slice(start, start + pageSize);
  document.getElementById(tbodyId).innerHTML = slice.join('') ||
    `<tr><td colspan="9" style="text-align:center;color:var(--cds-text-secondary);padding:24px">No results</td></tr>`;

  const pag = document.getElementById(pagId);
  pag.innerHTML = `
    <span>${filtered.length} items · page ${state.page} of ${totalPages}</span>
    <button onclick="goPage('${tbodyId}','${pagId}',-1)" ${state.page <= 1 ? 'disabled' : ''}>← Prev</button>
    <button onclick="goPage('${tbodyId}','${pagId}',1)"  ${state.page >= totalPages ? 'disabled' : ''}>Next →</button>`;
}

function goPage(tbodyId, pagId, delta) {
  const state      = PAGE_DATA[tbodyId];
  const totalPages = Math.ceil(state.filtered.length / state.pageSize);
  state.page = Math.max(1, Math.min(totalPages, state.page + delta));
  renderPage(tbodyId, pagId);
}

/* ─── Table filter ────────────────────────────────────────────────────── */
function filterTable(tbodyId, query) {
  const state = PAGE_DATA[tbodyId];
  if (!state) return;
  const q     = query.trim().toLowerCase();
  const pagId = tbodyId.replace('-tbody', '-pag');
  if (!q) {
    state.filtered = state.allRows;
  } else {
    state.filtered = state.allRows.filter(html => {
      const m = html.match(/data-search="([^"]*)"/);
      return m ? m[1].includes(q) : html.toLowerCase().includes(q);
    });
  }
  state.page = 1;
  renderPage(tbodyId, pagId);
}

/* ─── Table sort ──────────────────────────────────────────────────────── */
function sortTable(tbodyId, colIdx, th) {
  const state = PAGE_DATA[tbodyId];
  if (!state) return;
  const isAsc = th.dataset.sortDir !== 'asc';
  th.closest('thead').querySelectorAll('th').forEach(t => { t.classList.remove('sorted'); delete t.dataset.sortDir; });
  th.classList.add('sorted');
  th.dataset.sortDir = isAsc ? 'asc' : 'desc';

  const getCellText = html => {
    const tmp   = document.createElement('tbody');
    tmp.innerHTML = html;
    const cells = tmp.querySelectorAll('td');
    return cells[colIdx] ? cells[colIdx].textContent.trim() : '';
  };
  state.allRows.sort((a, b) => {
    const ta = getCellText(a), tb = getCellText(b);
    const na = parseFloat(ta),  nb = parseFloat(tb);
    if (!isNaN(na) && !isNaN(nb)) return isAsc ? na - nb : nb - na;
    return isAsc ? ta.localeCompare(tb) : tb.localeCompare(ta);
  });
  state.filtered = state.allRows;
  state.page     = 1;
  renderPage(tbodyId, tbodyId.replace('-tbody', '-pag'));
}
