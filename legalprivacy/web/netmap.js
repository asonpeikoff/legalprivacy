/*
 * netmap.js - EtherApe-style live network map for the legalPrivacy dashboard.
 *
 * Usage:
 *   const map = new NetMap(containerElement, {height: 420});
 *   map.update(nodes);   // full current list, call every ~2 s
 *   map.destroy();
 *
 * nodes = [{id, label, kind: 'you'|'noise'|'tor'|'dns'|'other', weight, active, detail}]
 *
 * Self-contained: no libraries, no network, no eval, no innerHTML.
 * All user-supplied text goes through textContent.
 */
(function () {
  'use strict';

  var SVGNS = 'http://www.w3.org/2000/svg';
  var MAX_NODES = 300;          // hard cap on rendered nodes (heaviest kept)
  var MAX_LABELS = 25;          // permanent labels for the heaviest nodes
  var LABEL_CHARS = 28;
  var R_MIN = 3, R_MAX = 16;    // node radius: 3 + 2.2*sqrt(weight), clamped
  var W_MIN = 0.6, W_MAX = 5;   // link width: 0.6 + 0.5*sqrt(weight), clamped
  var FADE_IN_MS = 400, FADE_OUT_MS = 600;
  var CENTER_R = 17;            // center node: always larger than any remote node (max 16)
  var CHAR_W = 6.2;             // estimated width of one 11px character
  var LEGEND = [
    ['you', 'Your apps'], ['noise', 'legalPrivacy'], ['tor', 'Tor'], ['dns', 'DNS']
  ];
  var KIND_NAMES = {you: 'your apps', noise: 'legalPrivacy', tor: 'Tor', dns: 'DNS', other: 'other'};
  var FALLBACK = {acc: '#2f7d4f', tor: '#7a3fb0', warn: '#b7791f', mute: '#6b7488', ink: '#1c2230', panel: '#ffffff', line: '#e2e5ec'};

  // One shared stylesheet for the pulse animation and tooltip.
  function ensureStyle() {
    if (document.getElementById('netmap-style')) return;
    var st = document.createElement('style');
    st.id = 'netmap-style';
    st.textContent =
      '.nm-wrap{position:relative;width:100%;overflow:hidden;-webkit-user-select:none;user-select:none}' +
      '.nm-wrap svg{display:block;width:100%;background:transparent;font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}' +
      '.nm-node{cursor:pointer}' +
      '.nm-pulse{animation:nm-pulse 1.6s ease-out infinite;pointer-events:none}' +
      '@keyframes nm-pulse{0%{transform:scale(1);opacity:.7}100%{transform:scale(1.9);opacity:0}}' +
      '@media (prefers-reduced-motion:reduce){.nm-pulse{animation:none;display:none}}' +
      '.nm-tip{position:absolute;z-index:3;max-width:260px;padding:6px 9px;border-radius:7px;font-size:12px;line-height:1.35;' +
      'pointer-events:none;box-shadow:0 2px 10px rgba(0,0,0,.18);border:1px solid;white-space:pre-wrap;word-break:break-word}' +
      '.nm-tip b{display:block;font-weight:600;margin-bottom:2px}';
    (document.head || document.documentElement).appendChild(st);
  }

  function el(name, attrs, parent) {
    var e = document.createElementNS(SVGNS, name);
    if (attrs) for (var k in attrs) if (Object.prototype.hasOwnProperty.call(attrs, k)) e.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(e);
    return e;
  }

  function clamp(v, a, b) { return v < a ? a : v > b ? b : v; }

  // Small stable string hash -> [0,1), used to spread nodes into a band.
  function hash01(s) {
    var h = 2166136261;
    for (var i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
    return ((h >>> 0) % 10007) / 10007;
  }

  function truncate(s, n) {
    s = String(s);
    return s.length > n ? s.slice(0, n - 1) + '…' : s;
  }

  function NetMap(container, opts) {
    if (!(this instanceof NetMap)) return new NetMap(container, opts);
    opts = opts || {};
    ensureStyle();
    this.container = container;
    this.height = Math.max(160, +opts.height || 420);
    this.width = Math.max(200, container.clientWidth || 600);
    this.nodes = new Map();       // id -> node state
    this.order = 0;               // insertion counter (golden-angle placement)
    this.heat = 0;                // simulation temperature
    this.raf = 0;
    this.lastT = 0;
    this.hoverId = null;
    this.pinnedId = null;
    this.onSelect = opts.onSelect || null;     // called with the clicked node (or null when the click was on empty map)
    this.colors = {};
    this.destroyed = false;

    this.reduced = !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);

    this._build();
    this._readColors();
    this._layoutStatic();
    this._bind();
    this.update([]);
  }

  NetMap.prototype._build = function () {
    var wrap = this.wrap = document.createElement('div');
    wrap.className = 'nm-wrap';
    var svg = this.svg = el('svg', {role: 'img', 'aria-label': 'Network map', focusable: 'false'});
    svg.style.height = this.height + 'px';
    wrap.appendChild(svg);
    this.gLinks = el('g', null, svg);
    this.gCenter = el('g', null, svg);
    this.gNodes = el('g', null, svg);
    this.gLabels = el('g', {'pointer-events': 'none'}, svg);
    this.gLegend = el('g', {'pointer-events': 'none'}, svg);

    // Center node: "This computer"
    this.centerCircle = el('circle', {r: CENTER_R, 'stroke-width': 3}, this.gCenter);
    this.centerLabel = el('text', {'text-anchor': 'middle', 'font-size': 12, 'font-weight': 600}, this.gCenter);
    this.centerLabel.textContent = 'This computer';

    // Legend (top-left)
    this.legendItems = [];
    for (var i = 0; i < LEGEND.length; i++) {
      var y = 14 + i * 16;
      var dot = el('circle', {cx: 14, cy: y, r: 4.5}, this.gLegend);
      var t = el('text', {x: 24, y: y + 4, 'font-size': 11}, this.gLegend);
      t.textContent = LEGEND[i][1];
      this.legendItems.push({kind: LEGEND[i][0], dot: dot, text: t});
    }

    this.emptyText = el('text', {'text-anchor': 'middle', 'font-size': 13}, svg);
    this.emptyText.textContent = 'No connections yet';

    var tip = this.tip = document.createElement('div');
    tip.className = 'nm-tip';
    tip.style.display = 'none';
    this.tipTitle = document.createElement('b');
    this.tipBody = document.createElement('span');
    tip.appendChild(this.tipTitle);
    tip.appendChild(this.tipBody);
    wrap.appendChild(tip);

    this.container.appendChild(wrap);
  };

  // Dark theme if <html data-theme=dark>, or the OS prefers dark and the page isn't forced light.
  NetMap.prototype._isDark = function () {
    var t = document.documentElement.getAttribute('data-theme');
    if (t === 'dark') return true;
    if (t === 'light') return false;
    return !!(window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
  };

  // Read theme colors from the document's CSS custom properties.
  NetMap.prototype._readColors = function () {
    var cs = getComputedStyle(document.documentElement);
    function v(name, fb) { var x = cs.getPropertyValue('--' + name).trim(); return x || fb; }
    var c = {
      noise: v('acc', FALLBACK.acc), tor: v('tor', FALLBACK.tor), dns: v('warn', FALLBACK.warn),
      other: v('mute', FALLBACK.mute), you: v('you-map', this._isDark() ? '#3fb8a9' : '#2a9d8f'),
      ink: v('ink', FALLBACK.ink), mute: v('mute', FALLBACK.mute),
      panel: v('panel', FALLBACK.panel), line: v('line', FALLBACK.line)
    };
    var changed = false;
    for (var k in c) if (c[k] !== this.colors[k]) { changed = true; break; }
    if (!changed) return;
    this.colors = c;
    // Static elements
    this.centerCircle.setAttribute('fill', c.ink);
    this.centerCircle.setAttribute('stroke', c.panel);
    this.centerLabel.setAttribute('fill', c.ink);
    this.emptyText.setAttribute('fill', c.mute);
    for (var i = 0; i < this.legendItems.length; i++) {
      this.legendItems[i].dot.setAttribute('fill', c[this.legendItems[i].kind]);
      this.legendItems[i].text.setAttribute('fill', c.mute);
    }
    this.tip.style.background = c.panel;
    this.tip.style.color = c.ink;
    this.tip.style.borderColor = c.line;
    var self = this;
    this.nodes.forEach(function (n) { self._paint(n); });
  };

  NetMap.prototype._paint = function (n) {
    var col = this.colors[n.kind] || this.colors.other;
    n.circle.setAttribute('fill', col);
    n.ring.setAttribute('stroke', col);
    n.line.setAttribute('stroke', col);
    if (n.label) n.label.setAttribute('fill', this.colors.ink);
  };

  // Size-dependent geometry: center, ring radius, aspect stretch.
  NetMap.prototype._layoutStatic = function () {
    var w = this.width, h = this.height;
    this.svg.setAttribute('viewBox', '0 0 ' + w + ' ' + h);
    this.cx = w / 2;
    this.cy = h / 2;
    // Stretch the ring into an ellipse on wide/tall containers so space is used.
    this.sx = w > h ? Math.min(w / h, 2.2) : 1;
    this.sy = h > w ? Math.min(h / w, 2.2) : 1;
    this._fitRing();
    this.centerCircle.setAttribute('cx', this.cx);
    this.centerCircle.setAttribute('cy', this.cy);
    this.centerLabel.setAttribute('x', this.cx);
    this.centerLabel.setAttribute('y', this.cy + CENTER_R + 15);
    this.emptyText.setAttribute('x', this.cx);
    this.emptyText.setAttribute('y', this.cy + CENTER_R + 40);
  };

  // Ring rest radius: ~38% of min(w,h), reduced so the outer edge of the
  // node band (plus the largest node) stays inside the canvas.
  NetMap.prototype._fitRing = function () {
    var w = this.width, h = this.height;
    var half = 0.5 * Math.min(this.spread || 0.1, 0.75) + 0.04;
    var pad = (this.rMax || R_MAX) + 8;
    this.R = Math.max(40, Math.min(0.38 * Math.min(w, h),
      (w / 2 - pad) / (this.sx * (1 + half)),
      (h / 2 - pad) / (this.sy * (1 + half))));
  };

  // Absolute sizing from traffic: radius and line width scale with sqrt(weight).
  NetMap.prototype._sizeNodes = function () {
    this.nodes.forEach(function (n) {
      var sw = n.sw || 0;
      n.rt = clamp(3 + 2.2 * sw, R_MIN, R_MAX);
      n.lwt = clamp(0.6 + 0.5 * sw, W_MIN, W_MAX);
    });
    this.rMax = R_MAX;
    this._fitRing();
  };

  NetMap.prototype._bind = function () {
    var self = this;
    if (window.ResizeObserver) {
      this.ro = new ResizeObserver(function () {
        var w = Math.max(200, self.container.clientWidth || self.width);
        if (Math.abs(w - self.width) < 1) return;
        var ox = self.cx, oy = self.cy;
        self.width = w;
        self._layoutStatic();
        self._sizeNodes();
        // Shift nodes with the center so the map doesn't jump.
        self.nodes.forEach(function (n) { n.x += self.cx - ox; n.y += self.cy - oy; });
        self._kick(0.3);
      });
      this.ro.observe(this.container);
    }
    // Theme changes: OS scheme or a data-theme attribute on <html>.
    if (window.matchMedia) {
      this.mqDark = window.matchMedia('(prefers-color-scheme: dark)');
      this.mqMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
      this._onScheme = function () { self._readColors(); };
      this._onMotion = function () { self.reduced = self.mqMotion.matches; self._kick(0.3); };
      listen(this.mqDark, this._onScheme);
      listen(this.mqMotion, this._onMotion);
    }
    if (window.MutationObserver) {
      this.mo = new MutationObserver(function () { self._readColors(); });
      this.mo.observe(document.documentElement, {attributes: true, attributeFilter: ['data-theme', 'class', 'style']});
    }

    // Hover / tap tooltip via event delegation on the nodes layer.
    function idOf(ev) {
      var t = ev.target && ev.target.closest ? ev.target.closest('[data-nmid]') : null;
      return t ? t.getAttribute('data-nmid') : null;
    }
    this._onOver = function (ev) {
      if (ev.pointerType && ev.pointerType !== 'mouse') return;
      var id = idOf(ev);
      if (id !== null) self._hover(id, ev);
    };
    this._onMove = function (ev) {
      if (self.hoverId !== null && (!ev.pointerType || ev.pointerType === 'mouse')) self._placeTip(ev);
    };
    this._onOut = function (ev) {
      if (ev.pointerType && ev.pointerType !== 'mouse') return;
      var id = idOf(ev);
      if (id !== null && id === self.hoverId && self.pinnedId !== id) self._hover(null);
    };
    this._onClick = function (ev) {
      var id = idOf(ev);
      if (id !== null) { self.pinnedId = id; self._hover(id, ev); }
      else { self.pinnedId = null; self._hover(null); }
      if (self.onSelect) { try { self.onSelect(id !== null ? self.nodes.get(id) || null : null); } catch (e) { /* the page's own handler */ } }
    };
    this.gNodes.addEventListener('pointerover', this._onOver);
    this.gNodes.addEventListener('pointerout', this._onOut);
    this.svg.addEventListener('pointermove', this._onMove);
    this.svg.addEventListener('click', this._onClick);
  };

  function listen(mq, fn) {
    if (mq.addEventListener) mq.addEventListener('change', fn); else if (mq.addListener) mq.addListener(fn);
  }
  function unlisten(mq, fn) {
    if (mq.removeEventListener) mq.removeEventListener('change', fn); else if (mq.removeListener) mq.removeListener(fn);
  }

  NetMap.prototype._hover = function (id, ev) {
    var n = id !== null ? this.nodes.get(id) : null;
    if (!n || n.removing) {
      this.hoverId = null;
      this.tip.style.display = 'none';
    } else {
      this.hoverId = id;
      this.tipTitle.textContent = n.text || 'Your app';
      this.tipBody.textContent = n.detail || '';
      this.tipBody.style.display = n.detail ? '' : 'none';
      this.tip.style.display = 'block';
      if (ev) this._placeTip(ev); else this._placeTipAtNode(n);
    }
    this._drawLabels();
  };

  NetMap.prototype._placeTip = function (ev) {
    var rect = this.wrap.getBoundingClientRect();
    this._setTipPos(ev.clientX - rect.left, ev.clientY - rect.top);
  };

  NetMap.prototype._placeTipAtNode = function (n) {
    var scale = this.wrap.clientWidth / this.width || 1;
    this._setTipPos(n.x * scale, n.y * scale);
  };

  NetMap.prototype._setTipPos = function (x, y) {
    var tw = this.tip.offsetWidth, th = this.tip.offsetHeight;
    var W = this.wrap.clientWidth, H = this.wrap.clientHeight;
    var left = x + 14, top = y + 14;
    if (left + tw > W - 4) left = x - tw - 14;
    if (top + th > H - 4) top = y - th - 14;
    this.tip.style.left = clamp(left, 4, Math.max(4, W - tw - 4)) + 'px';
    this.tip.style.top = clamp(top, 4, Math.max(4, H - th - 4)) + 'px';
  };

  // Create DOM for a new node.
  NetMap.prototype._create = function (d) {
    var n = {
      id: d.id, kind: d.kind, weight: 0, active: false, detail: '', text: '',
      x: 0, y: 0, vx: 0, vy: 0, r: R_MIN, rt: R_MIN, lw: W_MIN, lwt: W_MIN,
      alpha: 0, born: performance.now(), removing: false, removedAt: 0,
      band: hash01(d.id), label: null
    };
    // Place new nodes at a golden-angle position partway out; the spring pulls them out.
    var a = this.order++ * 2.399963 + hash01(d.id + '#') * 0.5;
    var rr = this.R * (this.reduced ? 1 : 0.55);
    n.x = this.cx + Math.cos(a) * rr * this.sx;
    n.y = this.cy + Math.sin(a) * rr * this.sy;

    n.line = el('line', {'stroke-opacity': 0.35, 'stroke-linecap': 'round'}, this.gLinks);
    n.g = el('g', {'class': 'nm-node', 'data-nmid': d.id}, this.gNodes);
    n.ring = el('circle', {'class': 'nm-pulse', fill: 'none', 'stroke-width': 1.5}, n.g);
    n.ring.style.display = 'none';
    n.hit = el('circle', {fill: 'transparent', 'pointer-events': 'all'}, n.g);
    n.circle = el('circle', {'fill-opacity': 0.9}, n.g);
    this.nodes.set(d.id, n);
    return n;
  };

  NetMap.prototype._drop = function (n) {
    n.line.remove();
    n.g.remove();
    if (n.label) n.label.remove();
    this.nodes.delete(n.id);
    if (this.hoverId === n.id) { this.hoverId = null; this.pinnedId = null; this.tip.style.display = 'none'; }
  };

  /** Replace the current node list. Safe to call often. */
  NetMap.prototype.update = function (list) {
    if (this.destroyed) return;
    this._readColors();
    list = Array.isArray(list) ? list : [];

    // Sanitize input, dedupe by id, cap to the heaviest MAX_NODES.
    var seen = Object.create(null), clean = [];
    for (var i = 0; i < list.length; i++) {
      var d = list[i];
      if (!d || d.id === undefined || d.id === null) continue;
      var id = String(d.id);
      if (seen[id]) continue;
      seen[id] = 1;
      var w = +d.weight;
      clean.push({
        id: id,
        label: d.label === undefined || d.label === null ? '' : String(d.label),
        kind: KIND_NAMES.hasOwnProperty(d.kind) ? d.kind : 'other',
        weight: isFinite(w) && w > 0 ? w : 0,
        active: !!d.active,
        detail: d.detail === undefined || d.detail === null ? '' : String(d.detail)
      });
    }
    if (clean.length > MAX_NODES) {
      clean.sort(function (a, b) { return b.weight - a.weight; });
      clean.length = MAX_NODES;
    }

    var keep = Object.create(null), added = 0, self = this;
    for (i = 0; i < clean.length; i++) {
      d = clean[i];
      keep[d.id] = 1;
      var n = this.nodes.get(d.id);
      if (!n) { n = this._create(d); added++; }
      else if (n.removing) { n.removing = false; n.born = performance.now() - FADE_IN_MS * n.alpha; }
      var kindChanged = n.kind !== d.kind;
      n.kind = d.kind;
      n.weight = d.weight;
      n.detail = d.detail;
      n.text = d.kind === 'you' ? '' : (d.label || d.id);
      n.sw = Math.sqrt(d.weight);
      if (n.active !== d.active) {
        n.active = d.active;
        n.ring.style.display = d.active && !this.reduced ? '' : 'none';
      }
      if (kindChanged || !n.circle.getAttribute('fill')) this._paint(n);
    }
    // Mark vanished nodes for fade-out.
    var now = performance.now();
    this.nodes.forEach(function (n) {
      if (!keep[n.id] && !n.removing) { n.removing = true; n.removedAt = now; n.ring.style.display = 'none'; }
    });

    // Pick the label set: heaviest MAX_LABELS live nodes.
    var live = clean.filter(function (x) { return x.kind !== 'you'; }).sort(function (a, b) { return b.weight - a.weight || (a.id < b.id ? -1 : 1); });
    // Fewer permanent labels on small canvases.
    var maxLabels = Math.min(MAX_LABELS, Math.max(6, Math.floor(this.width * this.height / 9000)));
    this.labelIds = live.slice(0, maxLabels).map(function (x) { return x.id; });

    // Accessibility summary.
    var counts = {you: 0, noise: 0, tor: 0, dns: 0, other: 0};
    for (i = 0; i < clean.length; i++) counts[clean[i].kind]++;
    var parts = [];
    ['you', 'noise', 'tor', 'dns', 'other'].forEach(function (k) {
      if (counts[k]) parts.push(counts[k] + ' ' + KIND_NAMES[k]);
    });
    this.svg.setAttribute('aria-label', clean.length
      ? 'Network map: ' + clean.length + ' connection' + (clean.length === 1 ? '' : 's') + ' from this computer (' + parts.join(', ') + ')'
      : 'Network map: no connections yet');
    this.emptyText.style.display = clean.length ? 'none' : '';
    this.count = clean.length;

    this.spread = Math.min(0.75, 0.1 + clean.length / 140);
    this._sizeNodes();

    if (this.hoverId !== null && this.nodes.has(this.hoverId)) {
      var hn = this.nodes.get(this.hoverId);
      this.tipTitle.textContent = hn.text || 'Your app';
      this.tipBody.textContent = hn.detail;
    }
    this._kick(added ? 0.8 : 0.12);
  };

  // Reheat the simulation and make sure the loop is running.
  NetMap.prototype._kick = function (heat) {
    if (this.destroyed) return;
    this.heat = Math.max(this.heat, heat);
    if (this.reduced) { this._settleNow(); return; }
    if (!this.raf) {
      var self = this;
      this.lastT = 0;
      this.raf = requestAnimationFrame(function (t) { self._frame(t); });
    }
  };

  // Reduced motion: no animation, run the layout to rest synchronously.
  NetMap.prototype._settleNow = function () {
    var self = this, rm = [];
    this.nodes.forEach(function (n) {
      if (n.removing) rm.push(n);
      else { n.alpha = 1; n.r = n.rt; n.lw = n.lwt; }
    });
    rm.forEach(function (n) { self._drop(n); });
    var cnt = this.nodes.size;
    // Bound the work: O(n^2) per iteration.
    var iters = clamp(Math.floor(6e6 / Math.max(1, cnt * cnt)), 40, 300);
    this.heat = 1;
    for (var i = 0; i < iters; i++) { this._tick(); this.heat = Math.max(0.05, this.heat * 0.985); }
    this.heat = 0;
    this._draw();
  };

  NetMap.prototype._frame = function (t) {
    this.raf = 0;
    if (this.destroyed) return;
    var now = performance.now(), busy = false, self = this, dead = [];

    // Fades and size easing.
    this.nodes.forEach(function (n) {
      if (n.removing) {
        n.alpha = 1 - (now - n.removedAt) / FADE_OUT_MS;
        if (n.alpha <= 0) dead.push(n); else busy = true;
      } else if (n.alpha < 1) {
        n.alpha = Math.min(1, (now - n.born) / FADE_IN_MS);
        busy = true;
      }
      if (Math.abs(n.rt - n.r) > 0.05 || Math.abs(n.lwt - n.lw) > 0.02) {
        n.r += (n.rt - n.r) * 0.15;
        n.lw += (n.lwt - n.lw) * 0.15;
        busy = true;
      } else { n.r = n.rt; n.lw = n.lwt; }
    });
    for (var i = 0; i < dead.length; i++) this._drop(dead[i]);

    if (this.heat > 0.004) { this._tick(); this.heat *= 0.982; busy = true; }
    else this.heat = 0;

    this._draw();
    if (busy) this.raf = requestAnimationFrame(function (tt) { self._frame(tt); });
  };

  // One step of the force simulation.
  NetMap.prototype._tick = function () {
    var arr = [], cx = this.cx, cy = this.cy, R = this.R, sx = this.sx, sy = this.sy;
    this.nodes.forEach(function (n) { if (!n.removing) arr.push(n); });
    var N = arr.length, i, j, a, b;
    if (!N) return;
    var heat = this.heat;
    var spread = this.spread || 0.1; // band thickness, grows with node count
    var fx = new Float64Array(N), fy = new Float64Array(N);

    for (i = 0; i < N; i++) {
      a = arr[i];
      // Spring toward an (elliptical) ring of rest length ~R around the center.
      var dx = a.x - cx, dy = a.y - cy;
      var u = dx / sx, v = dy / sy;
      var d = Math.sqrt(u * u + v * v) || 0.01;
      var rest = R * (1 + spread * (a.band - 0.5));
      var k = 0.06 * (d - rest) / d;
      fx[i] -= k * dx;
      fy[i] -= k * dy;
      // Keep clear of the center node.
      var minC = CENTER_R + a.r + 30;
      var dc = Math.sqrt(dx * dx + dy * dy) || 0.01;
      if (dc < minC) { fx[i] += (minC - dc) * 0.3 * dx / dc; fy[i] += (minC - dc) * 0.3 * dy / dc; }
    }

    // Pairwise repulsion (inverse-square, size aware), O(N^2) but N <= 300.
    for (i = 0; i < N; i++) {
      a = arr[i];
      for (j = i + 1; j < N; j++) {
        b = arr[j];
        var ddx = a.x - b.x, ddy = a.y - b.y;
        var d2 = ddx * ddx + ddy * ddy;
        if (d2 < 0.01) { ddx = (Math.random() - 0.5); ddy = (Math.random() - 0.5); d2 = ddx * ddx + ddy * ddy; }
        var s = a.r + b.r + 14;
        if (d2 > s * s * 36) continue; // ignore far pairs
        var dist = Math.sqrt(d2);
        var f = 0.6 * s * s / d2;
        // Extra push when circles overlap.
        if (dist < s - 8) f += (s - 8 - dist) * 0.5;
        if (f > 12) f = 12;
        var ux = ddx / dist * f, uy = ddy / dist * f;
        fx[i] += ux; fy[i] += uy;
        fx[j] -= ux; fy[j] -= uy;
      }
    }

    // Integrate with damping; keep nodes inside the canvas and off the legend.
    var w = this.width, h = this.height;
    for (i = 0; i < N; i++) {
      a = arr[i];
      a.vx = (a.vx + fx[i] * heat) * 0.6;
      a.vy = (a.vy + fy[i] * heat) * 0.6;
      var sp = Math.sqrt(a.vx * a.vx + a.vy * a.vy);
      if (sp > 15) { a.vx *= 15 / sp; a.vy *= 15 / sp; }
      a.x += a.vx;
      a.y += a.vy;
      var m = a.r + 3;
      a.x = clamp(a.x, m, w - m);
      a.y = clamp(a.y, m, h - m);
      // Legend box (top-left, ~110 x 74 px)
      if (a.x < 112 + a.r && a.y < 76 + a.r) {
        if (112 + a.r - a.x < 76 + a.r - a.y) a.x += (112 + a.r - a.x) * 0.5;
        else a.y += (76 + a.r - a.y) * 0.5;
      }
    }
  };

  // Push current state to the DOM.
  NetMap.prototype._draw = function () {
    var cx = this.cx, cy = this.cy;
    this.nodes.forEach(function (n) {
      var x = n.x.toFixed(1), y = n.y.toFixed(1);
      n.line.setAttribute('x1', cx);
      n.line.setAttribute('y1', cy);
      n.line.setAttribute('x2', x);
      n.line.setAttribute('y2', y);
      n.line.setAttribute('stroke-width', n.lw.toFixed(2));
      n.line.setAttribute('opacity', n.alpha.toFixed(3));
      n.g.setAttribute('transform', 'translate(' + x + ',' + y + ')');
      n.g.setAttribute('opacity', n.alpha.toFixed(3));
      var r = n.r.toFixed(2);
      n.circle.setAttribute('r', r);
      n.ring.setAttribute('r', r);
      n.hit.setAttribute('r', Math.max(n.r + 2, 9).toFixed(1));
    });
    this._drawLabels();
  };

  // Labels for the heaviest nodes (+ hovered one). Each label tries a few
  // positions (outward side first) and takes the one that stays on-canvas,
  // never overlaps another label and covers the fewest other nodes.
  NetMap.prototype._drawLabels = function () {
    var ids = (this.labelIds || []).slice();
    if (this.hoverId !== null && ids.indexOf(this.hoverId) < 0) {
      var hv = this.nodes.get(this.hoverId);
      if (hv && hv.text) ids.unshift(this.hoverId);
    }
    var want = Object.create(null), placed = [], w = this.width, h = this.height;
    var others = [];
    this.nodes.forEach(function (n) { if (!n.removing) others.push(n); });
    // Reserve the center label and legend areas.
    placed.push({x0: this.cx - 48, x1: this.cx + 48, y0: this.cy - CENTER_R - 2, y1: this.cy + CENTER_R + 20});
    placed.push({x0: 0, x1: 110, y0: 0, y1: 74});

    function overlaps(b, p) { return b.x0 < p.x1 && b.x1 > p.x0 && b.y0 < p.y1 && b.y1 > p.y0; }

    for (var i = 0; i < ids.length; i++) {
      var n = this.nodes.get(ids[i]);
      if (!n || n.removing) continue;
      var txt = truncate(n.text, LABEL_CHARS);
      var tw = txt.length * CHAR_W, th = 12, off = n.r + 3;
      var outR = n.x >= this.cx;
      // Candidate boxes: [x0, y0] of the text box; anchor derived from x.
      var cands = [
        outR ? [n.x + off, n.y - th / 2] : [n.x - off - tw, n.y - th / 2],
        outR ? [n.x - off - tw, n.y - th / 2] : [n.x + off, n.y - th / 2],
        [n.x - tw / 2, n.y - off - th],
        [n.x - tw / 2, n.y + off]
      ];
      var best = null, bestScore = Infinity, hovered = n.id === this.hoverId;
      for (var c = 0; c < cands.length; c++) {
        var b = {x0: cands[c][0], y0: cands[c][1]};
        b.x1 = b.x0 + tw; b.y1 = b.y0 + th;
        if (b.x0 < 2 || b.x1 > w - 2 || b.y0 < 2 || b.y1 > h - 2) continue;
        var bad = false;
        for (var j = 0; j < placed.length && !bad; j++) bad = overlaps(b, placed[j]);
        if (bad && !hovered) continue;
        var score = c * 0.5 + (bad ? 100 : 0);
        for (j = 0; j < others.length; j++) {
          var o = others[j];
          if (o === n) continue;
          var qx = clamp(o.x, b.x0, b.x1), qy = clamp(o.y, b.y0, b.y1);
          var ex = o.x - qx, ey = o.y - qy;
          if (ex * ex + ey * ey < o.r * o.r) score += 1 + o.r / 10;
        }
        if (score < bestScore) { bestScore = score; best = b; }
        if (score === 0) break;
      }
      if (!best) continue;
      placed.push(best);
      want[n.id] = 1;
      if (!n.label) {
        n.label = el('text', {'font-size': 11, 'paint-order': 'stroke', 'stroke-linejoin': 'round',
          'stroke-width': 3, 'stroke-opacity': 0.8}, this.gLabels);
      }
      if (n.labelText !== txt) { n.label.textContent = txt; n.labelText = txt; }
      n.label.setAttribute('fill', this.colors.ink);
      n.label.setAttribute('stroke', this.colors.panel);
      n.label.setAttribute('x', best.x0.toFixed(1));
      n.label.setAttribute('y', (best.y1 - 2.5).toFixed(1));
      n.label.setAttribute('opacity', n.alpha.toFixed(3));
      n.label.setAttribute('font-weight', hovered ? 600 : 400);
      n.label.style.display = '';
    }
    this.nodes.forEach(function (n) {
      if (n.label && !want[n.id]) n.label.style.display = 'none';
    });
  };

  /** Stop animation, remove listeners and DOM. */
  NetMap.prototype.destroy = function () {
    if (this.destroyed) return;
    this.destroyed = true;
    if (this.raf) cancelAnimationFrame(this.raf);
    this.raf = 0;
    if (this.ro) this.ro.disconnect();
    if (this.mo) this.mo.disconnect();
    if (this.mqDark) unlisten(this.mqDark, this._onScheme);
    if (this.mqMotion) unlisten(this.mqMotion, this._onMotion);
    this.gNodes.removeEventListener('pointerover', this._onOver);
    this.gNodes.removeEventListener('pointerout', this._onOut);
    this.svg.removeEventListener('pointermove', this._onMove);
    this.svg.removeEventListener('click', this._onClick);
    if (this.wrap.parentNode) this.wrap.parentNode.removeChild(this.wrap);
    this.nodes.clear();
  };

  window.NetMap = NetMap;
})();
