const rows = document.getElementById('rows') as HTMLTableSectionElement;
const loadBtn = document.getElementById('load') as HTMLButtonElement;
const siteIdEl = document.getElementById('siteId') as HTMLInputElement;
const ratingEl = document.getElementById('rating') as HTMLSelectElement;
const qEl = document.getElementById('q') as HTMLInputElement;
const yearEl = document.getElementById('year') as HTMLSpanElement | null;
const themeToggle = document.getElementById('themeToggle') as HTMLButtonElement | null;
const prevBtn = document.getElementById('prev') as HTMLButtonElement | null;
const nextBtn = document.getElementById('next') as HTMLButtonElement | null;
const countEl = document.getElementById('count') as HTMLSpanElement | null;
const limitEl = document.getElementById('limit') as HTMLSelectElement | null;
const chartCanvas = document.getElementById('thumbChart') as HTMLCanvasElement | null;
const chartLabel = document.getElementById('chartLabel') as HTMLSpanElement | null;

const API_BASE = (() => {
  // 1) Runtime env (set in /public/env.js): window.__FIDBAK_API_BASE = 'https://api.example.com'
  const w = window as any;
  if (typeof w.__FIDBAK_API_BASE === 'string' && w.__FIDBAK_API_BASE) return w.__FIDBAK_API_BASE;
  // 2) Dev autodetect (Vite)
  const port = location.port;
  if (port === '5173') return 'http://localhost:8787';
  // 3) Relative (same-origin) by default in prod
  return '';
})();

let state = {
  offset: 0,
  limit: 20,
  total: 0,
  lastSite: '',
  lastRating: '',
  lastQuery: '',
};

async function load() {
  const siteId = siteIdEl.value.trim();
  if (!siteId) {
    rows.innerHTML = `<tr><td colspan="5" class="empty"><div class="kicker">Enter a Site ID</div></td></tr>`;
    return;
  }
  const params = new URLSearchParams();
  if (ratingEl.value) params.set('rating', ratingEl.value);
  if (qEl.value) params.set('q', qEl.value);
  try {
    setLoading(true);
    state.lastSite = siteId; state.lastRating = ratingEl.value; state.lastQuery = qEl.value;
    const limit = Number(limitEl?.value || state.limit);
    state.limit = isNaN(limit) ? 20 : limit;
    params.set('limit', String(state.limit));
    params.set('offset', String(state.offset));
    const url = `${API_BASE}/v1/sites/${encodeURIComponent(siteId)}/feedback${params.toString() ? `?${params.toString()}` : ''}`;
    const res = await fetch(url, {
      headers: {
        accept: 'application/json'
      }
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const items = data.items ?? [];
    state.total = typeof data.total === 'number' ? data.total : (state.offset + items.length);
    renderRows(items);
    updatePager();
    drawChart(items);
  } catch (err) {
    console.error(err);
    rows.innerHTML = `<tr><td colspan="5" class="empty">Failed to load: ${(err as Error).message}</td></tr>`;
  }
  finally { setLoading(false); }
}

function escapeHtml(s: string) {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function renderRows(items: any[]) {
  if (!items.length) {
    rows.innerHTML = '<tr><td colspan="5" class="empty">No results</td></tr>';
    return;
  }
  rows.innerHTML = items
    .map((it) => {
      const d = new Date(it.created_at ?? Date.now()).toLocaleString();
      const rating = it.rating === 'up' ? '👍' : it.rating === 'down' ? '👎' : '';
      const page = it.page_id ?? '-';
      const ctx = (it.context_json ?? {}) as Record<string, any>;
      const url = typeof ctx.url === 'string' ? ctx.url : '';
      const title = typeof ctx.title === 'string' ? ctx.title : '';
      const nearest = typeof ctx.nearestHeading === 'string' ? ctx.nearestHeading : '';
      const scroll = typeof ctx.scrollPct === 'number' ? `${ctx.scrollPct}%` : '';
      const selected = typeof ctx.selectedText === 'string' ? ctx.selectedText : '';
      const pageCell = url
        ? `<div><a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(
            page
          )}</a></div><div style="color:#6b7280; font-size:12px; line-height:1.2" title="${escapeHtml(
            selected
          )}">${escapeHtml(title)}${nearest ? ` • ${escapeHtml(nearest)}` : ''}${scroll ? ` • ${escapeHtml(scroll)}` : ''}</div>`
        : escapeHtml(page);
      const comment = escapeHtml(it.comment ?? '');
      const email = it.email ?? '';
      return `<tr>
        <td data-k="When">${d}</td>
        <td data-k="Rating">${rating}</td>
        <td data-k="Page">${pageCell}</td>
        <td data-k="Comment">${comment}</td>
        <td data-k="Email">${email}</td>
      </tr>`;
    })
    .join('');
}

function setLoading(on: boolean) {
  const emptyMsg = document.getElementById('emptyMsg');
  if (!emptyMsg) return;
  const spinner = (emptyMsg.previousElementSibling as HTMLElement | null);
  if (on) {
    if (spinner) spinner.style.display = 'inline-block';
    emptyMsg.textContent = 'Loading…';
  } else {
    if (spinner) spinner.style.display = 'none';
  }
}

function initTheme() {
  const root = document.documentElement;
  const saved = localStorage.getItem('fidbak:dash:theme');
  if (!saved || saved === 'light') {
    root.classList.add('light');
  } else {
    root.classList.remove('light');
  }
  themeToggle?.addEventListener('click', () => {
    const isLight = root.classList.toggle('light');
    localStorage.setItem('fidbak:dash:theme', isLight ? 'light' : 'dark');
  });
}

function initMisc() {
  if (yearEl) yearEl.textContent = String(new Date().getFullYear());
  // Default limit
  if (limitEl) state.limit = Number(limitEl.value) || 20;
  prevBtn?.addEventListener('click', () => {
    state.offset = Math.max(0, state.offset - state.limit);
    load();
  });
  nextBtn?.addEventListener('click', () => {
    state.offset = state.offset + state.limit;
    load();
  });
  limitEl?.addEventListener('change', () => {
    state.limit = Number(limitEl.value) || 20;
    state.offset = 0;
    load();
  });
}

document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  initMisc();
});

loadBtn.addEventListener('click', load);

function updatePager() {
  const start = state.total === 0 ? 0 : state.offset + 1;
  const end = Math.min(state.total, state.offset + state.limit);
  if (countEl) countEl.textContent = `Showing ${start}–${end} of ${state.total}`;
  if (prevBtn) prevBtn.disabled = state.offset <= 0;
  if (nextBtn) nextBtn.disabled = end >= state.total;
}

function drawChart(items: any[]) {
  if (!chartCanvas) return;
  const up = items.filter(i => i.rating === 'up').length;
  const down = items.filter(i => i.rating === 'down').length;
  if (chartLabel) chartLabel.textContent = `👍 ${up} • 👎 ${down}`;
  const ctx = chartCanvas.getContext('2d');
  if (!ctx) return;
  ctx.clearRect(0,0,chartCanvas.width,chartCanvas.height);
  const total = Math.max(1, up + down);
  const w = chartCanvas.width - 2; const h = chartCanvas.height - 14;
  const upW = Math.round((up / total) * w);
  const downW = w - upW;
  // background track
  ctx.fillStyle = 'rgba(148,163,184,0.25)';
  ctx.fillRect(1,7,w,h);
  // up segment (emerald)
  ctx.fillStyle = '#22c55e';
  ctx.fillRect(1,7,upW,h);
  // down segment (rose)
  ctx.fillStyle = '#ef4444';
  ctx.fillRect(1+upW,7,downW,h);
  // border
  ctx.strokeStyle = 'rgba(148,163,184,0.35)';
  ctx.strokeRect(1,7,w,h);
}
