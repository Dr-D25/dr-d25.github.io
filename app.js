const listEl      = document.getElementById('article-list');
const articleEl   = document.getElementById('article');
const headerEl    = document.getElementById('content-header');
const searchEl    = document.getElementById('search');
const tagFilterEl = document.getElementById('tag-filter');

let articles = [];
let currentTag = null;
let searchQuery = '';

marked.setOptions({ breaks: true, gfm: true });

/* ---------- загрузка ---------- */
async function loadArticles() {
  try {
    const res = await fetch('articles.json');
    if (!res.ok) throw new Error('articles.json не найден');
    articles = await res.json();
    articles.sort((a, b) => (b.date || '').localeCompare(a.date || ''));
    renderTagFilter();
    renderList();

    const slug = location.hash.slice(1) || articles[0]?.slug;
    if (slug) loadArticle(slug);
  } catch (e) {
    listEl.innerHTML = `<div style="padding:20px;color:var(--error);">${e.message}</div>`;
  }
}

/* ---------- фильтр по тегам ---------- */
function allTags() {
  const set = new Set();
  articles.forEach(a => (a.tags || []).forEach(t => set.add(t)));
  return [...set].sort();
}

function renderTagFilter() {
  tagFilterEl.innerHTML = '';
  const chip = (label, value) => {
    const b = document.createElement('button');
    b.className = 'tag-chip' + (currentTag === value ? ' active' : '');
    b.textContent = label;
    b.onclick = () => {
      currentTag = currentTag === value ? null : value;
      renderTagFilter();
      renderList();
    };
    return b;
  };
  tagFilterEl.appendChild(chip('все', null));
  allTags().forEach(t => tagFilterEl.appendChild(chip(t, t)));
}

/* ---------- список ---------- */
function getFiltered() {
  return articles.filter(a => {
    if (currentTag && !(a.tags || []).includes(currentTag)) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const hay = [a.title, a.description || '', ...(a.tags || [])].join(' ').toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

function renderList() {
  listEl.innerHTML = '';
  const items = getFiltered();
  if (!items.length) {
    listEl.innerHTML = '<div style="padding:12px 20px;color:var(--fg-dim);font-size:13px;">// ничего не найдено</div>';
    return;
  }
  items.forEach(a => {
    const link = document.createElement('a');
    link.href = '#' + a.slug;
    link.dataset.slug = a.slug;
    link.innerHTML =
      `<span class="item-title">${escapeHtml(a.title)}</span>` +
      (a.date ? `<span class="item-date">${a.date}</span>` : '');
    if (a.slug === location.hash.slice(1)) link.classList.add('active');
    listEl.appendChild(link);
  });
}

/* ---------- статья ---------- */
async function loadArticle(slug) {
  const meta = articles.find(a => a.slug === slug);
  if (!meta) {
    articleEl.innerHTML = '<p class="loading">Статья не найдена</p>';
    return;
  }

  document.querySelectorAll('#article-list a').forEach(a => {
    a.classList.toggle('active', a.dataset.slug === slug);
  });

  headerEl.textContent = `~/notes $ cat articles/${slug}.md`;
  articleEl.innerHTML = '<p class="loading">Загрузка...</p>';

  try {
    const res = await fetch(`articles/${slug}.md`);
    if (!res.ok) throw new Error('Файл не найден');
    const text = await res.text();

    const words   = text.split(/\s+/).filter(Boolean).length;
    const minutes = Math.max(1, Math.ceil(words / 180));

    articleEl.innerHTML = buildMeta(meta, minutes) + marked.parse(text);

    processCallouts(articleEl);
    buildToc();

    if (typeof hljs !== 'undefined') {
      articleEl.querySelectorAll('pre code').forEach(el => {
        el.removeAttribute('data-highlighted');
        hljs.highlightElement(el);
      });
    }

    articleEl.scrollTop = 0;
    document.title = `${meta.title} — ~/notes`;
  } catch (e) {
    articleEl.innerHTML = `<p style="color:var(--error);">Ошибка загрузки: ${e.message}</p>`;
  }
}

function buildMeta(meta, minutes) {
  const tags = (meta.tags || [])
    .map(t => `<span class="meta-tag">${escapeHtml(t)}</span>`)
    .join('');
  const parts = [];
  if (meta.date) parts.push(`<span class="meta-date">${meta.date}</span>`);
  parts.push(`<span class="meta-time">~${minutes} мин</span>`);
  if (tags) parts.push(`<span class="meta-tags">${tags}</span>`);
  return `<div class="article-meta">${parts.join('<span class="meta-sep">·</span>')}</div>`;
}

/* ---------- callouts > [!WARNING] ---------- */
function processCallouts(root) {
  root.querySelectorAll('blockquote').forEach(bq => {
    const first = bq.querySelector('p');
    if (!first) return;
    const m = first.textContent.match(/^\[!(WARNING|NOTE|TIP|DANGER|INFO)\]\s*/i);
    if (!m) return;
    first.textContent = first.textContent.replace(/^\[![^\]]+\]\s*/, '');
    bq.classList.add('callout', 'callout-' + m[1].toLowerCase());
    bq.dataset.label = m[1].toUpperCase();
  });
}

/* ---------- TOC из h2/h3 ---------- */
function buildToc() {
  const headings = articleEl.querySelectorAll('h2, h3');
  if (headings.length < 2) return;

  const toc = document.createElement('div');
  toc.className = 'toc';
  toc.innerHTML = '<div class="toc-title">// toc</div>';

  const ul = document.createElement('ul');
  headings.forEach((h, i) => {
    h.id = 'h-' + i;
    const li = document.createElement('li');
    li.className = 'toc-' + h.tagName.toLowerCase();
    const a = document.createElement('a');
    a.textContent = h.textContent;
    a.href = '#';
    a.onclick = (e) => {
      e.preventDefault();
      h.scrollIntoView({ behavior: 'smooth', block: 'start' });
    };
    li.appendChild(a);
    ul.appendChild(li);
  });
  toc.appendChild(ul);

  const meta = articleEl.querySelector('.article-meta');
  (meta || articleEl).after(toc);
}

/* ---------- события ---------- */
searchEl.addEventListener('input', (e) => {
  searchQuery = e.target.value.trim();
  renderList();
});

window.addEventListener('hashchange', () => {
  const slug = location.hash.slice(1);
  if (slug) loadArticle(slug);
});

loadArticles();
