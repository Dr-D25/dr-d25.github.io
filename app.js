/* =========================================================
   Константы
   ========================================================= */
const SITE_NAME = 'Dr-D25';
const SECTIONS = {
  notes:    'Заметки',
  articles: 'Статьи',
  reports:  'Отчёты',
};
const WORDS_PER_MIN = 200;

/* =========================================================
   State
   ========================================================= */
const state = {
  articles: [],
  currentTag: null,
  searchQuery: '',
};

/* =========================================================
   DOM
   ========================================================= */
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

const views = {
  home:    $('#view-home'),
  article: $('#view-article'),
  archive: $('#view-archive'),
  tags:    $('#view-tags'),
  about:   $('#view-about'),
};

const articleContent = $('#article-content');
const tocSidebar     = $('#toc-sidebar');
const tocList        = $('#toc-list');
const articleLayout  = $('#article-layout');
const postNav        = $('#post-nav');
const postList       = $('#post-list');
const tagCloud       = $('#tag-cloud');
const archiveList    = $('#archive-list');
const breadcrumb     = $('#breadcrumb');
const backBtn        = $('#back-btn');
const searchInput    = $('#search');
const filterBadge    = $('#filter-badge');
const emptyHome      = $('#empty-home');

/* =========================================================
   Marked config
   ========================================================= */
marked.setOptions({ gfm: true, breaks: true });

/* =========================================================
   Инициализация
   ========================================================= */
async function init() {
  applyTheme(document.documentElement.getAttribute('data-theme') || 'dark');
  bindThemeToggle();
  bindSearch();
  bindBack();
  await loadArticles();
  window.addEventListener('hashchange', route);
  route();
}

/* =========================================================
   Тема
   ========================================================= */
function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('theme', theme);

  const icon = $('#theme-toggle i');
  if (icon) icon.className = theme === 'dark' ? 'fas fa-moon' : 'fas fa-sun';

  const hlDark  = document.getElementById('hl-dark');
  const hlLight = document.getElementById('hl-light');
  if (hlDark && hlLight) {
    hlDark.disabled  = theme !== 'dark';
    hlLight.disabled = theme !== 'light';
  }
}

function bindThemeToggle() {
  $('#theme-toggle').addEventListener('click', () => {
    const current = document.documentElement.getAttribute('data-theme');
    applyTheme(current === 'dark' ? 'light' : 'dark');
  });
}

/* =========================================================
   Загрузка статей
   ========================================================= */
async function loadArticles() {
  try {
    const res = await fetch('articles.json', { cache: 'no-cache' });
    if (!res.ok) throw new Error(`articles.json: HTTP ${res.status}`);
    state.articles = await res.json();
    state.articles.sort((a, b) => (b.date || '').localeCompare(a.date || ''));
  } catch (e) {
    console.error(e);
    postList.innerHTML = `<div class="error-msg">Не удалось загрузить статьи: ${e.message}</div>`;
  }
}

/* =========================================================
   Роутинг (hash)
   ========================================================= */
function route() {
  const hash = location.hash.replace(/^#/, '') || '/';

  if (hash === '/' || hash === '') {
    showHome();
  } else if (hash.startsWith('/post/')) {
    showArticle(decodeURIComponent(hash.slice('/post/'.length)));
  } else if (hash === '/archive') {
    showArchive();
  } else if (hash === '/tags') {
    showTags();
  } else if (hash === '/about') {
    showAbout();
  } else if (hash.startsWith('/tag/')) {
    const tag = decodeURIComponent(hash.slice('/tag/'.length));
    showHome(tag);
  } else {
    showHome();
  }

  window.scrollTo({ top: 0, behavior: 'instant' });
}

function switchView(name) {
  Object.entries(views).forEach(([key, el]) => {
    el.hidden = key !== name;
  });
  updateNavActive(name);
  backBtn.hidden = name !== 'article';
}

function updateNavActive(name) {
  // В режиме статьи подсвечиваем "Главная"
  const navName = name === 'article' ? 'home' : name;
  $$('.nav a').forEach(a => {
    a.classList.toggle('active', a.dataset.nav === navName);
  });
}

/* =========================================================
   Home
   ========================================================= */
function showHome(tag = null) {
  state.currentTag = tag;
  switchView('home');
  document.title = `${SITE_NAME} — Заметки`;
  breadcrumb.textContent = '';

  renderFilterBadge();
  renderPostList();
}

function renderFilterBadge() {
  if (!state.currentTag) {
    filterBadge.hidden = true;
    filterBadge.innerHTML = '';
    return;
  }
  filterBadge.hidden = false;
  filterBadge.innerHTML = `
    <span>#${escapeHtml(state.currentTag)}</span>
    <button title="Сбросить фильтр" aria-label="Сбросить">×</button>
  `;
  filterBadge.querySelector('button').onclick = () => {
    location.hash = '#/';
  };
}

function renderPostList() {
  const q = state.searchQuery.trim().toLowerCase();

  const filtered = state.articles.filter(a => {
    if (state.currentTag && !(a.tags || []).includes(state.currentTag)) return false;
    if (q) {
      const hay = [a.title, a.description || '', ...(a.tags || [])].join(' ').toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  postList.innerHTML = '';

  if (!filtered.length) {
    emptyHome.hidden = false;
    return;
  }
  emptyHome.hidden = true;

  filtered.forEach(meta => {
    const card = document.createElement('article');
    card.className = 'post-card';
    card.innerHTML = `
      <div class="post-meta">
        ${meta.date ? `<span><i class="far fa-calendar"></i> ${formatDate(meta.date)}</span>` : ''}
        ${meta.section ? `<span><i class="fas fa-folder"></i> ${SECTIONS[meta.section] || meta.section}</span>` : ''}
      </div>
      <h2 class="post-title">${escapeHtml(meta.title)}</h2>
      ${meta.description ? `<p class="post-desc">${escapeHtml(meta.description)}</p>` : ''}
      ${(meta.tags || []).length ? `
        <div class="post-tags">
          ${meta.tags.map(t => `<span class="tag" data-tag="${escapeHtml(t)}">#${escapeHtml(t)}</span>`).join('')}
        </div>` : ''}
    `;

    card.addEventListener('click', (e) => {
      const tagEl = e.target.closest('.tag');
      if (tagEl) {
        e.stopPropagation();
        location.hash = `#/tag/${encodeURIComponent(tagEl.dataset.tag)}`;
        return;
      }
      location.hash = `#/post/${encodeURIComponent(meta.slug)}`;
    });

    postList.appendChild(card);
  });
}

function bindSearch() {
  searchInput.addEventListener('input', (e) => {
    state.searchQuery = e.target.value;
    renderPostList();
  });
}

/* =========================================================
   Article
   ========================================================= */
async function showArticle(slug) {
  const meta = state.articles.find(a => a.slug === slug);
  if (!meta) {
    switchView('article');
    articleContent.innerHTML = `<div class="error-msg">Статья «${escapeHtml(slug)}» не найдена.</div>`;
    tocSidebar.style.display = 'none';
    articleLayout.classList.add('no-toc');
    postNav.innerHTML = '';
    document.title = 'Не найдено';
    return;
  }

  switchView('article');
  document.title = `${meta.title} — ${SITE_NAME}`;
  breadcrumb.textContent = `${SECTIONS[meta.section] || meta.section} / ${meta.title}`;
  articleContent.innerHTML = '<p class="loading">Загрузка</p>';
  tocSidebar.style.display = '';
  articleLayout.classList.remove('no-toc');
  postNav.innerHTML = '';

  try {
    const res = await fetch(`articles/${slug}.md`, { cache: 'no-cache' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const markdown = await res.text();

    const plain = markdown.replace(/```[\s\S]*?```/g, '').replace(/[#*_`>\-\[\]()]/g, ' ');
    const words = plain.split(/\s+/).filter(Boolean).length;
    const minutes = Math.max(1, Math.ceil(words / WORDS_PER_MIN));

    const html = marked.parse(markdown);
    articleContent.innerHTML = buildArticleHeader(meta, minutes, words) +
                               `<div class="markdown-body">${html}</div>`;

    processCallouts(articleContent);
    processImages(articleContent);
    buildToc();
    highlightCode(articleContent);
    buildPostNav(slug);

    // плавный скролл к началу
    window.scrollTo({ top: 0, behavior: 'instant' });
  } catch (e) {
    articleContent.innerHTML = `<div class="error-msg">Ошибка загрузки: ${e.message}</div>`;
  }
}

function buildArticleHeader(meta, minutes, words) {
  const parts = [];
  if (meta.date) parts.push(`<span><i class="far fa-calendar"></i> ${formatDate(meta.date)}</span>`);
  if (meta.section) parts.push(`<span><i class="fas fa-folder"></i> ${SECTIONS[meta.section] || meta.section}</span>`);
  parts.push(`<span><i class="far fa-clock"></i> ${minutes} мин чтения</span>`);
  parts.push(`<span><i class="fas fa-align-left"></i> ${words} слов</span>`);

  return `
    <header class="article-header">
      <div class="article-meta-top">${parts.join('')}</div>
      <h1>${escapeHtml(meta.title)}</h1>
      ${meta.description ? `<p class="article-desc">${escapeHtml(meta.description)}</p>` : ''}
    </header>
  `;
}

function processCallouts(root) {
  $$('blockquote', root).forEach(bq => {
    const first = bq.querySelector('p');
    if (!first) return;
    const m = first.textContent.match(/^\[!(WARNING|NOTE|TIP|DANGER|INFO)\]\s*/i);
    if (!m) return;
    first.textContent = first.textContent.replace(/^\[![^\]]+\]\s*/, '');
    bq.classList.add('callout', 'callout-' + m[1].toLowerCase());
    bq.dataset.label = m[1].toUpperCase();
  });
}

function processImages(root) {
  $$('img', root).forEach(img => {
    img.loading = 'lazy';
    img.decoding = 'async';
  });
}

function highlightCode(root) {
  if (typeof hljs === 'undefined') return;
  $$('pre code', root).forEach(el => {
    el.removeAttribute('data-highlighted');
    try { hljs.highlightElement(el); } catch (e) { /* noop */ }
  });
}

/* =========================================================
   TOC
   ========================================================= */
function buildToc() {
  const headings = $$('.markdown-body h2, .markdown-body h3', articleContent);

  if (headings.length < 2) {
    tocSidebar.style.display = 'none';
    articleLayout.classList.add('no-toc');
    return;
  }

  tocSidebar.style.display = '';
  articleLayout.classList.remove('no-toc');
  tocList.innerHTML = '';

  headings.forEach((h, i) => {
    const id = 'h-' + i;
    h.id = id;

    const li = document.createElement('li');
    li.className = 'toc-' + h.tagName.toLowerCase();

    const a = document.createElement('a');
    a.href = 'javascript:void(0)';
    a.textContent = h.textContent;

    a.addEventListener('click', (e) => {
      e.preventDefault();
      h.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });

    li.appendChild(a);
    tocList.appendChild(li);
  });
}

/* =========================================================
   Prev / Next
   ========================================================= */
function buildPostNav(slug) {
  const idx = state.articles.findIndex(a => a.slug === slug);
  if (idx === -1) {
    postNav.innerHTML = '';
    return;
  }

  // articles отсортированы «свежее сверху», значит prev (новее) = idx-1, next (старее) = idx+1
  const prev = state.articles[idx - 1];
  const next = state.articles[idx + 1];

  postNav.innerHTML = `
    ${prev ? `
      <a class="prev" href="#/post/${encodeURIComponent(prev.slug)}">
        <span class="nav-dir">← Новее</span>
        <span class="nav-title">${escapeHtml(prev.title)}</span>
      </a>` : '<span class="empty-nav"></span>'}
    ${next ? `
      <a class="next" href="#/post/${encodeURIComponent(next.slug)}">
        <span class="nav-dir">Старее →</span>
        <span class="nav-title">${escapeHtml(next.title)}</span>
      </a>` : '<span class="empty-nav"></span>'}
  `;
}

/* =========================================================
   Archive
   ========================================================= */
function showArchive() {
  switchView('archive');
  document.title = `Архив — ${SITE_NAME}`;
  breadcrumb.textContent = 'Архив';

  const total = state.articles.length;
  $('#archive-count').textContent = `Всего записей: ${total}`;

  // группировка по годам
  const groups = new Map();
  state.articles.forEach(a => {
    const year = (a.date || '').slice(0, 4) || '—';
    if (!groups.has(year)) groups.set(year, []);
    groups.get(year).push(a);
  });

  archiveList.innerHTML = '';
  if (!total) {
    archiveList.innerHTML = '<p class="empty">Пока пусто</p>';
    return;
  }

  [...groups.keys()].sort((a, b) => b.localeCompare(a)).forEach(year => {
    const header = document.createElement('div');
    header.className = 'archive-year';
    header.textContent = year;
    archiveList.appendChild(header);

    groups.get(year).forEach(a => {
      const item = document.createElement('div');
      item.className = 'archive-item';
      item.innerHTML = `
        <span class="archive-date">${a.date || ''}</span>
        <a href="#/post/${encodeURIComponent(a.slug)}">${escapeHtml(a.title)}</a>
        <span class="archive-section">${SECTIONS[a.section] || a.section || ''}</span>
      `;
      archiveList.appendChild(item);
    });
  });
}

/* =========================================================
   Tags
   ========================================================= */
function showTags() {
  switchView('tags');
  document.title = `Теги — ${SITE_NAME}`;
  breadcrumb.textContent = 'Теги';

  const counts = new Map();
  state.articles.forEach(a => {
    (a.tags || []).forEach(t => counts.set(t, (counts.get(t) || 0) + 1));
  });

  const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));

  tagCloud.innerHTML = '';
  if (!sorted.length) {
    tagCloud.innerHTML = '<p class="empty">Пока нет тегов</p>';
    return;
  }

  sorted.forEach(([tag, count]) => {
    const a = document.createElement('a');
    a.href = `#/tag/${encodeURIComponent(tag)}`;
    a.innerHTML = `#${escapeHtml(tag)} <span class="tag-count">${count}</span>`;
    tagCloud.appendChild(a);
  });
}

/* =========================================================
   About
   ========================================================= */
function showAbout() {
  switchView('about');
  document.title = `Обо мне — ${SITE_NAME}`;
  breadcrumb.textContent = 'Обо мне';
}

/* =========================================================
   Helpers
   ========================================================= */
function bindBack() {
  backBtn.addEventListener('click', () => {
    if (history.length > 1) history.back();
    else location.hash = '#/';
  });
}

function formatDate(str) {
  if (!str) return '';
  // 'YYYY-MM-DD' → '27 окт 2026'
  const months = ['янв','фев','мар','апр','мая','июн','июл','авг','сен','окт','ноя','дек'];
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(str);
  if (!m) return str;
  const [, y, mo, d] = m;
  return `${parseInt(d, 10)} ${months[parseInt(mo, 10) - 1]} ${y}`;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

/* =========================================================
   Запуск
   ========================================================= */
init();
