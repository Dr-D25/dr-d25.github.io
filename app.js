const listEl     = document.getElementById('article-list');
const articleEl  = document.getElementById('article');
const headerEl   = document.getElementById('content-header');

let articles = [];

marked.setOptions({ breaks: true, gfm: true });

async function loadArticles() {
  try {
    const res = await fetch('articles.json');
    if (!res.ok) throw new Error('articles.json не найден');
    articles = await res.json();
    renderList();

    const slug = location.hash.slice(1) || articles[0]?.slug;
    if (slug) loadArticle(slug);
  } catch (e) {
    listEl.innerHTML = `<div style="padding: 20px; color: var(--error);">${e.message}</div>`;
  }
}

function renderList() {
  listEl.innerHTML = '';
  articles.forEach(a => {
    const link = document.createElement('a');
    link.href = '#' + a.slug;
    link.textContent = a.title;
    link.dataset.slug = a.slug;
    listEl.appendChild(link);
  });
}

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
    articleEl.innerHTML = marked.parse(text);
    if (typeof hljs !== 'undefined') {
      articleEl.querySelectorAll('pre code').forEach(el => {
        el.removeAttribute('data-highlighted');
        hljs.highlightElement(el);
      });
    }
    articleEl.scrollTop = 0;
    document.title = `${meta.title} — ~/notes`;
  } catch (e) {
    articleEl.innerHTML = `<p style="color: var(--error);">Ошибка загрузки: ${e.message}</p>`;
  }
}

window.addEventListener('hashchange', () => {
  const slug = location.hash.slice(1);
  if (slug) loadArticle(slug);
});

loadArticles();
