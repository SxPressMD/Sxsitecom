const API = (window.location.origin.includes('localhost') ? 'http://localhost:3000' : '') || '';

document.getElementById('year').innerText = new Date().getFullYear();

const grid = document.getElementById('product-grid');
const search = document.getElementById('search');

async function fetchProducts(q=''){
  try{
    const res = await fetch(`${API}/products${q? '?q=' + encodeURIComponent(q): ''}`);
    const data = await res.json();
    return data;
  }catch(err){
    console.error(err);
    return [];
  }
}

function renderProducts(products, container){
  container.innerHTML = '';
  products.forEach(p=>{
    const el = document.createElement('article');
    el.className = 'card product-card';
    el.innerHTML = `
      <img class="product-thumb" src="${p.image || 'placeholder.png'}" alt="${escapeHtml(p.title)}" />
      <div class="product-title">${escapeHtml(p.title)}</div>
      <div class="product-cta">
        <a class="btn" href="${p.link}" target="_blank" rel="noopener">Ver</a>
      </div>
    `;
    container.appendChild(el);
  });
}

function escapeHtml(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;') }

async function load(q){
  const products = await fetchProducts(q);
  renderProducts(products, grid);
}

search.addEventListener('input', e=>{
  load(e.target.value);
});

document.getElementById('btn-login').addEventListener('click', ()=> {
  window.location.href = '/admin.html';
});

// initial load
load();
