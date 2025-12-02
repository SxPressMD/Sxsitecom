const API = (window.location.origin.includes('localhost') ? 'http://localhost:3000' : '') || '';

/* Elements */
const loginSection = document.getElementById('login-section');
const loginForm = document.getElementById('login-form');
const loginMsg = document.getElementById('login-msg');
const twoFASection = document.getElementById('2fa-section');
const twoFAForm = document.getElementById('2fa-form');
const twoFAMsg = document.getElementById('2fa-msg');

const adminPanel = document.getElementById('admin-panel');
const logoutBtn = document.getElementById('btn-logout');

const prodForm = document.getElementById('product-form');
const prodTableBody = document.querySelector('#prod-table tbody');
const previewGrid = document.getElementById('preview-grid');
const auditLog = document.getElementById('audit-log');

let tempToken = null; // returned after pwd check, used for 2fa
let jwtToken = null;

function setAuthToken(t){
  jwtToken = t;
  if(t) localStorage.setItem('admin_jwt', t);
  else localStorage.removeItem('admin_jwt');
}

function getAuthHeader(){
  return jwtToken ? { Authorization: 'Bearer ' + jwtToken } : {};
}

/* init: try to restore token */
(function initAuth(){
  const token = localStorage.getItem('admin_jwt');
  if(token){
    jwtToken = token;
    showAdminPanel();
    loadProducts();
    loadLog();
  }
})();

/* Login (step 1: email+password) */
loginForm.addEventListener('submit', async (e)=>{
  e.preventDefault();
  loginMsg.textContent = '';
  const email = document.getElementById('email').value;
  const password = document.getElementById('password').value;
  try{
    const res = await fetch(`${API}/auth/login`, {
      method: 'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({email,password})
    });
    const j = await res.json();
    if(!res.ok){ loginMsg.textContent = j.message || 'Erro no login'; return; }
    // server tells us to verify 2FA
    tempToken = j.tempToken;
    loginSection.classList.add('hidden');
    twoFASection.classList.remove('hidden');
  }catch(err){
    loginMsg.textContent = 'Erro de rede';
  }
});

/* 2FA verify */
twoFAForm.addEventListener('submit', async (e)=>{
  e.preventDefault();
  twoFAMsg.textContent = '';
  const code = document.getElementById('totp').value;
  try{
    const res = await fetch(`${API}/auth/2fa-verify`, {
      method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({tempToken, code})
    });
    const j = await res.json();
    if(!res.ok){ twoFAMsg.textContent = j.message || 'Código inválido'; return; }
    setAuthToken(j.token);
    twoFASection.classList.add('hidden');
    showAdminPanel();
    loadProducts();
    loadLog();
  }catch(err){
    twoFAMsg.textContent = 'Erro de rede';
  }
});

/* Show admin panel */
function showAdminPanel(){
  adminPanel.classList.remove('hidden');
  loginSection.classList.add('hidden');
  twoFASection.classList.add('hidden');
}

/* Logout */
logoutBtn.addEventListener('click', ()=>{
  setAuthToken(null);
  adminPanel.classList.add('hidden');
  loginSection.classList.remove('hidden');
});

/* CRUD functions */
async function loadProducts(){
  try{
    const res = await fetch(`${API}/products`);
    const products = await res.json();
    renderTable(products);
    renderPreview(products);
  }catch(e){ console.error(e) }
}

function renderTable(products){
  prodTableBody.innerHTML = '';
  products.forEach(p=>{
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${escapeHtml(p.title)}</td>
      <td><img src="${p.image||'placeholder.png'}" alt="" style="height:40px;object-fit:cover;border-radius:4px"/></td>
      <td><a href="${p.link}" target="_blank">${p.link}</a></td>
      <td>
        <button class="btn" data-id="${p.id}" data-act="edit">Editar</button>
        <button class="btn" data-id="${p.id}" data-act="del">Excluir</button>
      </td>
    `;
    prodTableBody.appendChild(tr);
  });
}

function renderPreview(products){
  renderProducts(products, previewGrid);
}

/* Product form submit (create/update) with optional file upload */
prodForm.addEventListener('submit', async (e)=>{
  e.preventDefault();
  const id = document.getElementById('prod-id').value;
  const title = document.getElementById('prod-title').value;
  const imageUrl = document.getElementById('prod-image').value;
  const link = document.getElementById('prod-link').value;
  const file = document.getElementById('prod-file').files[0];

  const formData = new FormData();
  formData.append('title', title);
  formData.append('link', link);
  if(imageUrl) formData.append('image', imageUrl);
  if(file) formData.append('file', file);

  try{
    const opts = {
      method: id ? 'PUT' : 'POST',
      headers: {...getAuthHeader()},
      body: formData
    };
    const url = `${API}/products${id? '/' + id : ''}`;
    const res = await fetch(url, opts);
    const j = await res.json();
    if(!res.ok){ document.getElementById('prod-msg').textContent = j.message || 'Erro'; return; }
    document.getElementById('prod-msg').textContent = 'Salvo com sucesso';
    prodForm.reset();
    loadProducts();
    loadLog();
  }catch(err){
    document.getElementById('prod-msg').textContent = 'Erro de rede';
  }
});

/* Table buttons (edit/delete) */
prodTableBody.addEventListener('click', async (e)=>{
  const btn = e.target.closest('button');
  if(!btn) return;
  const id = btn.dataset.id;
  const act = btn.dataset.act;
  if(act === 'edit'){
    // load product and populate form
    const res = await fetch(`${API}/products/${id}`);
    const p = await res.json();
    document.getElementById('prod-id').value = p.id;
    document.getElementById('prod-title').value = p.title;
    document.getElementById('prod-image').value = p.image || '';
    document.getElementById('prod-link').value = p.link;
  } else if(act === 'del'){
    if(!confirm('Confirma exclusão do produto?')) return;
    const res = await fetch(`${API}/products/${id}`, { method:'DELETE', headers:{...getAuthHeader()} });
    const j = await res.json();
    if(!res.ok) return alert(j.message || 'Erro ao excluir');
    loadProducts();
    loadLog();
  }
});

/* Clear form */
document.getElementById('clear-prod').addEventListener('click', ()=>{
  prodForm.reset();
  document.getElementById('prod-id').value = '';
  document.getElementById('prod-msg').textContent = '';
});

/* Helper: render products for preview */
function renderProducts(products, container){
  container.innerHTML = '';
  products.forEach(p=>{
    const el = document.createElement('article');
    el.className = 'card product-card';
    el.innerHTML = `
      <img class="product-thumb" src="${p.image || 'placeholder.png'}" alt="${escapeHtml(p.title)}" />
      <div class="product-title">${escapeHtml(p.title)}</div>
      <div class="product-cta"><a class="btn" href="${p.link}" target="_blank">Ver</a></div>
    `;
    container.appendChild(el);
  });
}

/* Load audit log */
async function loadLog(){
  try{
    const res = await fetch(`${API}/admin/log`, { headers:{...getAuthHeader()} });
    const j = await res.json();
    auditLog.innerHTML = '';
    (j.logs || []).slice(0,50).forEach(l=>{
      const li = document.createElement('li');
      li.textContent = `${l.when} — ${l.action}`;
      auditLog.appendChild(li);
    });
  }catch(e){ console.error(e) }
}

/* utility */
function escapeHtml(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;') }
