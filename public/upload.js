// Client upload page: asks the proxy for a pre-signed POST, uploads straight to
// S3 with progress, then asks the proxy to verify the file. Falls back to
// streaming through the proxy if the browser cannot reach S3 directly.
(() => {
  const base = location.pathname.replace(/\/+$/, '');
  const $ = (id) => document.getElementById(id);
  const fmt = (n) => (n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1024))} KB`);
  let info = null;
  let running = Promise.resolve();

  if (document.body.dataset.state !== 'ok') {
    $('error').hidden = false;
    return;
  }
  $('uploader').hidden = false;

  function showError(message) {
    $('uploader').hidden = true;
    $('error-text').textContent = message;
    $('error').hidden = false;
  }

  async function loadInfo() {
    const res = await fetch(`${base}/info`, { cache: 'no-store' });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) return showError(body.message || 'This link is no longer valid.');
    info = body;
    $('limits').textContent = `${info.allowedTypes.map((t) => t.toUpperCase()).join(', ')} · up to ${fmt(info.maxFileBytes)} each · ${info.remainingFiles} file(s) left`;
    $('picker').accept = info.allowedTypes.map((t) => `.${t}${t === 'jpg' ? ',.jpeg' : ''}`).join(',');
    const done = $('done');
    done.textContent = '';
    // Successful uploads move to the "received" list; failures stay visible in the queue.
    for (const li of [...$('queue').querySelectorAll('.item.ok')]) li.remove();
    $('done-title').hidden = info.files.length === 0;
    for (const f of info.files) done.append(row(f.name, `Received · ${fmt(f.size)}`, 'ok', 100));
  }

  function row(name, status, cls, pct) {
    const li = document.createElement('li');
    li.className = `item ${cls || ''}`;
    li.innerHTML = '<div class="row"><span class="name"></span><span class="status"></span></div><div class="bar"><i></i></div>';
    li.querySelector('.name').textContent = name;
    li.querySelector('.status').textContent = status;
    li.querySelector('.bar i').style.width = `${pct || 0}%`;
    return li;
  }

  function set(li, status, cls, pct) {
    if (cls) li.className = `item ${cls}`;
    li.querySelector('.status').textContent = status;
    if (pct !== undefined) li.querySelector('.bar i').style.width = `${pct}%`;
  }

  function send(method, url, body, onProgress) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open(method, url);
      xhr.upload.onprogress = (e) => e.lengthComputable && onProgress && onProgress(e.loaded / e.total);
      xhr.onload = () => resolve({ status: xhr.status, text: xhr.responseText });
      xhr.onerror = () => reject(new Error('network'));
      xhr.send(body);
    });
  }

  const json = (text) => { try { return JSON.parse(text); } catch { return {}; } };
  const s3Message = (text) => (text.match(/<Message>([^<]+)<\/Message>/) || [])[1];

  async function uploadOne(file) {
    const li = row(file.name, 'Waiting…', '', 0);
    $('queue').prepend(li);
    if (info && file.size > info.maxFileBytes) return set(li, `Too large (max ${fmt(info.maxFileBytes)})`, 'bad');
    try {
      set(li, 'Preparing…');
      const pre = await fetch(`${base}/presign`, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ filename: file.name, contentType: file.type, size: file.size }),
      });
      const intent = await pre.json().catch(() => ({}));
      if (!pre.ok) return set(li, intent.message || 'Refused', 'bad');

      const form = new FormData();
      for (const [k, v] of Object.entries(intent.upload.fields)) form.append(k, v);
      form.append('file', file); // must be the last field
      let direct;
      try {
        direct = await send('POST', intent.upload.url, form, (p) => set(li, `Uploading ${Math.round(p * 100)}%`, '', p * 95));
      } catch {
        return await viaProxy(file, li); // S3 unreachable from this network
      }
      if (direct.status >= 300) return set(li, s3Message(direct.text) || `Upload failed (${direct.status})`, 'bad');

      set(li, 'Verifying…', '', 97);
      const done = await fetch(`${base}/complete/${encodeURIComponent(intent.fileId)}`, { method: 'POST' });
      const body = await done.json().catch(() => ({}));
      if (!done.ok) return set(li, body.message || 'Rejected', 'bad');
      set(li, `Received · ${fmt(body.file.size)}`, 'ok', 100);
    } catch (err) {
      set(li, 'Connection problem, please retry', 'bad');
    }
  }

  async function viaProxy(file, li) {
    set(li, 'Uploading (secure relay)…', '', 0);
    const form = new FormData();
    form.append('file', file);
    const r = await send('POST', `${base}/files`, form, (p) => set(li, `Uploading ${Math.round(p * 100)}%`, '', p * 95));
    const body = json(r.text);
    const res = body.results && body.results[0];
    if (res && res.ok) return set(li, `Received · ${fmt(res.file.size)}`, 'ok', 100);
    set(li, (res && res.message) || body.message || `Upload failed (${r.status})`, 'bad');
  }

  function enqueue(files) {
    for (const f of files) running = running.then(() => uploadOne(f));
    running = running.then(loadInfo);
  }

  $('picker').addEventListener('change', (e) => { enqueue([...e.target.files]); e.target.value = ''; });
  const drop = $('drop');
  drop.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); $('picker').click(); } });
  ['dragenter', 'dragover'].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add('over'); }));
  ['dragleave', 'drop'].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.remove('over'); }));
  drop.addEventListener('drop', (e) => enqueue([...e.dataTransfer.files]));
  loadInfo();
})();
