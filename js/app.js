/* ==========================================================
   سیسمونی نی‌نی ماه - منطق اصلی سایت
   - بدون هیچ inline-script (سازگار با CSP)
   - تمام خروجی‌ها با textContent / DOM ساخته می‌شوند (ضد XSS)
   - ورودی‌ها هنگام ذخیره و بازیابی پاک‌سازی و اعتبارسنجی می‌شوند
   ========================================================== */
(() => {
  'use strict';

  // جلوگیری از قرار گرفتن سایت داخل iframe (Clickjacking)
  if (window.top !== window.self) {
    document.body.replaceChildren();
    return;
  }

  const CFG = Object.assign({
    ADMIN_SESSION_MIN: 10, ADMIN_ABSOLUTE_MIN: 120, ADMIN_HIDE_LOCK_MIN: 5, PBKDF2_ITER: 600000, ADMIN_ROUTE: 'admin'
  }, window.NINIMAH_CONFIG || {});
  // حداقل‌ها را نگه می‌داریم تا یک تنظیم اشتباه در config.js امنیت را پایین نیاورد
  CFG.PBKDF2_ITER = Math.max(300000, Number(CFG.PBKDF2_ITER) || 600000);
  CFG.ADMIN_ROUTE = /^[A-Za-z0-9_-]{3,40}$/.test(CFG.ADMIN_ROUTE) ? CFG.ADMIN_ROUTE : 'admin';

  const KEYS = {
    data: 'ninimah:data:v2',
    admin: 'ninimah:admin:v4',
    audit: 'ninimah:admin-audit:v3',
    lock: 'ninimah:admin-lock:v2',
    session: 'ninimah:admin-session:v2'
  };
  const LOGO_FALLBACK = 'assets/favicon.png';
  const DEFAULT_LOGO = 'assets/logo.png';
  const FADE_DISTANCE = 140;
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const hasCrypto = !!(window.crypto && window.crypto.subtle);
  const enc = new TextEncoder();

  /* ---------------------------------------------------------
     ابزارهای عمومی
     --------------------------------------------------------- */
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const clamp = (n, a, b) => Math.min(b, Math.max(a, n));
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const uid = () => 'x' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);

  function h(tag, props = {}, ...kids) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
      if (v == null || v === false) continue;
      if (k === 'class') n.className = v;
      else if (k === 'text') n.textContent = v;
      else if (k === 'dataset') Object.assign(n.dataset, v);
      else n.setAttribute(k, v === true ? '' : String(v));
    }
    kids.flat().forEach(c => {
      if (c == null || c === false) return;
      n.append(c.nodeType ? c : document.createTextNode(String(c)));
    });
    return n;
  }

  const store = {
    get(k, fb) { try { const v = localStorage.getItem(k); return v == null ? fb : JSON.parse(v); } catch { return fb; } },
    set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); return true; } catch { return false; } },
    del(k) { try { localStorage.removeItem(k); } catch { /* ignore */ } }
  };
  const session = {
    get() { try { return JSON.parse(sessionStorage.getItem(KEYS.session)); } catch { return null; } },
    set(v) { try { sessionStorage.setItem(KEYS.session, JSON.stringify(v)); } catch { /* ignore */ } },
    del() { try { sessionStorage.removeItem(KEYS.session); } catch { /* ignore */ } }
  };

  const toEn = s => String(s)
    .replace(/[۰-۹]/g, d => '۰۱۲۳۴۵۶۷۸۹'.indexOf(d))
    .replace(/[٠-٩]/g, d => '٠١٢٣٤٥٦٧٨٩'.indexOf(d));
  const normFa = s => toEn(String(s)).toLowerCase().replace(/ي/g, 'ی').replace(/ك/g, 'ک');
  const str = (v, max = 200) => typeof v === 'string'
    ? v.replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max) : '';
  const num = v => {
    const d = toEn(String(v ?? '')).replace(/[^\d]/g, '');
    const n = Number(d.slice(0, 12));
    return Number.isFinite(n) ? n : 0;
  };
  const formatPrice = p => p > 0 ? `${p.toLocaleString('fa-IR')} تومان` : 'تماس بگیرید';
  const escXml = s => String(s).replace(/[<>&"']/g, c => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;' }[c]));

  /** فقط آدرس‌های امن: https، مسیر نسبی داخل پروژه، یا تصویر data: */
  function safeUrl(u) {
    if (typeof u !== 'string') return '';
    u = u.trim();
    if (!u || u.length > 4_000_000) return '';
    if (/^data:image\/(png|jpe?g|webp|gif);base64,[a-z0-9+/=]+$/i.test(u)) return u;
    // تصاویر SVG تولیدشده توسط خود سایت (placeholder)؛ داخل <img> هیچ اسکریپتی اجرا نمی‌شود
    if (/^data:image\/svg\+xml;charset=utf-8,[A-Za-z0-9%_.~!*'()-]+$/.test(u)) return u;
    if (/^https:\/\//i.test(u) && u.length < 2048) { try { new URL(u); return u; } catch { return ''; } }
    if (/^(?!\/\/)[\w\-./]+\.(png|jpe?g|webp|gif|svg)$/i.test(u) && !u.includes('..')) return u;
    return '';
  }

  function placeholder(emoji, label, hue = 205) {
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 600 450"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="hsl(${hue} 100% 90%)"/><stop offset="1" stop-color="hsl(${hue + 12} 95% 70%)"/></linearGradient></defs><rect width="600" height="450" fill="url(#g)"/><circle cx="470" cy="105" r="52" fill="#fff" opacity=".6"/><text x="300" y="255" font-size="120" text-anchor="middle">${escXml(emoji)}</text><text x="300" y="360" font-size="28" font-family="Tahoma,sans-serif" text-anchor="middle" fill="#0757b8">${escXml(label)}</text></svg>`;
    return 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svg);
  }

  function withFallback(img, fallback) {
    img.addEventListener('error', () => {
      if (img.dataset.fb) return;
      img.dataset.fb = '1';
      img.src = typeof fallback === 'function' ? fallback() : fallback;
    });
    return img;
  }

  /* ---------------------------------------------------------
     داده‌ها: مقدار پیش‌فرض + پاک‌سازی
     --------------------------------------------------------- */
  const DEFAULT_SETTINGS = {
    siteName: 'سیسمونی نی‌نی ماه',
    slogan: 'دنیای آرامش و زیبایی برای فرشته کوچک شما',
    heroBadge: '✨ کامل‌ترین مجموعه سیسمونی نوزاد',
    heroTitle: 'هر آنچه برای شروع یک',
    heroHighlight: 'زندگی شیرین نیاز دارید',
    heroText: 'از پوشاک ضدحساسیت پنبه ارگانیک تا سرویس خواب، لوازم بهداشتی استاندارد و اسباب‌بازی‌های فکری؛ با عشق در کنار شما هستیم.',
    aboutTitle: 'همراه مطمئن والدین خوش‌سلیقه',
    aboutText: 'فروشگاه سیسمونی نی‌نی ماه با هدف ارائه باکیفیت‌ترین و ایمن‌ترین محصولات نوزاد و کودک راه‌اندازی شده است. ما در انتخاب تک‌تک کالاها، لطافت پوست نوزاد، ارگونومی استاندارد و طراحی دلنشین را در اولویت قرار می‌دهیم.',
    hours: 'پشتیبانی همه‌روزه از ساعت ۹ الی ۲۱',
    phone: '', whatsapp: '', instagram: '', telegram: '', address: '',
    logo: DEFAULT_LOGO
  };
  const OPTIONAL = new Set(['phone', 'whatsapp', 'instagram', 'telegram', 'address']);
  const LONG = new Set(['heroText', 'aboutText', 'address']);

  function cleanSetting(k, raw, def) {
    if (k === 'logo') return safeUrl(raw) || def;
    const s = typeof raw === 'string' ? raw : '';
    if (k === 'phone') { const v = str(toEn(s), 20); return /^[\d+\s-]{0,20}$/.test(v) ? v : ''; }
    if (k === 'whatsapp') {
      let d = toEn(s).replace(/\D/g, '');
      if (d.startsWith('0')) d = '98' + d.slice(1);
      return /^\d{8,15}$/.test(d) ? d : '';
    }
    if (k === 'instagram' || k === 'telegram') {
      const v = str(s, 80).replace(/^https?:\/\/(www\.)?(instagram\.com|t\.me)\//i, '').replace(/^@/, '').replace(/\/.*$/, '');
      return /^[A-Za-z0-9._]{1,40}$/.test(v) ? v : '';
    }
    const v = str(s, LONG.has(k) ? 500 : 150);
    return v || (OPTIONAL.has(k) ? '' : def);
  }

  const DEFAULT_CATS = [
    { id: 'clothes', name: 'پوشاک', icon: '👕' },
    { id: 'bed', name: 'تخت و کمد', icon: '🛏️' },
    { id: 'hygiene', name: 'بهداشتی', icon: '🛁' },
    { id: 'toys', name: 'اسباب بازی و اکسسوری', icon: '🧸' }
  ];
  const P = (id, cat, name, price, desc) => ({ id, cat, name, price, desc, img: '' });
  const DEFAULT_PRODUCTS = [
    P('p1', 'clothes', 'ست ۵ تکه بیمارستانی نوزاد طرح ماه', 980000, 'پنبه ارگانیک ۱۰۰٪ ضدحساسیت، مناسب بدو تولد'),
    P('p2', 'clothes', 'سرهمی نخی دکمه‌دار آسمانی', 540000, 'طراحی راحت برای تعویض پوشک با پارچه تنفس‌پذیر'),
    P('p3', 'clothes', 'بادی آستین کوتاه بسته ۳ عددی', 620000, 'دوخت ظریف بدون برچسب آزاردهنده داخلی'),
    P('p4', 'clothes', 'ست کلاه، دستکش و پاپوش نوزاد', 310000, 'بافت نرم و گرم، مناسب هوای سرد'),
    P('p5', 'clothes', 'سرهمی زمستانی پلار کلاه‌دار', 1150000, 'آستر پنبه‌ای و رویه پلار نرم'),
    P('p6', 'bed', 'تخت کنار مادر قابل تنظیم مدل رویا', 6800000, 'توری ضدحشره، حالت گهواره و تنظیم ارتفاع'),
    P('p7', 'bed', 'سرویس کامل تخت و کمد کودک مدل ابر', 24500000, 'چوب راش و MDF با رنگ پلی‌اورتان غیرسمی'),
    P('p8', 'bed', 'تشک طبی ضدرفلاکس نوزاد', 1450000, 'فوم هوشمند حافظه‌دار با روکش قابل شست‌وشو'),
    P('p9', 'bed', 'کمد ۴ کشو کودک مدل ستاره', 8900000, 'ریل‌های بی‌صدا و لبه‌های گرد ایمن'),
    P('p10', 'bed', 'ست ۷ تکه روتختی و محافظ تخت', 2100000, 'پنبه ۱۰۰٪ با طرح ماه و ستاره'),
    P('p11', 'hygiene', 'پک کامل حمام و مراقبت پوست نوزاد', 1290000, 'شامپو سر و بدن، لوسیون مرطوب‌کننده و کرم سوختگی'),
    P('p12', 'hygiene', 'وان حمام تاشو دماسنج‌دار نوزاد', 1750000, 'تشک توری نگهدارنده و نمایشگر دمای آب'),
    P('p13', 'hygiene', 'ست مانیکور و برس موی طبیعی کودک', 390000, 'قیچی سرگرد ایمن و برس الیاف طبیعی'),
    P('p14', 'hygiene', 'دستمال مرطوب بدون الکل بسته ۶ عددی', 480000, 'ضدحساسیت با عصاره آلوئه‌ورا'),
    P('p15', 'hygiene', 'ست شیشه شیر ضدکولیک و استریل‌کننده', 690000, 'سرشیشه سیلیکونی نرم و بدون BPA'),
    P('p16', 'toys', 'آویز موزیکال بالای تخت طرح ماه و ستاره', 1120000, 'لالایی ملایم با چرخش آرام و نور شب‌تاب'),
    P('p17', 'toys', 'تشک بازی جغجغه‌دار آموزشی', 1680000, 'تقویت حس بینایی، لامسه و مهارت‌های حرکتی'),
    P('p18', 'toys', 'کوله‌پشتی لوازم نوزاد ضدآب', 1490000, 'محفظه عایق حرارتی شیشه شیر و زیرانداز تعویض'),
    P('p19', 'toys', 'جغجغه و دندان‌گیر سیلیکونی', 260000, 'سیلیکون فوودگرید، مناسب دوران دندان‌درآوردن'),
    P('p20', 'toys', 'عروسک پولیشی خرگوش و ماه', 450000, 'نرم و قابل شست‌وشو، مناسب هدیه تولد')
  ];

  function defaults() {
    return {
      settings: { ...DEFAULT_SETTINGS },
      categories: DEFAULT_CATS.map(c => ({ ...c })),
      products: DEFAULT_PRODUCTS.map(p => ({ ...p })),
      slides: [
        { img: placeholder('👗', '', 205), caption: 'تنوع بی‌نظیر پوشاک نخی و ضدحساسیت نوزاد' },
        { img: placeholder('🛏️', '', 215), caption: 'طراحی آرامش‌بخش اتاق کودک با سرویس‌های استاندارد' },
        { img: placeholder('🧸', '', 195), caption: 'مشاوره تخصصی برای انتخاب بهترین سیسمونی' }
      ],
      // اسلایدر بنر بالای صفحه؛ fit: cover = پر کردن کادر (با برش)، contain = نمایش کامل بدون برش
      heroSlides: [
        { img: DEFAULT_LOGO, caption: 'کیفیت تضمین‌شده • ارسال به سراسر کشور', fit: 'contain' },
        { img: placeholder('🧸', 'اسباب‌بازی و اکسسوری ایمن', 198), caption: 'اسباب‌بازی و اکسسوری ایمن برای کودک شما', fit: 'cover' },
        { img: placeholder('🛏️', 'سرویس خواب کامل', 210), caption: 'سرویس خواب و کمد با متریال استاندارد', fit: 'cover' }
      ]
    };
  }

  /** هر داده‌ای که از localStorage یا فایل پشتیبان وارد شود از این فیلتر می‌گذرد */
  function sanitizeData(raw) {
    const d = defaults();
    if (!raw || typeof raw !== 'object') return d;
    if (!Array.isArray(raw.categories) || !Array.isArray(raw.products) || !Array.isArray(raw.slides)) return d;

    const out = { settings: {}, categories: [], products: [], slides: [], heroSlides: [] };
    const rs = raw.settings && typeof raw.settings === 'object' ? raw.settings : {};
    for (const k of Object.keys(DEFAULT_SETTINGS)) out.settings[k] = cleanSetting(k, rs[k], DEFAULT_SETTINGS[k]);

    const ids = new Set();
    for (const c of raw.categories.slice(0, 40)) {
      if (!c || typeof c !== 'object') continue;
      let id = str(c.id, 40);
      if (!/^[\w-]+$/.test(id) || ids.has(id)) id = uid();
      const name = str(c.name, 60);
      if (!name) continue;
      ids.add(id);
      out.categories.push({ id, name, icon: str(c.icon, 4) || '🍼' });
    }
    const pids = new Set();
    for (const p of raw.products.slice(0, 500)) {
      if (!p || typeof p !== 'object') continue;
      const cat = str(p.cat, 40);
      const name = str(p.name, 120);
      if (!name || !ids.has(cat)) continue;
      let id = str(p.id, 40);
      if (!/^[\w-]+$/.test(id) || pids.has(id)) id = uid();
      pids.add(id);
      out.products.push({ id, cat, name, price: num(p.price), desc: str(p.desc, 300), img: safeUrl(p.img) });
    }
    for (const s of raw.slides.slice(0, 30)) {
      if (!s || typeof s !== 'object') continue;
      const img = safeUrl(s.img);
      if (img) out.slides.push({ img, caption: str(s.caption, 150) });
    }
    if (Array.isArray(raw.heroSlides)) {
      for (const s of raw.heroSlides.slice(0, 10)) {
        if (!s || typeof s !== 'object') continue;
        const img = safeUrl(s.img);
        if (img) out.heroSlides.push({ img, caption: str(s.caption, 150), fit: s.fit === 'contain' ? 'contain' : 'cover' });
      }
    } else {
      out.heroSlides = d.heroSlides;
    }
    return out;
  }

  // data = آنچه الان نمایش داده می‌شود؛ published = نسخهٔ منتشرشده در data/site.json
  // KEYS.data فقط «پیش‌نویس» مدیر است (در مرورگر خود او) و برای بازدیدکنندگان وجود ندارد
  let data = defaults();
  let published = null;
  const hasDraft = () => store.get(KEYS.data, null) != null;

  async function loadPublished() {
    try {
      const r = await fetch('data/site.json', { cache: 'no-cache' });
      if (!r.ok) return null;
      const j = await r.json();
      const raw = j && j.data ? j.data : j;
      if (!raw || !Array.isArray(raw.categories) || !Array.isArray(raw.products) || !Array.isArray(raw.slides)) return null;
      return sanitizeData(raw);
    } catch { return null; }
  }

  /** تغییر داده با امکان بازگشت در صورت پر بودن حافظه مرورگر */
  function mutate(fn) {
    const backup = JSON.parse(JSON.stringify(data));
    fn();
    if (!store.set(KEYS.data, data)) {
      data = backup;
      toast('حافظه مرورگر پر است. تصاویر کوچک‌تر انتخاب کنید یا به‌جای آپلود، لینک https بدهید.', 'danger');
      return false;
    }
    renderPublic();
    renderAdmin();
    return true;
  }

  /* ---------------------------------------------------------
     Toast و مودال
     --------------------------------------------------------- */
  function toast(text, type = 'info', ms = 4200) {
    const t = h('div', { class: `toast toast-${type}`, role: 'status', text });
    $('#toasts').append(t);
    setTimeout(() => t.remove(), ms);
  }

  function setMsg(id, text, type = 'info') {
    const el = $('#' + id);
    if (!el) return;
    if (!text) { el.hidden = true; el.textContent = ''; return; }
    el.className = `alert alert-${type}`;
    el.textContent = text;
    el.hidden = false;
  }

  let lastFocus = null;
  function setView(modalId, name) {
    $$('[data-view]', $('#' + modalId)).forEach(v => { v.hidden = v.dataset.view !== name; });
  }
  function openModal(id) {
    const m = $('#' + id);
    lastFocus = document.activeElement;
    m.classList.add('open');
    m.setAttribute('aria-hidden', 'false');
    document.body.classList.add('no-scroll');
    setTimeout(() => {
      const f = $$('input:not([type=hidden]):not([type=file]), select, textarea', m).find(el => el.offsetParent !== null);
      if (f) f.focus();
    }, 30);
  }
  function closeModal(id) {
    const m = $('#' + id);
    m.classList.remove('open');
    m.setAttribute('aria-hidden', 'true');
    if (id === 'adminModal') {
      $$('#adminModal input[type=password]').forEach(i => { i.value = ''; });
      const show = $('#adminShowPass');
      if (show) { show.checked = false; $('#adminPass').type = 'password'; }
    }
    if (!$('.modal.open')) document.body.classList.remove('no-scroll');
    if (lastFocus && lastFocus.focus) lastFocus.focus();
  }

  /* ---------------------------------------------------------
     نمایش عمومی سایت
     --------------------------------------------------------- */
  let activeCat = 'all';
  const catById = id => data.categories.find(c => c.id === id);
  const catHue = id => 195 + (Math.max(0, data.categories.findIndex(c => c.id === id)) * 9) % 40;

  function productImage(p) {
    const c = catById(p.cat);
    return p.img || placeholder(c ? c.icon : '🍼', p.name.slice(0, 26), catHue(p.cat));
  }

  function contactHref(p) {
    const s = data.settings;
    const msg = `سلام، درباره «${p.name}» می‌خواستم اطلاعات بگیرم.`;
    if (s.whatsapp) return `https://wa.me/${s.whatsapp}?text=${encodeURIComponent(msg)}`;
    if (s.phone) return `tel:${s.phone.replace(/[^\d+]/g, '')}`;
    return '';
  }

  function renderBrand() {
    const s = data.settings;
    document.title = `${s.siteName} | فروشگاه تخصصی نوزاد و کودک`;
    $('#brandName').textContent = s.siteName;
    $('#brandSlogan').textContent = s.slogan;
    $('#heroBadge').textContent = s.heroBadge;
    $('#heroTitle').textContent = s.heroTitle;
    $('#heroHighlight').textContent = s.heroHighlight;
    $('#heroText').textContent = s.heroText;
    $('#aboutTitle').textContent = s.aboutTitle;
    $('#aboutText').textContent = s.aboutText;
    $('#footName').textContent = s.siteName;
    const logo = $('#siteLogo');
    logo.dataset.fb = '';
    logo.src = safeUrl(s.logo) || LOGO_FALLBACK;
    const li = (...kids) => h('li', {}, ...kids);
    const items = [];
    if (s.phone) items.push(li(h('a', { href: `tel:${s.phone.replace(/[^\d+]/g, '')}`, dir: 'ltr', text: `📞 ${s.phone}` })));
    if (s.whatsapp) items.push(li(h('a', { href: `https://wa.me/${s.whatsapp}`, target: '_blank', rel: 'noopener noreferrer', text: '💬 واتساپ' })));
    if (s.instagram) items.push(li(h('a', { href: `https://instagram.com/${s.instagram}`, target: '_blank', rel: 'noopener noreferrer', text: `📷 اینستاگرام: ${s.instagram}` })));
    if (s.telegram) items.push(li(h('a', { href: `https://t.me/${s.telegram}`, target: '_blank', rel: 'noopener noreferrer', text: `✈️ تلگرام: ${s.telegram}` })));
    if (s.address) items.push(li(`📍 ${s.address}`));
    if (s.hours) items.push(li(`🕘 ${s.hours}`));
    $('#footContact').replaceChildren(...items);
  }

  function renderTabs() {
    if (activeCat !== 'all' && !catById(activeCat)) activeCat = 'all';
    const mk = (id, label) => h('button', {
      class: 'cat-btn' + (activeCat === id ? ' active' : ''), type: 'button', role: 'tab',
      'aria-selected': String(activeCat === id), dataset: { action: 'cat', cat: id }, text: label
    });
    $('#categoryTabs').replaceChildren(
      mk('all', 'همه'),
      ...data.categories.map(c => mk(c.id, `${c.icon} ${c.name}`))
    );
  }

  // برای شلوغ نشدن صفحه، فقط چند محصول اول نشان داده می‌شود و بقیه با «نمایش بیشتر» می‌آید
  const pageSize = () => window.matchMedia('(max-width: 600px)').matches ? 6 : 8;
  let shown = pageSize();
  /** در تب «همه»، محصولات دسته‌ها به‌نوبت می‌آیند تا همهٔ دسته‌ها در همان چند مورد اول دیده شوند */
  function interleave(list) {
    const groups = data.categories.map(c => list.filter(p => p.cat === c.id)).filter(g => g.length);
    const out = [];
    for (let i = 0; out.length < list.length; i++) for (const g of groups) if (i < g.length) out.push(g[i]);
    return out;
  }

  function renderProducts() {
    const q = normFa($('#searchInput').value.trim());
    let list = data.products.filter(p =>
      (activeCat === 'all' || p.cat === activeCat) &&
      (!q || normFa(p.name).includes(q) || normFa(p.desc).includes(q)));
    if (activeCat === 'all' && !q) list = interleave(list);
    const grid = $('#productsGrid'), more = $('#moreWrap');
    if (!list.length) { grid.replaceChildren(h('p', { class: 'empty', text: 'محصولی با این مشخصات یافت نشد.' })); more.hidden = true; return; }

    const rest = list.length - shown;
    more.hidden = rest <= 0;
    if (rest > 0) more.replaceChildren(h('button', { class: 'btn btn-soft', type: 'button', dataset: { action: 'more' }, text: `نمایش بیشتر (${rest.toLocaleString('fa-IR')} محصول دیگر)` }));

    grid.replaceChildren(...list.slice(0, shown).map(p => {
      const c = catById(p.cat);
      const href = contactHref(p);
      const img = withFallback(h('img', { src: productImage(p), alt: p.name, loading: 'lazy', decoding: 'async' }),
        () => placeholder(c ? c.icon : '🍼', '', catHue(p.cat)));
      const action = href
        ? h('a', { class: 'btn btn-soft btn-sm', href, target: href.startsWith('http') ? '_blank' : null, rel: 'noopener noreferrer', text: 'استعلام / سفارش' })
        : h('button', { class: 'btn btn-soft btn-sm', type: 'button', dataset: { action: 'no-contact' }, text: 'استعلام / سفارش' });
      return h('article', { class: 'product-card fx' },
        h('div', { class: 'product-img' }, h('span', { class: 'product-tag', text: c ? c.name : '' }), img),
        h('div', { class: 'product-body' },
          h('div', {}, h('h4', { class: 'product-title', text: p.name }), h('p', { class: 'product-desc', text: p.desc })),
          h('div', { class: 'product-footer' }, h('span', { class: 'product-price', text: formatPrice(p.price) }), action)));
    }));
    updateFade();
  }

  /* ---------- اسلایدرها (بنر بالای صفحه + درباره ما) ---------- */
  function makeSlider({ root, track, dots, slides, alt, ms }) {
    const $root = $('#' + root), $track = $('#' + track), $dots = $('#' + dots);
    let idx = 0, hover = false, timer = null;

    function update() {
      // کانتینر RTL است: اسلاید بعدی سمت چپ قرار دارد، پس track به راست می‌رود
      $track.style.transform = `translateX(${idx * 100}%)`;
      $$('.dot', $dots).forEach((d, i) => d.classList.toggle('active', i === idx));
    }
    function render() {
      const items = slides(), n = items.length;
      $root.hidden = n === 0;
      if (idx >= n) idx = 0;
      $track.replaceChildren(...items.map(s => h('div', { class: 'slide' + (s.fit === 'contain' ? ' contain' : '') },
        withFallback(h('img', { src: s.img, alt: s.caption || alt, loading: 'lazy' }), () => placeholder('🍼', '', 205)),
        s.caption ? h('div', { class: 'slide-caption', text: s.caption }) : null)));
      $dots.replaceChildren(...items.map((_, i) =>
        h('button', { class: 'dot', type: 'button', 'aria-label': `اسلاید ${i + 1}`, dataset: { action: 'slide-go', slider: root, i } })));
      $$('.slider-btn', $root).forEach(b => { b.hidden = n < 2; });
      update();
    }
    function move(step) {
      const n = slides().length;
      if (n < 2) return;
      idx = (idx + step + n) % n;
      update();
    }
    function go(i) { idx = clamp(i, 0, Math.max(0, slides().length - 1)); update(); }
    function start() {
      clearInterval(timer);
      if (reduceMotion) return;
      timer = setInterval(() => { if (!hover && !document.hidden) move(1); }, ms);
    }
    $root.addEventListener('mouseenter', () => { hover = true; });
    $root.addEventListener('mouseleave', () => { hover = false; });
    $root.addEventListener('focusin', () => { hover = true; });
    $root.addEventListener('focusout', () => { hover = false; });
    let x0 = null;
    $root.addEventListener('pointerdown', e => { x0 = e.clientX; });
    $root.addEventListener('pointerup', e => {
      if (x0 == null) return;
      const dx = e.clientX - x0;
      x0 = null;
      if (Math.abs(dx) > 40) move(dx > 0 ? 1 : -1);
    });
    $root.addEventListener('pointercancel', () => { x0 = null; });
    return { render, move, go, start };
  }

  /** عکس اول بنر همان لوگوی فعلی سایت است (اگر لوگو را در پنل عوض کنید، اینجا هم عوض می‌شود) */
  const heroSrc = s => (s.img === DEFAULT_LOGO ? (safeUrl(data.settings.logo) || DEFAULT_LOGO) : s.img);
  const sliders = {
    heroSlider: makeSlider({ root: 'heroSlider', track: 'heroTrack', dots: 'heroDots', alt: 'تصویر بنر', ms: 5000,
      slides: () => data.heroSlides.map(s => ({ ...s, img: heroSrc(s) })) }),
    aboutSlider: makeSlider({ root: 'aboutSlider', track: 'slidesTrack', dots: 'sliderDots', alt: 'تصویر فروشگاه', ms: 4500,
      slides: () => data.slides })
  };

  function renderPublic() {
    renderBrand();
    renderTabs();
    renderProducts();
    Object.values(sliders).forEach(s => s.render());
  }

  /* ---------------------------------------------------------
     افکت محو شدن عناصر هنگام رفتن به زیر هدر
     --------------------------------------------------------- */
  let ticking = false;
  function updateFade() {
    const header = $('#mainHeader');
    header.classList.toggle('scrolled', window.scrollY > 30);
    if (reduceMotion) return;
    const hb = header.getBoundingClientRect().bottom;
    for (const el of $$('.fx')) {
      const r = el.getBoundingClientRect();
      const o = clamp((r.bottom - hb) / FADE_DISTANCE, 0, 1);
      const v = o >= 0.995 ? '' : o.toFixed(2);
      if (el.style.opacity !== v) el.style.opacity = v;
    }
  }
  function onScroll() {
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(() => { ticking = false; updateFade(); });
  }

  /* ---------------------------------------------------------
     رمزنگاری
     --------------------------------------------------------- */
  const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const randBytes = n => crypto.getRandomValues(new Uint8Array(n));
  function safeEqual(a, b) {
    if (a.length !== b.length) return false;
    let r = 0;
    for (let i = 0; i < a.length; i++) r |= a[i] ^ b[i];
    return r === 0;
  }
  function randomChars(set, n) {
    const lim = 256 - (256 % set.length);
    let out = '';
    while (out.length < n) for (const b of randBytes(n * 2)) if (b < lim && out.length < n) out += set[b % set.length];
    return out;
  }

  /* ---------- سیاست نام کاربری و رمز ----------
     چون فایل ورود (data/admin.json) روی گیت‌هاب عمومی است، رمز باید بلند و تصادفی‌مانند باشد. */
  const COMMON = ['password', 'admin', 'qwerty', 'letmein', 'welcome', 'iloveyou', 'ninimah', 'sisimooni', '123456', '111111', 'abc123'];
  function usernameProblem(u) {
    if (!/^[A-Za-z0-9_.-]{6,30}$/.test(u)) return 'نام کاربری باید ۶ تا ۳۰ کاراکتر انگلیسی، عدد یا _ . - باشد.';
    if (/^(admin|administrator|root|user|test|manager|owner|webmaster)/i.test(u)) return 'نام کاربری مثل «admin» قابل حدس است؛ یک نام یکتا انتخاب کنید.';
    return '';
  }
  function passwordProblem(pass, user) {
    if (pass.length < 14) return 'رمز عبور باید حداقل ۱۴ کاراکتر باشد (دکمهٔ «ساخت رمز قوی تصادفی» را بزنید).';
    if (!/[a-z]/.test(pass) || !/[A-Z]/.test(pass) || !/\d/.test(pass) || !/[^A-Za-z0-9]/.test(pass)) return 'رمز باید شامل حرف کوچک، حرف بزرگ، عدد و نماد (مثل !@#) باشد.';
    const low = pass.toLowerCase();
    if (COMMON.some(w => low.includes(w))) return 'رمز شامل کلمات رایج و قابل حدس است.';
    if (user && low.includes(user.toLowerCase())) return 'رمز عبور نباید شامل نام کاربری باشد.';
    if (/(.)\1{3,}/.test(pass)) return 'تکرار پشت‌سرهم یک کاراکتر مجاز نیست.';
    if (/(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|qwer|asdf|zxcv)/i.test(pass)) return 'الگوهای پشت‌سرهم (مثل 1234 یا qwer) مجاز نیست.';
    return '';
  }
  function generatePassword() {
    const set = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+';
    let p;
    do { p = randomChars(set, 20); } while (passwordProblem(p, ''));
    return p;
  }

  /* ---------- حساب مدیر (مشترک بین همهٔ دستگاه‌ها) ----------
     نه نام کاربری و نه رمز ذخیره نمی‌شوند؛ فقط «اثر انگشت» PBKDF2-SHA256 از ترکیب «نام کاربری + رمز»
     با Salt تصادفی و ۶۰۰٬۰۰۰ تکرار. این رکورد در data/admin.json (داخل بستهٔ انتشار) می‌آید
     تا از هر مرورگر و دستگاهی با همان نام کاربری و رمز بتوان وارد شد. */
  async function deriveHash(user, pass, salt, iterations) {
    const material = `${user.normalize('NFKC')}\u0000${pass.normalize('NFKC')}`;
    const key = await crypto.subtle.importKey('raw', enc.encode(material), 'PBKDF2', false, ['deriveBits']);
    return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256));
  }
  async function makeRecord(user, pass) {
    const salt = randBytes(16);
    return { v: 4, iter: CFG.PBKDF2_ITER, salt: b64(salt), hash: b64(await deriveHash(user, pass, salt, CFG.PBKDF2_ITER)) };
  }
  const validRec = r => !!(r && r.v === 4 && Number.isInteger(r.iter) && r.iter >= 100000 && r.iter <= 3000000 &&
    typeof r.salt === 'string' && typeof r.hash === 'string' && r.salt.length < 100 && r.hash.length < 100);
  async function recMatches(rec, user, pass) {
    try { return safeEqual(await deriveHash(user, pass, unb64(rec.salt), rec.iter), unb64(rec.hash)); } catch { return false; }
  }

  const adminState = { remote: undefined }; // undefined = هنوز معلوم نیست، null = فایل منتشر نشده، object = رکورد منتشرشده
  const localRec = () => { const r = store.get(KEYS.admin, null); return validRec(r) ? r : null; };
  async function loadRemoteAdmin() {
    try {
      const r = await fetch('data/admin.json', { cache: 'no-cache' });
      if (r.status === 404) return null;
      if (!r.ok) return undefined;
      const j = await r.json();
      const rec = j && (j.admin || j);
      return validRec(rec) ? { v: rec.v, iter: rec.iter, salt: rec.salt, hash: rec.hash } : null;
    } catch { return undefined; } // خطای شبکه با «وجود ندارد» فرق دارد
  }
  async function refreshRemoteAdmin() {
    const r = await loadRemoteAdmin();
    if (r !== undefined) adminState.remote = r;
  }
  /** نام کاربری و رمز با رکورد منتشرشده یا رکورد همین دستگاه سنجیده می‌شود (همهٔ رکوردها همیشه بررسی می‌شوند) */
  async function checkCreds(user, pass) {
    let ok = false;
    for (const rec of [adminState.remote, localRec()].filter(validRec)) ok = (await recMatches(rec, user, pass)) || ok;
    return ok;
  }

  /* ---------------------------------------------------------
     مدیر: نشست و ورود
     --------------------------------------------------------- */
  const audit = {
    get() { return store.get(KEYS.audit, { lastOk: 0, failsBefore: 0, fails: 0 }); },
    set(v) { store.set(KEYS.audit, v); }
  };
  const sessionValid = () => { const s = session.get(); return !!(s && s.t && s.exp > Date.now() && s.abs > Date.now()); };
  function startSession() {
    const now = Date.now();
    session.set({ t: b64(randBytes(16)), exp: now + CFG.ADMIN_SESSION_MIN * 60000, abs: now + CFG.ADMIN_ABSOLUTE_MIN * 60000 });
  }
  function touchSession() {
    const s = session.get();
    if (!sessionValid()) return;
    s.exp = Math.min(Date.now() + CFG.ADMIN_SESSION_MIN * 60000, s.abs);
    session.set(s);
  }
  function adminOk() {
    if (sessionValid()) { touchSession(); return true; }
    if ($('#adminModal').classList.contains('open')) { showAdminView(); toast('نشست شما منقضی شد. دوباره وارد شوید.', 'danger'); }
    return false;
  }

  function showAdminView() {
    const has = !!(validRec(adminState.remote) || localRec());
    const v = !has ? 'setup' : sessionValid() ? 'dash' : 'login';
    setView('adminModal', v);
    $('#adminCard').classList.toggle('wide', v === 'dash');
    setMsg('adminMsg', '');
    if (v === 'dash') { renderAdmin(); fillSettingsForm(); }
  }
  async function openAdmin() {
    if (!hasCrypto) { toast('مرورگر شما از رمزنگاری پشتیبانی نمی‌کند؛ سایت باید روی https یا localhost باز شود.', 'danger'); return; }
    await refreshRemoteAdmin();
    if (adminState.remote === undefined && !localRec()) {
      toast('اتصال به اینترنت برقرار نیست و فایل ورود مدیر خوانده نشد. چند لحظه بعد دوباره تلاش کنید.', 'danger', 7000);
      return;
    }
    showAdminView();
    openModal('adminModal');
  }

  /** راه‌اندازی اولیه: ساخت نام کاربری و رمز (فقط وقتی هنوز هیچ حسابی منتشر نشده) */
  async function adminSetup() {
    if (!hasCrypto) return;
    const user = str($('#setupUser').value, 30);
    const p1 = $('#setupPass').value, p2 = $('#setupPass2').value;
    const prob = usernameProblem(user) || passwordProblem(p1, user);
    if (prob) return setMsg('adminMsg', prob, 'danger');
    if (p1 !== p2) return setMsg('adminMsg', 'رمز و تکرار آن یکسان نیستند.', 'danger');
    const btn = $('#adminSetupForm button[type=submit]');
    btn.disabled = true;
    try {
      const rec = await makeRecord(user, p1);
      if (!store.set(KEYS.admin, rec)) return setMsg('adminMsg', 'ذخیره‌سازی ممکن نشد.', 'danger');
      $('#setupPass').value = ''; $('#setupPass2').value = '';
      audit.set({ lastOk: Date.now(), failsBefore: 0, fails: 0 });
      startSession();
      showAdminView();
      switchTab('security');
      toast('حساب مدیر ساخته شد. برای ورود از دستگاه‌های دیگر، یک بار «بستهٔ انتشار» را در گیت‌هاب آپلود کنید.', 'success', 10000);
    } finally { btn.disabled = false; }
  }

  async function adminLogin() {
    if (!hasCrypto) return;
    const lock = store.get(KEYS.lock, { fails: 0, until: 0 });
    if (Date.now() < lock.until) {
      const sec = Math.ceil((lock.until - Date.now()) / 1000);
      return setMsg('adminMsg', `به دلیل تلاش‌های ناموفق، ورود ${sec.toLocaleString('fa-IR')} ثانیه قفل است.`, 'danger');
    }
    const btn = $('#adminLoginBtn');
    btn.disabled = true;
    const t0 = Date.now();
    try {
      await refreshRemoteAdmin();
      const user = str($('#adminUser').value, 30);
      const pass = $('#adminPass').value;
      const ok = !!(user && pass) && await checkCreds(user, pass);
      // زمان پاسخ را یکنواخت می‌کنیم تا از روی سرعت، بخش نادرست قابل تشخیص نباشد
      await sleep(Math.max(0, 900 - (Date.now() - t0)) + Math.random() * 250);
      const a = audit.get();
      $('#adminPass').value = '';
      if (ok) {
        store.del(KEYS.lock);
        audit.set({ lastOk: Date.now(), failsBefore: a.fails || 0, fails: 0 });
        $('#adminUser').value = '';
        startSession();
        showAdminView();
        if (a.fails) toast(`⚠️ ${a.fails.toLocaleString('fa-IR')} تلاش ناموفق برای ورود قبل از این ورود ثبت شده بود.`, 'danger', 9000);
      } else {
        audit.set({ ...a, fails: (a.fails || 0) + 1 });
        lock.fails = (lock.fails || 0) + 1;
        let text = `نام کاربری یا رمز عبور اشتباه است. (${(lock.fails % 3 || 3).toLocaleString('fa-IR')} از ۳)`;
        if (lock.fails % 3 === 0) {
          const sec = Math.min(3600, 60 * Math.pow(2, lock.fails / 3 - 1));
          lock.until = Date.now() + sec * 1000;
          text = `۳ بار ورود ناموفق! دسترسی به مدت ${sec.toLocaleString('fa-IR')} ثانیه مسدود شد.`;
        }
        store.set(KEYS.lock, lock);
        setMsg('adminMsg', text, 'danger');
      }
    } finally { btn.disabled = false; }
  }
  function adminLogout() {
    session.del();
    closeModal('adminModal');
    toast('با موفقیت خارج شدید.');
  }

  async function changeCredentials() {
    if (!adminOk()) return;
    const cu = str($('#chUser').value, 30), cp = $('#chPass').value;
    const nu = str($('#chNewUser').value, 30), np = $('#chNewPass').value;
    if (!(cu && cp && await checkCreds(cu, cp))) { await sleep(900); return setMsg('pwMsg', 'نام کاربری یا رمز فعلی نادرست است.', 'danger'); }
    const prob = usernameProblem(nu) || passwordProblem(np, nu);
    if (prob) return setMsg('pwMsg', prob, 'danger');
    if (!store.set(KEYS.admin, await makeRecord(nu, np))) return setMsg('pwMsg', 'ذخیره‌سازی ممکن نشد.', 'danger');
    ['chUser', 'chPass', 'chNewUser', 'chNewPass'].forEach(id => { $('#' + id).value = ''; });
    setMsg('pwMsg', 'نام کاربری و رمز جدید ذخیره شد. برای اعمال روی همهٔ دستگاه‌ها، «بستهٔ انتشار» را دوباره در گیت‌هاب آپلود کنید.', 'success');
    renderAdmin();
  }

  /** ورود به پنل مدیر فقط با آدرس /#<ADMIN_ROUTE> (دکمه‌ای در صفحهٔ عمومی وجود ندارد) */
  function checkAdminHash() {
    if (location.hash !== '#' + CFG.ADMIN_ROUTE) return;
    history.replaceState(null, '', location.pathname + location.search);
    openAdmin();
  }
  window.addEventListener('hashchange', checkAdminHash);

  // قفل خودکار: اگر تب مدتی پنهان بماند، نشست پایان می‌یابد
  let hiddenAt = 0;
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) { hiddenAt = Date.now(); return; }
    if (hiddenAt && Date.now() - hiddenAt > CFG.ADMIN_HIDE_LOCK_MIN * 60000) {
      session.del();
      if ($('#adminModal').classList.contains('open')) { showAdminView(); toast('برای امنیت، نشست مدیر قفل شد.'); }
    }
    hiddenAt = 0;
  });

  /* ---------------------------------------------------------
     مدیر: ابزار تصویر
     --------------------------------------------------------- */
  async function fileToDataUrl(file, { max = 900, type = 'image/jpeg', q = 0.82 } = {}) {
    if (!/^image\/(png|jpe?g|webp|gif)$/i.test(file.type)) throw new Error('فرمت تصویر مجاز نیست (PNG, JPG, WEBP, GIF).');
    if (file.size > 10 * 1024 * 1024) throw new Error('حجم تصویر بیش از ۱۰ مگابایت است.');
    const url = URL.createObjectURL(file);
    try {
      const img = await new Promise((res, rej) => {
        const i = new Image();
        i.onload = () => res(i);
        i.onerror = () => rej(new Error('تصویر قابل خواندن نیست.'));
        i.src = url;
      });
      const scale = Math.min(1, max / Math.max(img.naturalWidth, img.naturalHeight));
      const w = Math.max(1, Math.round(img.naturalWidth * scale));
      const hh = Math.max(1, Math.round(img.naturalHeight * scale));
      const c = document.createElement('canvas');
      c.width = w; c.height = hh;
      const ctx = c.getContext('2d');
      if (type === 'image/jpeg') { ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, w, hh); }
      ctx.drawImage(img, 0, 0, w, hh);
      const out = c.toDataURL(type, q);
      return safeUrl(out) ? out : (() => { throw new Error('تبدیل تصویر ناموفق بود.'); })();
    } finally { URL.revokeObjectURL(url); }
  }
  function setPreview(id, url, fallback) {
    const el = $('#' + id);
    el.dataset.fb = '';
    el.src = url || fallback;
  }

  /* ---------------------------------------------------------
     مدیر: داشبورد
     --------------------------------------------------------- */
  let currentTab = 'products';
  let prodEditId = null, prodImg = '';
  let slideImgPending = '';
  let logoPending = null;

  function switchTab(name) {
    currentTab = name;
    $$('[data-panel]').forEach(p => { p.hidden = p.dataset.panel !== name; });
    $$('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
  }

  const rowBtn = (label, action, dataset, cls = 'btn-soft') =>
    h('button', { class: `btn btn-sm ${cls}`, type: 'button', dataset: { action, ...dataset }, text: label });

  function renderAdmin() {
    if (!$('#adminModal').classList.contains('open') || $('[data-view=dash]').hidden) return;

    $('#draftNote').textContent = hasDraft()
      ? '⚠️ تغییرات فعلی فقط «پیش‌نویس» همین مرورگر است و هنوز برای بازدیدکنندگان منتشر نشده.'
      : '✅ آنچه می‌بینید همان نسخهٔ منتشرشدهٔ سایت است.';

    const au = audit.get(), lr = localRec(), rr = adminState.remote;
    const same = lr && validRec(rr) && lr.salt === rr.salt && lr.hash === rr.hash;
    const shared = validRec(rr) && (!lr || same)
      ? '✅ حساب مدیر منتشر شده است: از هر دستگاه با همان نام کاربری و رمز می‌توانید وارد شوید.'
      : lr && validRec(rr)
        ? '⚠️ نام کاربری/رمز جدید هنوز منتشر نشده؛ «بستهٔ انتشار» را در گیت‌هاب آپلود کنید.'
        : '⚠️ حساب مدیر هنوز منتشر نشده و فقط روی همین دستگاه کار می‌کند؛ «بستهٔ انتشار» را در گیت‌هاب آپلود کنید.';
    $('#securityStatus').replaceChildren(...[
      shared,
      au.lastOk ? `آخرین ورود موفق: ${new Date(au.lastOk).toLocaleString('fa-IR')}` : '',
      `تلاش ناموفق ثبت‌شده قبل از آخرین ورود (روی همین دستگاه): ${(au.failsBefore || 0).toLocaleString('fa-IR')}`,
      `پایان خودکار نشست: ${CFG.ADMIN_SESSION_MIN.toLocaleString('fa-IR')} دقیقه بی‌فعالیتی`
    ].filter(Boolean).map(t => h('li', { text: t })));

    const sel = $('#prodCat'), prev = sel.value;
    sel.replaceChildren(...data.categories.map(c => h('option', { value: c.id, text: `${c.icon} ${c.name}` })));
    if (prev && catById(prev)) sel.value = prev;

    $('#adminProducts').replaceChildren(...(data.products.length ? data.products.map(p => {
      const c = catById(p.cat);
      return h('div', { class: 'row' },
        h('div', { class: 'row-main' },
          withFallback(h('img', { class: 'thumb', src: productImage(p), alt: '' }), () => placeholder('🍼', '')),
          h('div', {}, h('strong', { text: p.name }), h('small', { text: `${c ? c.name : '—'} • ${formatPrice(p.price)}` }))),
        h('div', { class: 'row-actions' },
          rowBtn('ویرایش', 'prod-edit', { id: p.id }),
          rowBtn('حذف', 'prod-del', { id: p.id }, 'btn-danger')));
    }) : [h('p', { class: 'hint', text: 'هنوز محصولی ثبت نشده است.' })]));

    $('#adminCategories').replaceChildren(...data.categories.map(c => h('div', { class: 'row' },
      h('div', { class: 'row-main' },
        h('input', { class: 'cat-input cat-icon', value: c.icon, maxlength: 4, 'aria-label': 'آیکون', dataset: { catId: c.id, field: 'icon' } }),
        h('input', { class: 'cat-input cat-name', value: c.name, maxlength: 60, 'aria-label': 'نام دسته‌بندی', dataset: { catId: c.id, field: 'name' } }),
        h('small', { text: `${data.products.filter(p => p.cat === c.id).length.toLocaleString('fa-IR')} محصول` })),
      h('div', { class: 'row-actions' }, rowBtn('حذف', 'cat-del', { id: c.id }, 'btn-danger')))));

    $('#adminSlides').replaceChildren(...(data.slides.length ? data.slides.map((s, i) => h('div', { class: 'row' },
      h('div', { class: 'row-main' },
        withFallback(h('img', { class: 'thumb', src: s.img, alt: '' }), () => placeholder('🍼', '')),
        h('div', {}, h('strong', { text: s.caption || '(بدون متن)' }), h('small', { text: `اسلاید ${(i + 1).toLocaleString('fa-IR')}` }))),
      h('div', { class: 'row-actions' },
        rowBtn('↑', 'slide-up', { i }), rowBtn('↓', 'slide-down', { i }), rowBtn('حذف', 'slide-del', { i }, 'btn-danger'))))
      : [h('p', { class: 'hint', text: 'اسلایدی وجود ندارد.' })]));

    const fitOpt = (v, label, cur) => h('option', { value: v, selected: cur === v, text: label });
    $('#adminHeroSlides').replaceChildren(...(data.heroSlides.length ? data.heroSlides.map((s, i) => h('div', { class: 'row' },
      h('div', { class: 'row-main' },
        withFallback(h('img', { class: 'thumb', src: heroSrc(s), alt: '' }), () => placeholder('🍼', '')),
        h('div', { class: 'hs-fields' },
          h('input', { class: 'cat-input', value: s.caption, maxlength: 150, placeholder: 'متن روی اسلاید', 'aria-label': 'متن اسلاید', dataset: { heroI: i, field: 'caption' } }),
          h('select', { class: 'cat-input', 'aria-label': 'نحوهٔ نمایش', dataset: { heroI: i, field: 'fit' } },
            fitOpt('cover', 'پر کردن کادر (ممکن است کمی برش بخورد)', s.fit),
            fitOpt('contain', 'نمایش کامل عکس بدون برش (مناسب لوگو)', s.fit)))),
      h('div', { class: 'row-actions' },
        rowBtn('↑', 'hero-up', { i }), rowBtn('↓', 'hero-down', { i }),
        h('label', { class: 'btn btn-sm btn-soft file-btn' }, 'تعویض عکس',
          h('input', { type: 'file', accept: 'image/png,image/jpeg,image/webp,image/gif', dataset: { heroImg: i } })),
        rowBtn('حذف', 'hero-del', { i }, 'btn-danger'))))
      : [h('p', { class: 'hint', text: 'اسلایدی وجود ندارد؛ بخش بنر نمایش داده نمی‌شود.' })]));
  }

  function fillSettingsForm() {
    const s = data.settings;
    $$('#settingsForm [name]').forEach(el => { el.value = s[el.name] || ''; });
    logoPending = null;
    setPreview('logoPreview', safeUrl(s.logo), LOGO_FALLBACK);
    setMsg('setMsg', '');
  }

  /* ---------- محصولات ---------- */
  function resetProductForm() {
    prodEditId = null; prodImg = '';
    $('#productForm').reset();
    $('#productFormTitle').textContent = 'افزودن محصول';
    $('#prodCancel').hidden = true;
    setPreview('prodPreview', '', placeholder('🍼', 'بدون عکس'));
    setMsg('prodMsg', '');
  }
  function editProduct(id) {
    const p = data.products.find(x => x.id === id);
    if (!p) return;
    prodEditId = id; prodImg = p.img;
    $('#prodName').value = p.name;
    $('#prodCat').value = p.cat;
    $('#prodPrice').value = p.price || '';
    $('#prodDesc').value = p.desc;
    $('#prodImgUrl').value = p.img.startsWith('data:') ? '' : p.img;
    $('#productFormTitle').textContent = 'ویرایش محصول';
    $('#prodCancel').hidden = false;
    setPreview('prodPreview', productImage(p), '');
    $('#productForm').scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'center' });
  }
  function saveProduct() {
    if (!adminOk()) return;
    const name = str($('#prodName').value, 120);
    const cat = $('#prodCat').value;
    const price = num($('#prodPrice').value);
    const desc = str($('#prodDesc').value, 300);
    const urlRaw = $('#prodImgUrl').value.trim();
    if (!name) return setMsg('prodMsg', 'نام محصول الزامی است.', 'danger');
    if (!catById(cat)) return setMsg('prodMsg', 'ابتدا یک دسته‌بندی بسازید.', 'danger');
    if (urlRaw && !safeUrl(urlRaw)) return setMsg('prodMsg', 'آدرس عکس معتبر نیست؛ فقط https یا مسیر فایل داخل پروژه مجاز است.', 'danger');
    const img = urlRaw ? safeUrl(urlRaw) : prodImg;
    const ok = mutate(() => {
      if (prodEditId) {
        const i = data.products.findIndex(p => p.id === prodEditId);
        if (i > -1) data.products[i] = { id: prodEditId, cat, name, price, desc, img };
      } else {
        data.products.unshift({ id: uid(), cat, name, price, desc, img });
      }
    });
    if (ok) { resetProductForm(); toast('محصول ذخیره شد.', 'success'); }
  }

  /* ---------- دسته‌بندی‌ها ---------- */
  function addCategory() {
    if (!adminOk()) return;
    const name = str($('#newCatName').value, 60);
    const icon = str($('#newCatIcon').value, 4) || '🍼';
    if (!name) return setMsg('catMsg', 'نام دسته‌بندی را وارد کنید.', 'danger');
    if (data.categories.some(c => c.name === name)) return setMsg('catMsg', 'این دسته‌بندی از قبل وجود دارد.', 'danger');
    if (data.categories.length >= 40) return setMsg('catMsg', 'حداکثر ۴۰ دسته‌بندی مجاز است.', 'danger');
    if (mutate(() => data.categories.push({ id: uid(), name, icon }))) {
      $('#categoryForm').reset(); setMsg('catMsg', '');
      toast('دسته‌بندی افزوده شد.', 'success');
    }
  }
  function deleteCategory(id) {
    if (!adminOk()) return;
    const used = data.products.filter(p => p.cat === id).length;
    if (used) return toast(`ابتدا ${used.toLocaleString('fa-IR')} محصول این دسته را منتقل یا حذف کنید.`, 'danger');
    if (!confirm('این دسته‌بندی حذف شود؟')) return;
    mutate(() => { data.categories = data.categories.filter(c => c.id !== id); });
  }
  function editCategoryField(el) {
    if (!adminOk()) return;
    const c = catById(el.dataset.catId);
    if (!c) return;
    const val = str(el.value, el.dataset.field === 'icon' ? 4 : 60);
    if (!val) { renderAdmin(); return; }
    if (el.dataset.field === 'name' && data.categories.some(x => x.id !== c.id && x.name === val)) { toast('این نام تکراری است.', 'danger'); renderAdmin(); return; }
    mutate(() => { c[el.dataset.field] = val; });
  }

  /* ---------- اسلایدر ---------- */
  function addSlide() {
    if (!adminOk()) return;
    const urlRaw = $('#slideUrl').value.trim();
    if (urlRaw && !safeUrl(urlRaw)) return setMsg('slideMsg', 'آدرس عکس معتبر نیست؛ فقط https یا مسیر فایل داخل پروژه.', 'danger');
    const img = urlRaw ? safeUrl(urlRaw) : slideImgPending;
    if (!img) return setMsg('slideMsg', 'یک عکس انتخاب یا لینک آن را وارد کنید.', 'danger');
    if (data.slides.length >= 30) return setMsg('slideMsg', 'حداکثر ۳۰ اسلاید مجاز است.', 'danger');
    const caption = str($('#slideCaption').value, 150);
    if (mutate(() => data.slides.push({ img, caption }))) {
      $('#slideForm').reset(); slideImgPending = '';
      setPreview('slidePreview', '', placeholder('🖼️', ''));
      setMsg('slideMsg', ''); toast('اسلاید افزوده شد.', 'success');
    }
  }
  function moveSlideItem(i, dir) {
    if (!adminOk()) return;
    const j = i + dir;
    if (j < 0 || j >= data.slides.length) return;
    mutate(() => { [data.slides[i], data.slides[j]] = [data.slides[j], data.slides[i]]; });
  }
  function deleteSlide(i) {
    if (!adminOk() || !confirm('این اسلاید حذف شود؟')) return;
    mutate(() => { data.slides.splice(i, 1); });
  }

  /* ---------- اسلایدر بنر بالای صفحه ---------- */
  let heroImgPending = '';
  function addHeroSlide() {
    if (!adminOk()) return;
    const urlRaw = $('#heroUrl').value.trim();
    if (urlRaw && !safeUrl(urlRaw)) return setMsg('heroMsg', 'آدرس عکس معتبر نیست؛ فقط https یا مسیر فایل داخل پروژه.', 'danger');
    const img = urlRaw ? safeUrl(urlRaw) : heroImgPending;
    if (!img) return setMsg('heroMsg', 'یک عکس انتخاب یا لینک آن را وارد کنید.', 'danger');
    if (data.heroSlides.length >= 10) return setMsg('heroMsg', 'حداکثر ۱۰ اسلاید برای بنر مجاز است.', 'danger');
    const caption = str($('#heroCaption').value, 150);
    const fit = $('#heroFit').value === 'contain' ? 'contain' : 'cover';
    if (mutate(() => data.heroSlides.push({ img, caption, fit }))) {
      $('#heroSlideForm').reset(); heroImgPending = '';
      setPreview('heroPreview', '', placeholder('🖼️', ''));
      setMsg('heroMsg', ''); toast('اسلاید بنر افزوده شد.', 'success');
    }
  }
  function moveHeroSlide(i, dir) {
    if (!adminOk()) return;
    const j = i + dir;
    if (j < 0 || j >= data.heroSlides.length) return;
    mutate(() => { [data.heroSlides[i], data.heroSlides[j]] = [data.heroSlides[j], data.heroSlides[i]]; });
  }
  function deleteHeroSlide(i) {
    if (!adminOk() || !confirm('این اسلاید بنر حذف شود؟')) return;
    mutate(() => { data.heroSlides.splice(i, 1); });
  }
  function editHeroField(el) {
    if (!adminOk()) return;
    const s = data.heroSlides[Number(el.dataset.heroI)];
    if (!s) return;
    if (el.dataset.field === 'fit') mutate(() => { s.fit = el.value === 'contain' ? 'contain' : 'cover'; });
    else mutate(() => { s.caption = str(el.value, 150); });
  }
  function resetHeroSlides() {
    if (!adminOk() || !confirm('اسلایدهای بنر به حالت اولیه برگردد؟')) return;
    mutate(() => { data.heroSlides = defaults().heroSlides; });
  }

  /* ---------- تنظیمات و لوگو ---------- */
  function saveSettings() {
    if (!adminOk()) return;
    const next = {};
    for (const k of Object.keys(DEFAULT_SETTINGS)) {
      if (k === 'logo') continue;
      const el = $(`#settingsForm [name="${k}"]`);
      next[k] = cleanSetting(k, el ? el.value : '', DEFAULT_SETTINGS[k]);
    }
    next.logo = logoPending === '' ? DEFAULT_LOGO : (logoPending || data.settings.logo);
    if (mutate(() => { data.settings = next; })) { fillSettingsForm(); toast('تنظیمات ذخیره شد.', 'success'); }
  }

  /* ---------- پشتیبان ---------- */
  function downloadBlob(blob, filename) {
    const a = h('a', { href: URL.createObjectURL(blob), download: filename });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }
  function exportData() {
    if (!adminOk()) return;
    downloadBlob(new Blob([JSON.stringify({ app: 'ninimah', version: 2, exportedAt: new Date().toISOString(), data }, null, 2)], { type: 'application/json' }), 'ninimah-backup.json');
  }

  /*ZIP-START*/
  const CRC_TABLE = (() => {
    const t = new Uint32Array(256);
    for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; }
    return t;
  })();
  function crc32(u8) {
    let c = 0xFFFFFFFF;
    for (let i = 0; i < u8.length; i++) c = CRC_TABLE[(c ^ u8[i]) & 255] ^ (c >>> 8);
    return (c ^ 0xFFFFFFFF) >>> 0;
  }
  /** ساخت ZIP بدون فشرده‌سازی (store)؛ نام فایل‌ها UTF-8 */
  function buildZip(files) {
    const u16 = n => [n & 255, (n >>> 8) & 255];
    const u32 = n => [n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255];
    const body = [], central = [];
    let offset = 0, centralSize = 0;
    for (const f of files) {
      const name = enc.encode(f.name), crc = crc32(f.bytes), size = f.bytes.length;
      const local = new Uint8Array([0x50, 0x4b, 3, 4, ...u16(20), ...u16(0x0800), ...u16(0), ...u16(0), ...u16(0x21),
        ...u32(crc), ...u32(size), ...u32(size), ...u16(name.length), ...u16(0)]);
      const cen = new Uint8Array([0x50, 0x4b, 1, 2, ...u16(20), ...u16(20), ...u16(0x0800), ...u16(0), ...u16(0), ...u16(0x21),
        ...u32(crc), ...u32(size), ...u32(size), ...u16(name.length), ...u16(0), ...u16(0), ...u16(0), ...u16(0), ...u32(0), ...u32(offset)]);
      body.push(local, name, f.bytes);
      central.push(cen, name);
      offset += local.length + name.length + size;
      centralSize += cen.length + name.length;
    }
    const end = new Uint8Array([0x50, 0x4b, 5, 6, ...u16(0), ...u16(0), ...u16(files.length), ...u16(files.length), ...u32(centralSize), ...u32(offset), ...u16(0)]);
    return new Blob([...body, ...central, end], { type: 'application/zip' });
  }
  /*ZIP-END*/

  function dataUrlToFile(url, base) {
    const m = /^data:image\/(png|jpe?g|webp|gif);base64,([A-Za-z0-9+/=]+)$/i.exec(url || '');
    if (!m) return null;
    const bin = atob(m[2]);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    // کد کوتاه محتوا در نام فایل می‌آید تا بعد از تعویض عکس، مرورگرها نسخهٔ قدیمی را نشان ندهند
    return { name: `assets/uploads/${base}-${crc32(bytes).toString(36)}.${m[1].toLowerCase().replace('jpeg', 'jpg')}`, bytes };
  }

  /** بستهٔ انتشار: data/site.json + عکس‌های آپلودشده به‌صورت فایل جدا در assets/uploads */
  function exportPublish() {
    if (!adminOk()) return;
    const copy = JSON.parse(JSON.stringify(data));
    const files = [];
    const take = (url, base) => { const f = dataUrlToFile(url, base); if (!f) return url; files.push(f); return f.name; };
    copy.products.forEach(p => { p.img = take(p.img, `product-${p.id}`); });
    copy.slides.forEach((s, i) => { s.img = take(s.img, `slide-${i + 1}`); });
    copy.heroSlides.forEach((s, i) => { s.img = take(s.img, `hero-${i + 1}`); });
    copy.settings.logo = take(copy.settings.logo, 'logo');
    files.push({ name: 'data/site.json', bytes: enc.encode(JSON.stringify({ app: 'ninimah', version: 2, exportedAt: new Date().toISOString(), data: copy }, null, 2)) });
    // فایل ورود مدیر (فقط اثر انگشت رمزنگاری‌شده) تا ورود از هر دستگاهی ممکن شود
    const rec = localRec();
    if (rec) files.push({ name: 'data/admin.json', bytes: enc.encode(JSON.stringify({ app: 'ninimah', version: 4, admin: rec }, null, 2)) });
    downloadBlob(buildZip(files), 'ninimah-publish.zip');
    toast('بستهٔ انتشار دانلود شد. پوشه‌های data و assets داخل آن را در گیت‌هاب آپلود کنید.', 'success', 7000);
  }

  function discardDraft() {
    if (!adminOk()) return;
    if (!hasDraft()) return toast('پیش‌نویس منتشرنشده‌ای وجود ندارد.');
    if (!confirm('تغییرات منتشرنشدهٔ این مرورگر پاک شود و نسخهٔ منتشرشده نمایش داده شود؟')) return;
    store.del(KEYS.data);
    data = published ? JSON.parse(JSON.stringify(published)) : defaults();
    renderPublic(); renderAdmin(); fillSettingsForm(); resetProductForm();
    toast('پیش‌نویس حذف شد.', 'success');
  }
  async function importData(file) {
    if (!adminOk() || !file) return;
    if (file.size > 12 * 1024 * 1024) return setMsg('bkMsg', 'حجم فایل بیش از حد مجاز است.', 'danger');
    let parsed;
    try { parsed = JSON.parse(await file.text()); } catch { return setMsg('bkMsg', 'فایل JSON معتبر نیست.', 'danger'); }
    const raw = parsed && parsed.data ? parsed.data : parsed;
    if (!raw || !Array.isArray(raw.categories) || !Array.isArray(raw.products) || !Array.isArray(raw.slides)) return setMsg('bkMsg', 'ساختار فایل پشتیبان درست نیست.', 'danger');
    if (!confirm('اطلاعات فعلی سایت با فایل پشتیبان جایگزین شود؟')) return;
    if (mutate(() => { data = sanitizeData(raw); })) { fillSettingsForm(); setMsg('bkMsg', 'بازیابی با موفقیت انجام شد.', 'success'); }
  }
  function resetSite() {
    if (!adminOk() || !confirm('همه محصولات، اسلایدها و تنظیمات به حالت اولیه برمی‌گردد. ادامه می‌دهید؟')) return;
    mutate(() => { data = defaults(); });
    fillSettingsForm(); resetProductForm();
  }

  /* ---------------------------------------------------------
     رویدادها
     --------------------------------------------------------- */
  document.addEventListener('click', e => {
    const t = e.target.closest('[data-action]');
    if (t) {
      const d = t.dataset;
      switch (d.action) {
        case 'gen-password': {
          const p = generatePassword();
          if (d.target === 'pw') { $('#chNewPass').value = p; setMsg('pwMsg', `رمز پیشنهادی: ${p} — همین الان آن را جای امن (مدیر رمز یا یادداشت) ذخیره کنید.`, 'info'); }
          else { $('#setupPass').value = p; $('#setupPass2').value = p; setMsg('adminMsg', `رمز پیشنهادی: ${p} — همین الان آن را جای امن (مدیر رمز یا یادداشت) ذخیره کنید؛ قابل بازیابی نیست.`, 'info'); }
          break;
        }
        case 'close-modal': { const m = t.closest('.modal'); if (m) closeModal(m.id); break; }
        case 'cat': activeCat = d.cat; shown = pageSize(); renderTabs(); renderProducts(); break;
        case 'more': shown += pageSize(); renderProducts(); break;
        case 'no-contact': toast('اطلاعات تماس هنوز در تنظیمات فروشگاه ثبت نشده است.'); break;
        case 'slide-next': if (sliders[d.slider]) sliders[d.slider].move(1); break;
        case 'slide-prev': if (sliders[d.slider]) sliders[d.slider].move(-1); break;
        case 'slide-go': if (sliders[d.slider]) sliders[d.slider].go(Number(d.i) || 0); break;
        case 'hero-up': moveHeroSlide(Number(d.i), -1); break;
        case 'hero-down': moveHeroSlide(Number(d.i), 1); break;
        case 'hero-del': deleteHeroSlide(Number(d.i)); break;
        case 'hero-reset': resetHeroSlides(); break;
        case 'tab': switchTab(d.tab); break;
        case 'admin-logout': adminLogout(); break;
        case 'prod-edit': if (adminOk()) editProduct(d.id); break;
        case 'prod-del':
          if (adminOk() && confirm('این محصول حذف شود؟')) mutate(() => { data.products = data.products.filter(p => p.id !== d.id); });
          break;
        case 'prod-cancel': resetProductForm(); break;
        case 'prod-clear-img': prodImg = ''; $('#prodImgUrl').value = ''; $('#prodImgFile').value = ''; setPreview('prodPreview', '', placeholder('🍼', 'بدون عکس')); break;
        case 'cat-del': deleteCategory(d.id); break;
        case 'slide-up': moveSlideItem(Number(d.i), -1); break;
        case 'slide-down': moveSlideItem(Number(d.i), 1); break;
        case 'slide-del': deleteSlide(Number(d.i)); break;
        case 'logo-reset': logoPending = ''; $('#logoFile').value = ''; setPreview('logoPreview', DEFAULT_LOGO, LOGO_FALLBACK); break;
        case 'export': exportData(); break;
        case 'export-publish': exportPublish(); break;
        case 'discard-draft': discardDraft(); break;
        case 'reset-site': resetSite(); break;
        default: break;
      }
      return;
    }
    if (e.target.classList && e.target.classList.contains('modal')) closeModal(e.target.id);
  });

  document.addEventListener('submit', e => {
    e.preventDefault();
    switch (e.target.id) {
      case 'searchForm': shown = pageSize(); renderProducts(); break;
      case 'adminSetupForm': adminSetup(); break;
      case 'adminLoginForm': adminLogin(); break;
      case 'productForm': saveProduct(); break;
      case 'categoryForm': addCategory(); break;
      case 'slideForm': addSlide(); break;
      case 'heroSlideForm': addHeroSlide(); break;
      case 'settingsForm': saveSettings(); break;
      case 'passwordForm': changeCredentials(); break;
      default: break;
    }
  });

  document.addEventListener('change', async e => {
    const el = e.target;
    try {
      if (el.id === 'prodImgFile' && el.files[0]) {
        if (!adminOk()) return;
        prodImg = await fileToDataUrl(el.files[0]);
        $('#prodImgUrl').value = '';
        setPreview('prodPreview', prodImg, '');
        setMsg('prodMsg', '');
      } else if (el.id === 'slideFile' && el.files[0]) {
        if (!adminOk()) return;
        slideImgPending = await fileToDataUrl(el.files[0], { max: 1400, q: 0.8 });
        $('#slideUrl').value = '';
        setPreview('slidePreview', slideImgPending, '');
        setMsg('slideMsg', '');
      } else if (el.id === 'heroFile' && el.files[0]) {
        if (!adminOk()) return;
        heroImgPending = await fileToDataUrl(el.files[0], { max: 1400, type: 'image/webp', q: 0.85 });
        $('#heroUrl').value = '';
        setPreview('heroPreview', heroImgPending, '');
        setMsg('heroMsg', '');
      } else if (el.dataset && el.dataset.heroImg !== undefined && el.files[0]) {
        if (!adminOk()) return;
        const img = await fileToDataUrl(el.files[0], { max: 1400, type: 'image/webp', q: 0.85 });
        const i = Number(el.dataset.heroImg);
        mutate(() => { if (data.heroSlides[i]) data.heroSlides[i].img = img; });
      } else if (el.id === 'adminShowPass') {
        $('#adminPass').type = el.checked ? 'text' : 'password';
      } else if (el.id === 'logoFile' && el.files[0]) {
        if (!adminOk()) return;
        logoPending = await fileToDataUrl(el.files[0], { max: 500, type: 'image/webp', q: 0.92 });
        setPreview('logoPreview', logoPending, '');
      } else if (el.id === 'importFile') {
        await importData(el.files[0]);
        el.value = '';
      } else if (el.dataset && el.dataset.catId) {
        editCategoryField(el);
      } else if (el.dataset && el.dataset.heroI !== undefined && el.dataset.field) {
        editHeroField(el);
      }
    } catch (err) {
      const target = { prodImgFile: 'prodMsg', slideFile: 'slideMsg', heroFile: 'heroMsg', logoFile: 'setMsg' }[el.id];
      if (target) setMsg(target, err.message, 'danger'); else toast(err.message, 'danger');
      el.value = '';
    }
  });

  $('#prodImgUrl').addEventListener('input', () => {
    const u = safeUrl($('#prodImgUrl').value);
    if (u) { prodImg = ''; $('#prodImgFile').value = ''; setPreview('prodPreview', u, ''); }
  });
  $('#slideUrl').addEventListener('input', () => {
    const u = safeUrl($('#slideUrl').value);
    if (u) { slideImgPending = ''; $('#slideFile').value = ''; setPreview('slidePreview', u, ''); }
  });
  $('#heroUrl').addEventListener('input', () => {
    const u = safeUrl($('#heroUrl').value);
    if (u) { heroImgPending = ''; $('#heroFile').value = ''; setPreview('heroPreview', u, ''); }
  });
  $('#searchInput').addEventListener('input', () => { shown = pageSize(); renderProducts(); });

  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') { const m = $('.modal.open'); if (m) closeModal(m.id); }
  });
  // هر فعالیتی در پنل، نشست مدیر را تمدید می‌کند
  $('#adminModal').addEventListener('input', touchSession);
  setInterval(() => {
    if ($('#adminModal').classList.contains('open') && !$('[data-view=dash]').hidden && !sessionValid()) {
      showAdminView();
      toast('به دلیل بی‌فعالیتی از پنل خارج شدید.', 'danger');
    }
  }, 15000);

  window.addEventListener('scroll', onScroll, { passive: true });
  window.addEventListener('resize', onScroll);

  /* ---------------------------------------------------------
     شروع
     --------------------------------------------------------- */
  withFallback($('#siteLogo'), LOGO_FALLBACK);
  withFallback($('#logoPreview'), LOGO_FALLBACK);
  setPreview('prodPreview', '', placeholder('🍼', 'بدون عکس'));
  setPreview('slidePreview', '', placeholder('🖼️', ''));
  setPreview('heroPreview', '', placeholder('🖼️', ''));
  // پاک‌سازی دادهٔ نسخه‌های قبلی (ورود مشتری و حساب مدیر قدیمی با کد دومرحله‌ای)
  ['ninimah:users:v2', 'ninimah:user:v2', 'ninimah:admin:v2', 'ninimah:admin:v3'].forEach(k => store.del(k));
  (async () => {
    const [pub, rem] = await Promise.all([loadPublished(), loadRemoteAdmin()]);
    published = pub;
    if (rem !== undefined) adminState.remote = rem;
    const draft = store.get(KEYS.data, null);
    data = draft ? sanitizeData(draft) : (published || defaults());
    renderPublic();
    Object.values(sliders).forEach(s => s.start());
    updateFade();
    checkAdminHash();
  })();
})();
