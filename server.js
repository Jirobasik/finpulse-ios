const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT) || 3050;
const DATA_DIR = fs.existsSync('/data') ? '/data' : __dirname;
const DB_FILE = path.join(DATA_DIR, 'users-db.json');
const MAX_BODY_BYTES = 64 * 1024; // 64KB anti-DoS payload limit

// Zero-Knowledge Cryptographic Constants (No plaintext usernames, passwords, or credits in code)
const ADMIN_USER_SHA256 = '0d1a10520b97449b441227f90d004c3f0ea8f8d4ee13dfdf3bfde3dca2c15c7d';
const ADMIN_SALT_HEX = 'f9a3e8c1d4b2705192837465a0b1c2d3';
const ADMIN_HASH_HEX = '4d45f0241f713e919c0ef7191c746d4601ba6b9cd187890d5c74ee0bf1894410';

const VAULT_SALT_HEX = 'a7c4e9102b83d6f541928374650a1b2c';
const VAULT_IV_B64 = '9jzgVIOg4WxoPZjd';
const VAULT_CT_B64 = 'PCpKiwCj97Jkh30oE4uMV7sU0GYVCvBXWQh0txUnve5hMutpzshY5oc0mo8OMYdBWYoL8sdCCPOfa30Yj8dPioUsb9WMUuOVH9CYVEseGu9ka0gkotPIBJkB3avJjazkCzy2JLL0Wa+Kqgwn0Zb4WFRRUNj+W2Uz/5oeSRvvxJzP2ZyZh0ZMwjG9HUfTS9x4vqUByK0H2QYwJBg40o3sCIXvt5XMPahrqWmxkDhyZNyiHEfQktt2mEovLL/yOmOlk01XA+ntYu58/x9Gx1TWmAW7/pWijT8T38Va1jkmkHpirNJnX5IP6ak6DSDcV8SJcjGG3ToLC44bE4psCqkjOOcRGR6COLIiC2CtpLXyO2tvUJ/SYA4tF6VnfMeN3RaKLjWYpkLK4DNaOuJfQ15O1S6R4Gg8Y77l5FXItUV1PHidCJwns+tZMJ08BcteFuZGEKBABdopFfmtVgqSYr7VEZPIyyF92sZ6H2jzvlE90cww+XcaGYeFq1ni1E2vfcv7qtVmtsFP4HlYussdDLKYxsKuKnCXqcAv0A8/kpOJ51G0hZLCQ36usu81Bj2w7PLvLISXt90zxyWfkERS74WQ218BKHRVQW9kpQzeLkHBF3w4FnSMvQtVl0ikmy2Dwp/XMUQ+ROvmQjVbKixOKdjvSWJ7UPmAyZEcE4gMGohTrdHvg57QqAg1Md5iaiJNScggdmRJHUzgMdhGm52J+fbhkdc9rMrLHUOvb2lPd59F04lxsQpjbZba8hPGXTcXZULB4873V5IHBjwF1Ewa9myoyaom7xqPBoFmXjEbqze6mHSwNpbimK/E/2I4QGsVfN+jX2NVZpbIaTgqEsl6lDGbzU1JHm8ltcsbyfBebjHZ/7AlL5MWEP91idPuxiXZ0U6v+6LuHD0TtfuIcGhm3hHaGtURRWPPO7rfDAvFWEEthZWPDsh359SZjrjYrbmpdIb41tGFV4dJ5o1v/T/YLWNdow8IuKzDJBxSw809Z0QAxgMllqUu9kZ59ss3vyKBPSp7EjYguQU+wqp9heM4KS0Qfdt77e6zEK67bT65X2Y6DzrNmHR9OGy8+m9vhyJzLiBAbf53ABMowG3sLpGGoEIF6/H1LG1CjhqRdZCFanVYTB6UmjBAhpKQnqZe3EXMXbwo6wgexGYuOv86asDWl1IS0daTBYmam+/oULzzSGdxmzSxDHRICQ3p0M/mB4ErzoeWwplxw59LTEUfbd9hai7iICRv1OHEbi3YKsrUydAjZyY4uFb0MbMq1sVbrhsDe0dPbthMOqcbfGq6DYR8EIOB+/Mgs6D1c+M0xPFTdXTuo8vpdRSxbQVuMs2GlaZxMezgYIlqRyDyEHqPx1ymebBDmsmYigvYkHw3chfHZ8C/K2WTC15S1IHiaiAgygGb/RVBtxw93R+cWuWiaMjuWWA9S+SzlmlX2u2kcnbmgASiOZm5jZ3YiS9COAffBfPUrJi1ha4DqALGBLqF5DCdf/XGq+e1wm0ydlSrkpkVUq9YjOnuS4+wwPUhLmcTqm3h4uL8/DCC5xaPFUtISi0GTk6aEIrQn/RuMOeWkdfg5nGZjiI13MxjlV0+9Q/+ATmgerT0MS9Rs1wUw76uwpVPimvUcEshjkaR0Q==';

function isRootAdminUser(usernameLower) {
  const h = crypto.createHash('sha256').update(String(usernameLower || '').toLowerCase()).digest('hex');
  return h === ADMIN_USER_SHA256;
}

function hashPassword(password, saltHex) {
  return crypto.pbkdf2Sync(String(password), Buffer.from(saltHex, 'hex'), 100000, 32, 'sha256').toString('hex');
}

function verifyPassword(password, saltHex, expectedHashHex) {
  try {
    const actual = Buffer.from(hashPassword(password, saltHex), 'hex');
    const expected = Buffer.from(expectedHashHex, 'hex');
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
  } catch (e) {
    return false;
  }
}

function decryptAdminVaultServer(password) {
  try {
    const key = crypto.pbkdf2Sync(String(password), Buffer.from(VAULT_SALT_HEX, 'hex'), 100000, 32, 'sha256');
    const iv = Buffer.from(VAULT_IV_B64, 'base64');
    const combined = Buffer.from(VAULT_CT_B64, 'base64');
    const tag = combined.subarray(combined.length - 16);
    const enc = combined.subarray(0, combined.length - 16);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const dec = Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8');
    return JSON.parse(dec);
  } catch (e) {
    return getCleanUserProfile();
  }
}

function getCleanUserProfile() {
  return {
    settings: {
      currency: '₽',
      paydayDay: 25,
      salaryDay: 10,
      advanceDay: 25,
      cashWindow: '10–15 числа',
      monthlyIncomeGoal: 100000
    },
    transactions: [],
    credits: []
  };
}

function createInitialDb() {
  return {
    system: {
      allowRegistration: true,
      hmacSecret: crypto.randomBytes(32).toString('hex')
    },
    users: {},
    auditLog: [
      {
        id: 'log_init',
        time: new Date().toISOString(),
        type: 'SYSTEM_INIT',
        severity: 'info',
        actor: 'system',
        ip: 'hidden',
        details: 'Защищённое ядро FinPulse инициализировано (AES-256-GCM + PBKDF2-SHA256 + WAF)'
      }
    ]
  };
}

const CLOUD_POINTER_URL = 'https://api.restful-api.dev/objects/ff808181a09d98f701a12e232c8d44c9';
const CLOUD_BLOB_POST_URL = 'https://bytebin.lucko.me/post';
const CLOUD_BLOB_GET_BASE = 'https://bytebin.lucko.me/';
const CLOUD_CIPHER_SEED = 'fp_v3_aes_gcm_91a8c4e27b3d506f84219e0c7a5b3d1f';
const cloudAesKey = crypto.createHash('sha256').update(CLOUD_CIPHER_SEED).digest();

function encryptCloudPayload(obj) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', cloudAesKey, iv);
  const enc = Buffer.concat([cipher.update(JSON.stringify(obj), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    v: 3,
    iv: iv.toString('base64'),
    ct: Buffer.concat([enc, tag]).toString('base64')
  };
}

function decryptCloudPayload(envelope) {
  const iv = Buffer.from(envelope.iv, 'base64');
  const combined = Buffer.from(envelope.ct, 'base64');
  const tag = combined.subarray(combined.length - 16);
  const enc = combined.subarray(0, combined.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', cloudAesKey, iv);
  decipher.setAuthTag(tag);
  return JSON.parse(Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8'));
}

async function pushServerDbToCloud(db) {
  try {
    db.updatedAt = Date.now();
    const encryptedEnvelope = encryptCloudPayload(db);
    const postRes = await fetch(CLOUD_BLOB_POST_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(encryptedEnvelope)
    });
    if (!postRes.ok) return;
    const { key } = await postRes.json();
    if (!key) return;
    await fetch(CLOUD_POINTER_URL, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'fp_sync_v3',
        data: { key, updatedAt: db.updatedAt }
      })
    });
  } catch (e) {}
}

async function pullServerDbFromCloud() {
  try {
    const ptrRes = await fetch(CLOUD_POINTER_URL);
    if (!ptrRes.ok) return;
    const ptrJson = await ptrRes.json();
    const key = ptrJson && ptrJson.data && ptrJson.data.key;
    if (!key) return;
    const blobRes = await fetch(CLOUD_BLOB_GET_BASE + key);
    if (!blobRes.ok) return;
    const rawPayload = await blobRes.json();
    const cloudDb = rawPayload && rawPayload.ct ? decryptCloudPayload(rawPayload) : rawPayload;
    if (cloudDb && cloudDb.users) {
      if (!cloudDb.system || !cloudDb.system.hmacSecret) {
        cloudDb.system = cloudDb.system || { allowRegistration: true };
        cloudDb.system.hmacSecret = crypto.randomBytes(32).toString('hex');
      }
      fs.writeFileSync(DB_FILE, JSON.stringify(cloudDb, null, 2), 'utf8');
    }
  } catch (e) {}
}

// Pull latest Cloud DB on server start
pullServerDbFromCloud();

function loadDb() {
  if (!fs.existsSync(DB_FILE)) {
    const init = createInitialDb();
    fs.writeFileSync(DB_FILE, JSON.stringify(init, null, 2), 'utf8');
    return init;
  }
  try {
    const db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    if (!db.users) {
      const init = createInitialDb();
      fs.writeFileSync(DB_FILE, JSON.stringify(init, null, 2), 'utf8');
      return init;
    }
    if (!db.system || !db.system.hmacSecret) {
      db.system = db.system || { allowRegistration: true };
      db.system.hmacSecret = crypto.randomBytes(32).toString('hex');
    }
    return db;
  } catch (e) {
    return createInitialDb();
  }
}

function saveDb(db) {
  if (db.auditLog && db.auditLog.length > 250) {
    db.auditLog = db.auditLog.slice(0, 250);
  }
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf8');
  pushServerDbToCloud(db);
}

function addAuditLog(db, type, severity, actor, ip, details) {
  db.auditLog.unshift({
    id: 'log_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6),
    time: new Date().toISOString(),
    type,
    severity,
    actor: String(actor || 'anonymous').slice(0, 40),
    ip: String(ip || 'unknown').slice(0, 45),
    details: String(details || '').slice(0, 300)
  });
}

// Signed Session Token (HMAC-SHA256)
function signToken(payloadObj, secret) {
  const data = Buffer.from(JSON.stringify(payloadObj)).toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(data).digest('base64url');
  return `${data}.${sig}`;
}

function verifyToken(token, secret) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [data, sig] = token.split('.');
  const expectedSig = crypto.createHmac('sha256', secret).update(data).digest('base64url');
  const a = Buffer.from(sig || '');
  const b = Buffer.from(expectedSig);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const payload = JSON.parse(Buffer.from(data, 'base64url').toString('utf8'));
    if (!payload.exp || Date.now() > payload.exp) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

// Brute-force & Rate Limiting in-memory store
const loginAttempts = new Map(); // key -> { count, lockedUntil }
const apiRateLimits = new Map(); // ip -> { count, resetAt }

function checkRateLimit(ip, limitPerMin = 120) {
  const now = Date.now();
  const entry = apiRateLimits.get(ip) || { count: 0, resetAt: now + 60000 };
  if (now > entry.resetAt) {
    entry.count = 0;
    entry.resetAt = now + 60000;
  }
  entry.count++;
  apiRateLimits.set(ip, entry);
  return entry.count <= limitPerMin;
}

function checkLoginLockout(key) {
  const entry = loginAttempts.get(key);
  if (!entry) return { locked: false };
  if (entry.lockedUntil && Date.now() < entry.lockedUntil) {
    const secLeft = Math.ceil((entry.lockedUntil - Date.now()) / 1000);
    return { locked: true, secLeft };
  }
  if (entry.lockedUntil && Date.now() >= entry.lockedUntil) {
    loginAttempts.delete(key);
  }
  return { locked: false };
}

function recordFailedLogin(key) {
  const entry = loginAttempts.get(key) || { count: 0, lockedUntil: 0 };
  entry.count++;
  if (entry.count >= 5) {
    entry.lockedUntil = Date.now() + 15 * 60 * 1000; // 15 minutes lockout
  }
  loginAttempts.set(key, entry);
  return entry;
}

// WAF (Web Application Firewall) detector for XSS / SQLi / Path Traversal
const WAF_PATTERNS = [
  /<\s*script\b/i,
  /javascript\s*:/i,
  /on(error|load|mouseover|focus|click)\s*=/i,
  /<\s*(iframe|object|embed|svg)\b/i,
  /\bunion\s+all\s+select\b|\bunion\s+select\b/i,
  /\bdrop\s+table\b/i,
  /\.\.\/|\.\.\\/,
  /\$where|\$ne\b/i
];

function inspectWaf(rawString) {
  if (!rawString) return null;
  for (const rx of WAF_PATTERNS) {
    if (rx.test(rawString)) {
      return rx.toString();
    }
  }
  return null;
}

function sanitizeText(str, maxLen = 120) {
  return String(str || '')
    .replace(/[<>]/g, '')
    .trim()
    .slice(0, maxLen);
}

// Smart Russian NLP parser
function parseSmartInput(rawText) {
  if (!rawText || typeof rawText !== 'string') return [];
  const parts = rawText.split(/[,;\n]+/).map(s => s.trim()).filter(Boolean);
  const results = [];

  const categoryKeywords = [
    { cat: 'Зарплата', type: 'income', words: ['зп', 'зарплат', 'аванс', 'оклад', 'преми', 'наличк'] },
    { cat: 'Фриланс / Доход', type: 'income', words: ['доход', 'фриланс', 'перевод от', 'вернул', 'кэшбэк', 'кешбек', 'заказ', 'плюс'] },
    { cat: 'Продукты', type: 'expense', words: ['продукт', 'пятерочк', 'перекрест', 'магнит', 'вкусвилл', 'лента', 'ашан', 'самокат', 'лавка', 'хлеб', 'молок', 'еда', 'супермаркет'] },
    { cat: 'Кафе и рестораны', type: 'expense', words: ['кофе', 'обед', 'ужин', 'завтрак', 'кафе', 'ресторан', 'бургер', 'пицц', 'шаурм', 'ролл', 'суши', 'додо'] },
    { cat: 'Транспорт', type: 'expense', words: ['такси', 'бензин', 'заправк', 'метро', 'автобус', 'парковк', 'каршеринг', 'проезд'] },
    { cat: 'Дом и ЖКУ', type: 'expense', words: ['жкх', 'кварплат', 'аренд', 'свет', 'вода', 'дом', 'ремонт', 'аптек', 'лекарств'] },
    { cat: 'Покупки и Маркетплейсы', type: 'expense', words: ['озон', 'ozon', 'wb', 'вб', 'вайлдберриз', 'маркет', 'одежд', 'обув', 'техник', 'подарок'] },
    { cat: 'Подписки и связь', type: 'expense', words: ['связь', 'интернет', 'подписк', 'мтс', 'билайн', 'мегафон', 'теле2', 't2', 'яндекс плюс', 'музык', 'vpn'] },
    { cat: 'Кредиты', type: 'credit_payment', words: ['кредит', 'рассрочк', 'долг', 'ипотек', 'сплит'] }
  ];

  for (const part of parts) {
    const lower = part.toLowerCase();
    const numMatch = part.match(/([+-]?\d+(?:[.,]\d+)?)/);
    if (!numMatch) continue;

    const rawNum = numMatch[1].replace(',', '.');
    const amount = Math.abs(parseFloat(rawNum));
    if (isNaN(amount) || amount <= 0 || amount > 1e9) continue;

    let type = rawNum.startsWith('+') ? 'income' : 'expense';
    let category = type === 'income' ? 'Доход' : 'Разное';

    for (const rule of categoryKeywords) {
      if (rule.words.some(w => lower.includes(w))) {
        category = rule.cat;
        if (rule.type === 'income') type = 'income';
        if (rule.type === 'credit_payment') type = 'expense';
        break;
      }
    }

    const titleClean = sanitizeText(part.replace(numMatch[0], '').replace(/[₽рp.]+/gi, '').trim() || category, 80);
    const title = titleClean ? titleClean.charAt(0).toUpperCase() + titleClean.slice(1) : category;

    results.push({
      id: 't_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6),
      type,
      amount,
      category,
      title,
      date: new Date().toISOString()
    });
  }

  return results;
}

function calculateAnalytics(profile) {
  const now = new Date();
  const currentDay = now.getDate();
  const daysInMonth = new Date(now.getFullYear(), now.getMonth() + 1, 0).getDate();

  let totalIncome = 0;
  let totalExpense = 0;
  const expensesByCategory = {};

  for (const t of profile.transactions || []) {
    if (t.type === 'income') {
      totalIncome += Number(t.amount);
    } else {
      totalExpense += Number(t.amount);
      expensesByCategory[t.category] = (expensesByCategory[t.category] || 0) + Number(t.amount);
    }
  }

  const netBalance = totalIncome - totalExpense;

  let totalDebt = 0;
  let totalMonthlyCreditPayment = 0;
  let unpaidCreditReserve = 0;
  const upcomingReminders = [];

  const creditsEnriched = (profile.credits || []).map(c => {
    totalDebt += Number(c.totalDebt);
    totalMonthlyCreditPayment += Number(c.monthlyPayment);
    if (!c.paidThisMonth) unpaidCreditReserve += Number(c.monthlyPayment);

    let daysUntil = c.paymentDay - currentDay;
    if (daysUntil < 0) daysUntil = (daysInMonth - currentDay) + c.paymentDay;

    if (!c.paidThisMonth && daysUntil <= 14) {
      upcomingReminders.push({
        id: c.id,
        name: c.name,
        amount: c.monthlyPayment,
        paymentDay: c.paymentDay,
        daysUntil
      });
    }

    const paidPercent = c.originalAmount > 0
      ? Math.max(0, Math.min(100, Math.round(((c.originalAmount - c.totalDebt) / c.originalAmount) * 100)))
      : 0;

    return { ...c, daysUntil, paidPercent };
  }).sort((a, b) => a.daysUntil - b.daysUntil);

  const freeMoneyAfterCredits = netBalance - unpaidCreditReserve;
  let daysToPayday = 1;
  let nextPaydayTitle = '25-го числа (Аванс)';
  if (currentDay < 10) {
    daysToPayday = 10 - currentDay;
    nextPaydayTitle = '10-го числа (ЗП + нал)';
  } else if (currentDay < 25) {
    daysToPayday = 25 - currentDay;
    nextPaydayTitle = '25-го числа (Аванс)';
  } else {
    daysToPayday = (daysInMonth - currentDay) + 10;
    nextPaydayTitle = '10-го числа (ЗП + нал)';
  }

  const safeDailyLimit = Math.max(0, Math.round(freeMoneyAfterCredits / Math.max(1, daysToPayday)));
  const baseIncome = Math.max(totalIncome, (profile.settings && profile.settings.monthlyIncomeGoal) || 150000);
  const dtiPercent = Math.round((totalMonthlyCreditPayment / baseIncome) * 100);

  return {
    totalIncome,
    totalExpense,
    netBalance,
    totalDebt,
    totalMonthlyCreditPayment,
    unpaidCreditReserve,
    freeMoneyAfterCredits,
    safeDailyLimit,
    daysToPayday,
    nextPaydayTitle,
    dtiPercent,
    expensesByCategory,
    creditsEnriched,
    upcomingReminders
  };
}

function buildBriefingText(profile, analytics) {
  const cur = (profile.settings && profile.settings.currency) || '₽';
  const fmt = n => Number(n).toLocaleString('ru-RU') + ' ' + cur;

  let lines = [];
  lines.push(`Баланс: ${fmt(analytics.netBalance)}`);
  lines.push(`После резерва кредитов: ${fmt(analytics.freeMoneyAfterCredits)}`);
  lines.push(`Лимит на день: ${fmt(analytics.safeDailyLimit)}/дн (до выплаты ${analytics.daysToPayday} дн. — ${analytics.nextPaydayTitle})`);

  if (analytics.upcomingReminders.length > 0) {
    lines.push(`\nБЛИЖАЙШИЕ КРЕДИТЫ:`);
    for (const r of analytics.upcomingReminders) {
      const when = r.daysUntil === 0 ? 'СЕГОДНЯ' : r.daysUntil === 1 ? 'ЗАВТРА' : `через ${r.daysUntil} дн. (${r.paymentDay}-го числа)`;
      lines.push(`• ${r.name}: ${fmt(r.amount)} — ${when}`);
    }
  }
  return lines.join('\n');
}

function getAuthenticatedUser(req, db, parsedUrl) {
  const authHeader = req.headers['authorization'] || '';
  const bearer = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : (parsedUrl.searchParams.get('session') || '');
  if (!bearer) return null;
  const payload = verifyToken(bearer, db.system.hmacSecret);
  if (!payload || !payload.sub) return null;
  const user = db.users[payload.sub];
  if (!user || user.banned) return null;
  return user;
}

function readBodySafe(req, res, db, ip, callback) {
  let body = '';
  let bytes = 0;
  let aborted = false;

  req.on('data', chunk => {
    bytes += chunk.length;
    if (bytes > MAX_BODY_BYTES) {
      aborted = true;
      addAuditLog(db, 'DOS_PAYLOAD_LIMIT', 'high', 'anonymous', ip, `Превышен лимит запроса 64KB (${bytes} bytes)`);
      saveDb(db);
      res.writeHead(413, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ ok: false, error: 'Payload too large' }));
      req.destroy();
      return;
    }
    body += chunk;
  });

  req.on('end', () => {
    if (aborted) return;
    const wafHit = inspectWaf(body) || inspectWaf(req.url);
    if (wafHit) {
      addAuditLog(db, 'WAF_BLOCK', 'critical', 'anonymous', ip, `Заблокирована атака (${wafHit}) на ${req.url}`);
      saveDb(db);
      res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ ok: false, error: 'Запрос заблокирован системой защиты WAF' }));
      return;
    }
    callback(body);
  });
}

const server = http.createServer((req, res) => {
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1').split(',')[0].trim();

  // Hardened HTTP Security Headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), camera=(), microphone=()');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }

  if (!checkRateLimit(ip, 150)) {
    res.writeHead(429, { 'Content-Type': 'application/json; charset=utf-8' });
    return res.end(JSON.stringify({ ok: false, error: 'Слишком много запросов. Подождите минуту.' }));
  }

  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsedUrl.pathname;

  // 1. AUTH: Login
  if (pathname === '/api/auth/login' && req.method === 'POST') {
    const db = loadDb();
    return readBodySafe(req, res, db, ip, body => {
      try {
        const { username, password } = JSON.parse(body || '{}');
        const uLower = String(username || '').trim().toLowerCase();
        const lockKey = `${ip}:${uLower}`;
        const lock = checkLoginLockout(lockKey);

        if (lock.locked) {
          addAuditLog(db, 'BRUTEFORCE_LOCKOUT', 'high', uLower, ip, `Блокировка перебора пароля (${lock.secLeft} сек.)`);
          saveDb(db);
          res.writeHead(429, { 'Content-Type': 'application/json; charset=utf-8' });
          return res.end(JSON.stringify({ ok: false, error: `Слишком много попыток. Повторите через ${lock.secLeft} сек.` }));
        }

        let user = db.users[uLower];
        const isRoot = isRootAdminUser(uLower);
        const saltToUse = isRoot ? ADMIN_SALT_HEX : (user ? user.salt : ADMIN_SALT_HEX);
        const expectedHash = isRoot ? ADMIN_HASH_HEX : (user ? user.passwordHash : '');

        if ((!user && !isRoot) || !verifyPassword(String(password || ''), saltToUse, expectedHash)) {
          const entry = recordFailedLogin(lockKey);
          addAuditLog(db, 'AUTH_FAIL', 'warn', uLower || 'unknown', ip, `Неудачная попытка входа (${entry.count}/5)`);
          saveDb(db);
          res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8' });
          return res.end(JSON.stringify({ ok: false, error: 'Неверный логин или пароль' }));
        }

        if (isRoot && !user) {
          user = {
            id: 'usr_root_admin',
            username: String(username || '').trim(),
            usernameLower: uLower,
            role: 'admin',
            salt: ADMIN_SALT_HEX,
            passwordHash: ADMIN_HASH_HEX,
            shortcutToken: 'fp_' + crypto.randomBytes(10).toString('hex'),
            banned: false,
            createdAt: new Date().toISOString(),
            lastLoginAt: new Date().toISOString(),
            profile: decryptAdminVaultServer(password)
          };
          db.users[uLower] = user;
        } else if (isRoot && user) {
          user.role = 'admin';
          user.banned = false;
        }

        if (user.banned) {
          addAuditLog(db, 'AUTH_BANNED', 'warn', user.username, ip, 'Попытка входа в заблокированный аккаунт');
          saveDb(db);
          res.writeHead(403, { 'Content-Type': 'application/json; charset=utf-8' });
          return res.end(JSON.stringify({ ok: false, error: 'Аккаунт заблокирован администратором' }));
        }

        loginAttempts.delete(lockKey);
        user.lastLoginAt = new Date().toISOString();
        addAuditLog(db, 'AUTH_SUCCESS', 'info', user.username, ip, `Успешный вход (${user.role})`);
        saveDb(db);

        const token = signToken(
          { sub: user.usernameLower, username: user.username, role: user.role, exp: Date.now() + 7 * 86400000 },
          db.system.hmacSecret
        );

        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        return res.end(JSON.stringify({
          ok: true,
          token,
          user: {
            username: user.username,
            role: user.role,
            shortcutToken: user.shortcutToken
          }
        }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
        return res.end(JSON.stringify({ ok: false, error: 'Ошибка запроса' }));
      }
    });
  }

  // 2. AUTH: Register new user
  if (pathname === '/api/auth/register' && req.method === 'POST') {
    const db = loadDb();
    return readBodySafe(req, res, db, ip, body => {
      try {
        if (!db.system.allowRegistration) {
          res.writeHead(403, { 'Content-Type': 'application/json; charset=utf-8' });
          return res.end(JSON.stringify({ ok: false, error: 'Регистрация новых пользователей закрыта администратором' }));
        }

        const { username, password } = JSON.parse(body || '{}');
        const cleanName = String(username || '').trim();
        const uLower = cleanName.toLowerCase();

        if (!/^[a-zA-Zа-яА-ЯёЁ0-9_.-]{3,24}$/.test(cleanName)) {
          res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
          return res.end(JSON.stringify({ ok: false, error: 'Логин должен быть от 3 до 24 символов (буквы, цифры, _ . -)' }));
        }

        if (String(password || '').length < 6) {
          res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
          return res.end(JSON.stringify({ ok: false, error: 'Пароль должен содержать минимум 6 символов' }));
        }

        if (db.users[uLower] || isRootAdminUser(uLower)) {
          res.writeHead(409, { 'Content-Type': 'application/json; charset=utf-8' });
          return res.end(JSON.stringify({ ok: false, error: 'Этот логин уже занят' }));
        }

        const salt = crypto.randomBytes(16).toString('hex');
        const passwordHash = hashPassword(password, salt);
        const shortcutToken = 'fp_' + crypto.randomBytes(12).toString('hex');

        db.users[uLower] = {
          id: 'usr_' + Date.now(),
          username: cleanName,
          usernameLower: uLower,
          role: 'user',
          salt,
          passwordHash,
          shortcutToken,
          banned: false,
          createdAt: new Date().toISOString(),
          lastLoginAt: new Date().toISOString(),
          profile: getCleanUserProfile()
        };

        addAuditLog(db, 'USER_REGISTER', 'info', cleanName, ip, 'Зарегистрирован новый аккаунт');
        saveDb(db);

        const token = signToken(
          { sub: uLower, username: cleanName, role: 'user', exp: Date.now() + 7 * 86400000 },
          db.system.hmacSecret
        );

        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        return res.end(JSON.stringify({
          ok: true,
          token,
          user: { username: cleanName, role: 'user', shortcutToken }
        }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
        return res.end(JSON.stringify({ ok: false, error: 'Некорректные данные регистрации' }));
      }
    });
  }

  // 3. STATE: Get authenticated user's financial state
  if (pathname === '/api/state' && req.method === 'GET') {
    const db = loadDb();
    const user = getAuthenticatedUser(req, db, parsedUrl);
    if (!user) {
      res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8' });
      return res.end(JSON.stringify({ ok: false, error: 'Требуется авторизация' }));
    }
    const analytics = calculateAnalytics(user.profile);
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    return res.end(JSON.stringify({
      ok: true,
      user: { username: user.username, role: user.role, shortcutToken: user.shortcutToken },
      data: user.profile,
      analytics,
      briefing: buildBriefingText(user.profile, analytics)
    }));
  }

  // 4. TRANSACTIONS: Add / Delete for authenticated user
  if (pathname === '/api/transaction' && req.method === 'POST') {
    const db = loadDb();
    const user = getAuthenticatedUser(req, db, parsedUrl);
    if (!user) {
      res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8' });
      return res.end(JSON.stringify({ ok: false, error: 'Требуется авторизация' }));
    }
    return readBodySafe(req, res, db, ip, body => {
      try {
        const payload = JSON.parse(body || '{}');
        if (payload.smartText) {
          const parsed = parseSmartInput(payload.smartText);
          user.profile.transactions.unshift(...parsed);
        } else {
          const amt = Math.abs(Number(payload.amount));
          if (amt > 0 && amt <= 1e9) {
            user.profile.transactions.unshift({
              id: 't_' + Date.now(),
              type: payload.type === 'income' ? 'income' : 'expense',
              amount: amt,
              category: sanitizeText(payload.category || 'Разное', 40),
              title: sanitizeText(payload.title || payload.category || 'Операция', 80),
              date: new Date().toISOString()
            });
          }
        }
        saveDb(db);
        const analytics = calculateAnalytics(user.profile);
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        return res.end(JSON.stringify({ ok: true, data: user.profile, analytics }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
        return res.end(JSON.stringify({ ok: false, error: e.message }));
      }
    });
  }

  if (pathname === '/api/transaction' && req.method === 'DELETE') {
    const db = loadDb();
    const user = getAuthenticatedUser(req, db, parsedUrl);
    if (!user) {
      res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8' });
      return res.end(JSON.stringify({ ok: false, error: 'Требуется авторизация' }));
    }
    const id = parsedUrl.searchParams.get('id');
    user.profile.transactions = user.profile.transactions.filter(t => t.id !== id);
    saveDb(db);
    const analytics = calculateAnalytics(user.profile);
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    return res.end(JSON.stringify({ ok: true, data: user.profile, analytics }));
  }

  // 5. CREDITS: Add / Pay / Delete for authenticated user
  if (pathname === '/api/credit' && req.method === 'POST') {
    const db = loadDb();
    const user = getAuthenticatedUser(req, db, parsedUrl);
    if (!user) {
      res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8' });
      return res.end(JSON.stringify({ ok: false, error: 'Требуется авторизация' }));
    }
    return readBodySafe(req, res, db, ip, body => {
      try {
        const payload = JSON.parse(body || '{}');
        if (payload.action === 'pay' && payload.id) {
          const credit = user.profile.credits.find(c => c.id === payload.id);
          if (credit && !credit.paidThisMonth) {
            credit.paidThisMonth = true;
            credit.totalDebt = Math.max(0, credit.totalDebt - credit.monthlyPayment);
            user.profile.transactions.unshift({
              id: 't_' + Date.now(),
              type: 'expense',
              amount: credit.monthlyPayment,
              category: 'Кредиты',
              title: `Платёж по кредиту: ${credit.name}`,
              date: new Date().toISOString()
            });
          }
        } else if (payload.action === 'delete' && payload.id) {
          user.profile.credits = user.profile.credits.filter(c => c.id !== payload.id);
        } else {
          user.profile.credits.push({
            id: 'c_' + Date.now(),
            name: sanitizeText(payload.name || 'Кредит', 50),
            totalDebt: Math.max(0, Number(payload.totalDebt) || 0),
            originalAmount: Math.max(0, Number(payload.originalAmount || payload.totalDebt) || 0),
            monthlyPayment: Math.max(0, Number(payload.monthlyPayment) || 0),
            interestRate: Math.max(0, Number(payload.interestRate) || 0),
            paymentDay: Math.min(31, Math.max(1, Number(payload.paymentDay) || 15)),
            paidThisMonth: false
          });
        }
        saveDb(db);
        const analytics = calculateAnalytics(user.profile);
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        return res.end(JSON.stringify({ ok: true, data: user.profile, analytics }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
        return res.end(JSON.stringify({ ok: false, error: e.message }));
      }
    });
  }

  // 6. ADMIN PANEL ENDPOINTS (Strictly for role === 'admin')
  if (pathname === '/api/admin/overview' && req.method === 'GET') {
    const db = loadDb();
    const user = getAuthenticatedUser(req, db, parsedUrl);
    if (!user || user.role !== 'admin') {
      addAuditLog(db, 'UNAUTHORIZED_ADMIN', 'high', user ? user.username : 'anonymous', ip, 'Попытка доступа к админ-панели без прав');
      saveDb(db);
      res.writeHead(403, { 'Content-Type': 'application/json; charset=utf-8' });
      return res.end(JSON.stringify({ ok: false, error: 'Доступ запрещён' }));
    }

    const usersList = Object.values(db.users).map(u => {
      const a = calculateAnalytics(u.profile);
      return {
        username: u.username,
        usernameLower: u.usernameLower,
        role: u.role,
        banned: !!u.banned,
        createdAt: u.createdAt,
        lastLoginAt: u.lastLoginAt,
        transactionsCount: (u.profile.transactions || []).length,
        creditsCount: (u.profile.credits || []).length,
        totalDebt: a.totalDebt,
        netBalance: a.netBalance,
        totalIncome: a.totalIncome,
        totalExpense: a.totalExpense
      };
    });

    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    return res.end(JSON.stringify({
      ok: true,
      system: {
        allowRegistration: db.system.allowRegistration,
        globalBanner: db.system.globalBanner || ''
      },
      users: usersList,
      auditLog: db.auditLog.slice(0, 100)
    }));
  }

  if (pathname === '/api/admin/action' && req.method === 'POST') {
    const db = loadDb();
    const admin = getAuthenticatedUser(req, db, parsedUrl);
    if (!admin || admin.role !== 'admin') {
      res.writeHead(403, { 'Content-Type': 'application/json; charset=utf-8' });
      return res.end(JSON.stringify({ ok: false, error: 'Доступ только для администратора' }));
    }

    return readBodySafe(req, res, db, ip, body => {
      try {
        const payload = JSON.parse(body || '{}');
        const { action, targetUser, allowRegistration, newPassword, newUsername, globalBanner, balanceBonus } = payload;
        const targetKey = String(targetUser || '').toLowerCase();

        if (action === 'toggle_registration') {
          db.system.allowRegistration = !!allowRegistration;
          addAuditLog(db, 'ADMIN_ACTION', 'info', admin.username, ip, `Регистрация новых аккаунтов: ${db.system.allowRegistration ? 'ВКЛ' : 'ВЫКЛ'}`);
        } else if (action === 'set_banner') {
          db.system.globalBanner = sanitizeText(globalBanner || '', 200);
          addAuditLog(db, 'ADMIN_ACTION', 'info', admin.username, ip, db.system.globalBanner ? `Установлен глобальный баннер: "${db.system.globalBanner}"` : 'Глобальный баннер отключён');
        } else if (action === 'create_user') {
          const cleanName = sanitizeText(newUsername || '', 24);
          const uLower = cleanName.toLowerCase();
          if (!cleanName || uLower.length < 3 || db.users[uLower] || isRootAdminUser(uLower)) {
            res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
            return res.end(JSON.stringify({ ok: false, error: 'Логин некорректен или уже занят' }));
          }
          const salt = crypto.randomBytes(16).toString('hex');
          db.users[uLower] = {
            id: 'usr_' + Date.now(),
            username: cleanName,
            usernameLower: uLower,
            role: 'user',
            salt,
            passwordHash: hashPassword(String(newPassword || '123456'), salt),
            shortcutToken: 'fp_' + crypto.randomBytes(10).toString('hex'),
            banned: false,
            createdAt: new Date().toISOString(),
            lastLoginAt: null,
            profile: getCleanUserProfile()
          };
          addAuditLog(db, 'ADMIN_ACTION', 'info', admin.username, ip, `Админ создал пользователя ${cleanName}`);
        } else if (action === 'change_password' && db.users[targetKey] && db.users[targetKey].role !== 'admin') {
          const salt = crypto.randomBytes(16).toString('hex');
          db.users[targetKey].salt = salt;
          db.users[targetKey].passwordHash = hashPassword(String(newPassword || '123456'), salt);
          addAuditLog(db, 'ADMIN_ACTION', 'warn', admin.username, ip, `Админ сменил пароль пользователю ${targetKey}`);
        } else if (action === 'add_bonus' && db.users[targetKey]) {
          const amt = Number(balanceBonus) || 0;
          if (amt !== 0) {
            db.users[targetKey].profile.transactions.unshift({
              id: 't_' + Date.now(),
              type: amt > 0 ? 'income' : 'expense',
              amount: Math.abs(amt),
              category: 'Корректировка Админа',
              title: amt > 0 ? 'Начисление администратором' : 'Списание администратором',
              date: new Date().toISOString()
            });
            addAuditLog(db, 'ADMIN_ACTION', 'info', admin.username, ip, `Изменён баланс ${targetKey} на ${amt} ₽`);
          }
        } else if (action === 'impersonate' && db.users[targetKey]) {
          const target = db.users[targetKey];
          const impToken = signToken(
            { sub: target.usernameLower, username: target.username, role: target.role, exp: Date.now() + 86400000 },
            db.system.hmacSecret
          );
          addAuditLog(db, 'ADMIN_IMPERSONATE', 'info', admin.username, ip, `Вход в режим просмотра профиля ${target.username}`);
          saveDb(db);
          res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
          return res.end(JSON.stringify({
            ok: true,
            impersonateSession: {
              token: impToken,
              username: target.username,
              usernameLower: target.usernameLower,
              role: target.role,
              shortcutToken: target.shortcutToken
            }
          }));
        } else if (action === 'unlock_bruteforce') {
          loginAttempts.clear();
          addAuditLog(db, 'ADMIN_ACTION', 'info', admin.username, ip, 'Сброшены все блокировки анти-брутфорса');
        } else if (action === 'ban_toggle' && db.users[targetKey] && db.users[targetKey].role !== 'admin') {
          db.users[targetKey].banned = !db.users[targetKey].banned;
          addAuditLog(db, 'ADMIN_ACTION', 'warn', admin.username, ip, `${db.users[targetKey].banned ? 'Заблокирован' : 'Разблокирован'} пользователь ${targetKey}`);
        } else if (action === 'reset_user' && db.users[targetKey]) {
          db.users[targetKey].profile = getCleanUserProfile();
          addAuditLog(db, 'ADMIN_ACTION', 'warn', admin.username, ip, `Сброшены финансовые данные пользователя ${targetKey}`);
        } else if (action === 'delete_user' && db.users[targetKey] && db.users[targetKey].role !== 'admin') {
          delete db.users[targetKey];
          addAuditLog(db, 'ADMIN_ACTION', 'high', admin.username, ip, `Удалён аккаунт ${targetKey}`);
        } else if (action === 'clear_logs') {
          db.auditLog = [];
          addAuditLog(db, 'ADMIN_ACTION', 'info', admin.username, ip, 'Журнал безопасности очищен администратором');
        }

        saveDb(db);
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        return res.end(JSON.stringify({ ok: true }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
        return res.end(JSON.stringify({ ok: false, error: e.message }));
      }
    });
  }

  // 7. iPhone Shortcut Webhook
  if (pathname === '/api/shortcut') {
    const db = loadDb();
    return readBodySafe(req, res, db, ip, body => {
      const tokenParam = parsedUrl.searchParams.get('token') || '';
      const userParam = (parsedUrl.searchParams.get('user') || '').toLowerCase();

      let targetUser = Object.values(db.users).find(u => tokenParam && u.shortcutToken === tokenParam) || db.users[userParam];
      if (!targetUser || targetUser.banned) {
        res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
        return res.end('Доступ запрещён');
      }

      let queryText = parsedUrl.searchParams.get('q') || parsedUrl.searchParams.get('text') || '';
      if (body) {
        try {
          const json = JSON.parse(body);
          if (json.text || json.q) queryText = json.text || json.q;
        } catch (e) {
          if (!queryText) queryText = body.trim();
        }
      }

      queryText = sanitizeText(queryText, 200);
      const profile = targetUser.profile;
      const cur = (profile.settings && profile.settings.currency) || '₽';
      const fmt = n => Number(n).toLocaleString('ru-RU') + ' ' + cur;

      const lowerQ = queryText.toLowerCase();
      if (!queryText || ['сводка', 'баланс', 'статус', 'кредиты', 'отчет', 'отчёт'].includes(lowerQ)) {
        const analytics = calculateAnalytics(profile);
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        return res.end(`FinPulse (${targetUser.username})\n\n${buildBriefingText(profile, analytics)}`);
      }

      const added = parseSmartInput(queryText);
      if (added.length > 0) {
        profile.transactions.unshift(...added);
        saveDb(db);
        const analytics = calculateAnalytics(profile);
        const addedLines = added.map(t => `${t.type === 'income' ? '+' : '−'}${fmt(t.amount)} (${t.title} • ${t.category})`).join('\n');
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        return res.end(`Записано (${targetUser.username}):\n${addedLines}\n\nСвободно: ${fmt(analytics.freeMoneyAfterCredits)}\nЛимит на день: ${fmt(analytics.safeDailyLimit)}`);
      }

      const analytics = calculateAnalytics(profile);
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end(`FinPulse (${targetUser.username})\n\n${buildBriefingText(profile, analytics)}`);
    });
  }

  // Static files
  if ((pathname === '/api/credits.ics' || pathname === '/credits.ics') && req.method === 'GET') {
    const icsPath = path.join(__dirname, 'credits.ics');
    if (fs.existsSync(icsPath)) {
      res.writeHead(200, {
        'Content-Type': 'text/calendar; charset=utf-8',
        'Content-Disposition': 'attachment; filename="credits-reminders.ics"'
      });
      return res.end(fs.readFileSync(icsPath, 'utf8'));
    }
  }

  if (pathname === '/' || pathname === '/index.html') {
    const htmlPath = path.join(__dirname, 'index.html');
    if (fs.existsSync(htmlPath)) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(fs.readFileSync(htmlPath, 'utf8'));
    }
  }

  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('Not found');
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`FinPulse Hardened Multi-User Server running on http://0.0.0.0:${PORT}`);
});
