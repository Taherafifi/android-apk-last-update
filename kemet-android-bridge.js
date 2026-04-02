/**
 * KEMET POS - Android Bridge
 * Replaces Electron preload.js for Capacitor/Android
 * Runs before kemet_qr3.html scripts
 */

(function () {
  'use strict';

  // ═══════════════════════════════════════════
  //  Ed25519 Public Key (same as Electron keys/public.pem)
  // ═══════════════════════════════════════════
  const PUBLIC_KEY_B64 = 'MCowBQYDK2VwAyEAb/y/kKQbEf/TninitGdy1WL/+VCndl5SZn7x1LBpv0I=';

  // ═══════════════════════════════════════════
  //  Helpers
  // ═══════════════════════════════════════════
  function b64ToBytes(b64) {
    const bin = atob(b64.replace(/-/g, '+').replace(/_/g, '/'));
    return Uint8Array.from(bin, c => c.charCodeAt(0));
  }

  async function sha256Hex(str) {
    const data = new TextEncoder().encode(str);
    const buf = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function getCapPlugin(name) {
    return window.Capacitor && window.Capacitor.Plugins && window.Capacitor.Plugins[name];
  }

  function isNative() {
    return !!(window.Capacitor && window.Capacitor.isNativePlatform && window.Capacitor.isNativePlatform());
  }

  // ═══════════════════════════════════════════
  //  Device ID → Android HWID (32 hex chars)
  // ═══════════════════════════════════════════
  async function getAndroidHWID() {
    let deviceId = 'android-fallback';
    try {
      const Device = getCapPlugin('Device');
      if (Device) {
        const info = await Device.getId();
        deviceId = info.identifier || info.uuid || 'android-fallback';
      }
    } catch (e) { /* fallback */ }

    const hash = await sha256Hex('KEMET_POS_HWID|' + deviceId);
    return hash.substring(0, 32).toUpperCase();
  }

  function hwidToMachineCode(hwid) {
    return hwid.match(/.{4}/g).join('-');
  }

  // ═══════════════════════════════════════════
  //  Encrypted State Storage (Capacitor Preferences)
  // ═══════════════════════════════════════════
  const PREF_KEY = 'kemet_license_state';

  async function getStateKey(hwid) {
    const keyData = new TextEncoder().encode('KEMET_STATE_KEY|' + hwid);
    const hashBuf = await crypto.subtle.digest('SHA-256', keyData);
    return crypto.subtle.importKey('raw', hashBuf, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  }

  async function encryptState(state, hwid) {
    const key = await getStateKey(hwid);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = new TextEncoder().encode(JSON.stringify(state));
    const enc = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
    const combined = new Uint8Array(12 + enc.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(enc), 12);
    return btoa(String.fromCharCode(...combined));
  }

  async function decryptState(b64, hwid) {
    try {
      const key = await getStateKey(hwid);
      const combined = b64ToBytes(b64);
      const iv = combined.subarray(0, 12);
      const enc = combined.subarray(12);
      const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, enc);
      return JSON.parse(new TextDecoder().decode(dec));
    } catch (e) {
      return null;
    }
  }

  async function loadState(hwid) {
    try {
      const Prefs = getCapPlugin('Preferences');
      if (Prefs) {
        const { value } = await Prefs.get({ key: PREF_KEY });
        if (value) return await decryptState(value, hwid);
      } else {
        const val = localStorage.getItem(PREF_KEY);
        if (val) return await decryptState(val, hwid);
      }
    } catch (e) { /* */ }
    return null;
  }

  async function saveState(state, hwid) {
    const enc = await encryptState(state, hwid);
    try {
      const Prefs = getCapPlugin('Preferences');
      if (Prefs) {
        await Prefs.set({ key: PREF_KEY, value: enc });
      } else {
        localStorage.setItem(PREF_KEY, enc);
      }
    } catch (e) { /* */ }
  }

  // ═══════════════════════════════════════════
  //  Ed25519 Signature Verification (Web Crypto)
  // ═══════════════════════════════════════════
  async function verifySignature(payload, signature) {
    try {
      const keyBytes = b64ToBytes(PUBLIC_KEY_B64);
      const pubKey = await crypto.subtle.importKey(
        'spki', keyBytes.buffer,
        { name: 'Ed25519' }, false, ['verify']
      );
      return await crypto.subtle.verify('Ed25519', pubKey, signature, payload);
    } catch (e) {
      console.error('[License] Verify error:', e);
      return false;
    }
  }

  // ═══════════════════════════════════════════
  //  kemetLicense — Android Implementation
  // ═══════════════════════════════════════════
  async function getMachineCode() {
    const hwid = await getAndroidHWID();
    return hwidToMachineCode(hwid);
  }

  async function checkLicense() {
    const hwid = await getAndroidHWID();
    const state = await loadState(hwid);

    if (!state || !state.activated) {
      return { valid: false, reason: 'not_activated' };
    }
    if (state.tamperDetected) {
      return { valid: false, reason: 'tamper_detected' };
    }
    if (state.remoteBlocked) {
      return { valid: false, reason: 'remote_blocked', message: state.remoteBlockMessage || '' };
    }

    const now = Date.now();

    // Anti-tamper: backward time
    if (now < state.lastTimestamp - 300000) {
      state.tamperDetected = true;
      await saveState(state, hwid);
      return { valid: false, reason: 'tamper_detected' };
    }

    // Expiry check
    if (state.licenseType !== 'lifetime') {
      if (state.expiryTimestamp && now > state.expiryTimestamp) {
        return { valid: false, reason: 'expired', type: state.licenseType };
      }
      const maxRuntimeMinutes = (state.expiryDays || 30) * 24 * 60;
      if (state.totalRuntimeMinutes > maxRuntimeMinutes) {
        return { valid: false, reason: 'expired', type: state.licenseType };
      }
    }

    state.lastTimestamp = now;
    await saveState(state, hwid);

    const daysRemaining = state.licenseType === 'lifetime'
      ? -1
      : Math.max(0, Math.ceil((state.expiryTimestamp - now) / 86400000));

    const msRemaining = state.licenseType === 'lifetime'
      ? -1
      : Math.max(0, state.expiryTimestamp - now);

    return {
      valid: true,
      type: state.licenseType,
      expiryDays: state.expiryDays,
      expiryTimestamp: state.expiryTimestamp || 0,
      daysRemaining,
      msRemaining,
      clientName: state.clientName || ''
    };
  }

  async function activate(activationCode) {
    try {
      const hwid = await getAndroidHWID();
      const clean = activationCode.replace(/[\s\r\n]/g, '');
      const buf = b64ToBytes(clean);

      if (buf.length < 68) return { success: false, error: 'كود التفعيل قصير جداً' };

      const payloadLen = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
      if (payloadLen < 10 || payloadLen > buf.length - 68) {
        return { success: false, error: 'كود التفعيل غير صالح' };
      }

      const payload = buf.subarray(4, 4 + payloadLen);
      const signature = buf.subarray(4 + payloadLen);

      const valid = await verifySignature(payload, signature);
      if (!valid) return { success: false, error: 'كود التفعيل غير صالح أو مزور' };

      const data = JSON.parse(new TextDecoder().decode(payload));

      if (data.hwid !== hwid) {
        return { success: false, error: 'كود التفعيل مخصص لجهاز آخر' };
      }

      const existingState = await loadState(hwid) || {};
      const usedNonces = existingState.usedNonces || [];
      // Keep only last 3 nonces — allow reactivation with same code after reinstall
      if (usedNonces.includes(data.nonce) && usedNonces.length > 3) {
        return { success: false, error: 'كود التفعيل مستخدم بالفعل' };
      }

      const now = Date.now();
      const newState = {
        activated: true,
        licenseType: data.type,
        activatedAt: now,
        lastTimestamp: now,
        expiryDays: data.expiryDays || 0,
        expiryTimestamp: data.type === 'lifetime' ? 0 : (now + (data.expiryDays || 30) * 86400000),
        totalRuntimeMinutes: 0,
        launchCount: 1,
        tamperDetected: false,
        usedNonces: [...usedNonces, data.nonce],
        clientName: data.clientName || ''
      };

      await saveState(newState, hwid);

      const typeLabel = data.type === 'lifetime' ? 'مدى الحياة' :
        data.type === 'trial' ? 'نسخة تجريبية' : 'مؤقت';

      let durationLabel = '';
      if (data.type !== 'lifetime') {
        const d = data.expiryDays;
        if (d >= 30 && d % 30 === 0) durationLabel = `${Math.round(d / 30)} شهر`;
        else if (d >= 1) durationLabel = `${Math.round(d)} يوم`;
        else if (d * 24 >= 1) durationLabel = `${Math.round(d * 24)} ساعة`;
        else durationLabel = `${Math.round(d * 1440)} دقيقة`;
      }

      const expiryDate = data.type === 'lifetime' ? '' :
        new Date(newState.expiryTimestamp).toLocaleDateString('ar-EG', {
          year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit'
        });

      return {
        success: true,
        type: data.type, typeLabel, durationLabel, expiryDate,
        expiryTimestamp: newState.expiryTimestamp,
        message: `تم التفعيل بنجاح ✅ (${typeLabel}${durationLabel ? ' - ' + durationLabel : ''})`
      };
    } catch (e) {
      return { success: false, error: 'خطأ في معالجة كود التفعيل' };
    }
  }

  async function updateRuntime() {
    const hwid = await getAndroidHWID();
    const state = await loadState(hwid);
    if (!state || !state.activated) return;
    const now = Date.now();
    if (now < state.lastTimestamp - 300000) {
      state.tamperDetected = true;
    } else {
      state.totalRuntimeMinutes = (state.totalRuntimeMinutes || 0) + 1;
      state.lastTimestamp = now;
    }
    await saveState(state, hwid);
  }

  window.kemetLicense = { getMachineCode, checkLicense, activate, updateRuntime, remoteCheck, reportDevice };

  // ═══════════════════════════════════════════
  //  Remote Blocklist Check (fetch from GitHub Gist)
  // ═══════════════════════════════════════════
  async function remoteCheck(url) {
    if (!url) return { blocked: false };
    try {
      // Cache-bust GitHub CDN by appending timestamp
      const bustUrl = url + (url.includes('?') ? '&' : '?') + '_t=' + Date.now();
      const resp = await fetch(bustUrl, { cache: 'no-store' });
      if (!resp.ok) return { blocked: false, offline: true };
      const json = await resp.json();
      const hwid = await getAndroidHWID();
      const blocked = Array.isArray(json.blocked) && json.blocked.map(h => h.toUpperCase().replace(/-/g, '')).includes(hwid);
      const message = json.messages && json.messages[hwid] ? json.messages[hwid] : '';

      const state = await loadState(hwid);
      if (!state || !state.activated) return { blocked: false };

      if (blocked) {
        state.remoteBlocked = true;
        state.remoteBlockMessage = message || 'تم إيقاف الترخيص عن بعد. تواصل مع المطور.';
        await saveState(state, hwid);
        return { blocked: true, message: state.remoteBlockMessage };
      } else {
        if (state.remoteBlocked) {
          state.remoteBlocked = false;
          state.remoteBlockMessage = '';
          await saveState(state, hwid);
        }
        return { blocked: false };
      }
    } catch (e) {
      return { blocked: false, offline: true };
    }
  }

  // ═══════════════════════════════════════════
  //  Device Reporting (patch GitHub Gist)
  // ═══════════════════════════════════════════
  async function reportDevice(gistId, token) {
    if (!gistId || !token) return;
    const hwid = await getAndroidHWID();
    const state = await loadState(hwid);
    if (!state || !state.activated) return;

    const now = Date.now();
    const daysRemaining = state.licenseType === 'lifetime' ? -1
      : Math.max(0, Math.ceil((state.expiryTimestamp - now) / 86400000));

    const Device = getCapPlugin('Device');
    let deviceName = 'Android', platform = 'android';
    try {
      if (Device) {
        const info = await Device.getInfo();
        deviceName = (info.manufacturer || '') + ' ' + (info.model || '');
        platform = info.operatingSystem + ' ' + info.osVersion;
      }
    } catch(e) {}

    const info = {
      hwid: hwidToMachineCode(hwid),
      clientName: state.clientName || '',
      computerName: deviceName,
      platform,
      licenseType: state.licenseType,
      activatedAt: state.activatedAt,
      expiryTimestamp: state.expiryTimestamp || 0,
      expiryDays: state.expiryDays || 0,
      daysRemaining,
      totalRuntimeMinutes: state.totalRuntimeMinutes || 0,
      launchCount: state.launchCount || 1,
      lastOnline: new Date().toISOString(),
      appType: 'android'
    };

    // Get IP/location
    try {
      const geo = await fetch('http://ip-api.com/json/?fields=query,city,regionName,country,isp', { signal: AbortSignal.timeout(5000) }).then(r => r.json());
      info.ip = geo.query || ''; info.city = geo.city || ''; info.region = geo.regionName || ''; info.country = geo.country || ''; info.isp = geo.isp || '';
    } catch(e) { info.ip = ''; }

    const fileName = 'device_' + hwid + '.json';
    try {
      await fetch('https://api.github.com/gists/' + gistId, {
        method: 'PATCH',
        headers: { 'Authorization': 'token ' + token, 'User-Agent': 'KEMET-POS-Android', 'Content-Type': 'application/json' },
        body: JSON.stringify({ files: { [fileName]: { content: JSON.stringify(info, null, 2) } } })
      });
    } catch(e) { /* silent */ }
  }

  // ═══════════════════════════════════════════
  //  kemetShell — Open External URLs
  // ═══════════════════════════════════════════
  window.kemetShell = {
    openExternal: async (url) => {
      try {
        // For tel:, mailto:, whatsapp links — use intent-based navigation on Android
        if (url.startsWith('tel:') || url.startsWith('mailto:') || url.indexOf('wa.me') !== -1 || url.indexOf('whatsapp') !== -1) {
          window.location.href = url.startsWith('tel:') || url.startsWith('mailto:') ? url : 'intent://' + url.replace(/^https?:\/\//, '') + '#Intent;scheme=https;package=com.whatsapp;end';
          return;
        }
        const Browser = getCapPlugin('Browser');
        if (Browser) await Browser.open({ url });
        else window.open(url, '_blank');
      } catch (e) {
        window.open(url, '_blank');
      }
    }
  };

  // ═══════════════════════════════════════════
  //  kemetUpdater — OTA Update System for Android
  //  Fetches update from GitHub Gist, injects Android scripts, applies
  // ═══════════════════════════════════════════
  // OTA عبر GitHub Repo مباشر (android-apk)
  const OTA_REPO_RAW_BASE = 'https://raw.githubusercontent.com/Taherafifi/android-apk-last-update/main/';
  const OTA_INFO_URL = OTA_REPO_RAW_BASE + 'update_info.json';
  const OTA_HTML_URL = OTA_REPO_RAW_BASE + 'index.html';
  const OTA_FILE_KEY = 'kemet_ota_version';
  const OTA_HTML_PATH = 'kemet_ota.html';

  window.kemetUpdater = {
    getVersion: async () => {
      try {
        const Prefs = getCapPlugin('Preferences');
        if (Prefs) {
          const { value } = await Prefs.get({ key: OTA_FILE_KEY });
          if (value) return value;
        }
        const App = getCapPlugin('App');
        if (App) {
          const info = await App.getInfo();
          return info.version;
        }
      } catch (e) { /* */ }
      return '1.0.0';
    },

    checkUpdate: async () => {
      try {
        const resp = await fetch(OTA_INFO_URL + '?_t=' + Date.now(), { cache: 'no-store' });
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        const info = await resp.json();

        const currentVer = await window.kemetUpdater.getVersion();
        const cur = currentVer.split('.').map(Number);
        const rem = info.version.split('.').map(Number);
        let newer = false;
        for (let i = 0; i < 3; i++) {
          if ((rem[i] || 0) > (cur[i] || 0)) { newer = true; break; }
          if ((rem[i] || 0) < (cur[i] || 0)) break;
        }

        if (!newer) return { available: false, message: 'أنت على آخر إصدار ✅ (' + currentVer + ')' };

        return {
          available: true,
          version: info.version,
          changelog: info.changelog || '',
          message: 'يوجد تحديث جديد: الإصدار ' + info.version
        };
      } catch (e) {
        console.warn('[OTA] checkUpdate error:', e);
        const _oErr = document.getElementById('kemet-ota-err');
        if (_oErr) _oErr.remove();
        const _eOv = document.createElement('div');
        _eOv.id = 'kemet-ota-err';
        _eOv.style.cssText = 'position:fixed;inset:0;z-index:100001;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;font-family:Cairo,sans-serif';
        const _eBx = document.createElement('div');
        _eBx.style.cssText = 'background:linear-gradient(135deg,#7f1d1d,#991b1b);border:1px solid #f87171;border-radius:16px;padding:28px 32px;max-width:360px;width:88%;color:#fff;text-align:center;direction:rtl';
        _eBx.innerHTML = '<div style="font-size:38px;margin-bottom:10px">⚠️</div>'
          + '<div style="font-size:16px;font-weight:700;margin-bottom:8px">تعذّر التحقّق من التحديثات</div>'
          + '<div style="font-size:13px;opacity:.85;margin-bottom:16px">تحقّق من الاتصال بالإنترنت ثم حاول مرة أخرى</div>'
          + '<button onclick="document.getElementById(\'kemet-ota-err\').remove()" style="padding:8px 28px;border:none;border-radius:8px;background:rgba(255,255,255,.2);color:#fff;font-family:Cairo,sans-serif;font-size:14px;font-weight:700;cursor:pointer">حسناً</button>';
        _eOv.appendChild(_eBx);
        document.body.appendChild(_eOv);
        _eOv.onclick = (ev) => { if (ev.target === _eOv) _eOv.remove(); };
        setTimeout(() => { if (_eOv.parentNode) _eOv.remove(); }, 6000);
        return { available: false, error: true, message: 'تعذّر التحقّق من التحديثات' };
      }
    },

    showUpdateDialog: (version, changelog) => {
      return new Promise(resolve => {
        const old = document.getElementById('kemet-update-dialog');
        if (old) old.remove();
        const ov = document.createElement('div');
        ov.id = 'kemet-update-dialog';
        ov.style.cssText = 'position:fixed;inset:0;z-index:100000;background:rgba(0,0,0,.7);display:flex;align-items:center;justify-content:center;font-family:Cairo,sans-serif';
        const bx = document.createElement('div');
        bx.style.cssText = 'background:linear-gradient(135deg,#1e3a5f,#1a237e);border:1px solid #42a5f5;border-radius:16px;padding:28px;max-width:420px;width:88%;color:#fff;text-align:center;direction:rtl';
        bx.innerHTML = '<div style="font-size:42px;margin-bottom:10px">\u{1F504}</div>'
          + '<div style="font-size:18px;font-weight:700;margin-bottom:8px">\u062A\u062D\u062F\u064A\u062B \u062C\u062F\u064A\u062F \u0645\u062A\u0627\u062D</div>'
          + '<div style="font-size:15px;opacity:.9;margin-bottom:4px">\u0627\u0644\u0625\u0635\u062F\u0627\u0631 ' + version + '</div>'
          + (changelog ? (function(cl){
              const lines = cl.split('\n').filter(l => l.trim());
              const items = lines.map(l => '<div style="display:flex;align-items:flex-start;gap:6px;margin:3px 0"><span style="color:#4ade80;flex-shrink:0;font-size:16px">&#x2022;</span><span>' + l.replace(/^[•\-\*]\s*/,'') + '</span></div>').join('');
              return '<div style="font-size:13px;opacity:.9;margin:10px 0;padding:10px 12px;background:rgba(255,255,255,.08);border-radius:8px;text-align:right;max-height:150px;overflow-y:auto;line-height:1.9">' + items + '</div>';
            })(changelog) : '')
          + '<div style="display:flex;gap:12px;justify-content:center;margin-top:18px">'
          + '<button id="kemet-upd-yes" style="padding:10px 28px;border:none;border-radius:8px;background:#4caf50;color:#fff;font-family:Cairo,sans-serif;font-size:14px;font-weight:700;cursor:pointer">\u062A\u062D\u062F\u064A\u062B \u0627\u0644\u0622\u0646</button>'
          + '<button id="kemet-upd-no" style="padding:10px 28px;border:none;border-radius:8px;background:rgba(255,255,255,.18);color:#fff;font-family:Cairo,sans-serif;font-size:14px;font-weight:700;cursor:pointer">\u0644\u0627\u062D\u0642\u0627\u064B</button>'
          + '</div>';
        ov.appendChild(bx);
        document.body.appendChild(ov);
        document.getElementById('kemet-upd-yes').onclick = () => { ov.remove(); resolve(true); };
        document.getElementById('kemet-upd-no').onclick  = () => { ov.remove(); resolve(false); };
      });
    },

    applyUpdate: async () => {
      try {
        // Fetch update_info.json
        const infoResp = await fetch(OTA_INFO_URL + '?_t=' + Date.now(), { cache: 'no-store' });
        if (!infoResp.ok) throw new Error('info fetch ' + infoResp.status);
        const info = await infoResp.json();

        // Fetch index.html
        const htmlResp = await fetch(OTA_HTML_URL + '?_t=' + Date.now(), { cache: 'no-store' });
        if (!htmlResp.ok) return { success: false, error: 'ملف التحديث غير موجود' };
        const html = await htmlResp.text();
        if (!html || html.length < 100) {
          return { success: false, error: 'ملف التحديث فارغ أو تالف' };
        }

        // Inject <base href="/"> so scripts resolve from app root when loaded from file URL
        let patchedHtml = html;
        if (patchedHtml.indexOf('<base ') === -1) {
          patchedHtml = patchedHtml.replace('<head>', '<head>\n<base href="/">');
        }

        // Inject Capacitor + Bridge scripts before </head>
        const capInject = '\n<script src="capacitor.js"><\/script>\n<script src="kemet-android-bridge.js"><\/script>\n';
        if (patchedHtml.indexOf('kemet-android-bridge.js') === -1) {
          patchedHtml = patchedHtml.replace('</head>', capInject + '</head>');
        }

        // Save OTA HTML to Filesystem
        const Fs = getCapPlugin('Filesystem');
        const Prefs = getCapPlugin('Preferences');
        if (!Fs || !Prefs) return { success: false, error: 'Filesystem غير متاح' };

        await Fs.writeFile({
          path: OTA_HTML_PATH,
          data: patchedHtml,
          directory: 'DATA',
          encoding: 'utf8'
        });

        // Save version
        await Prefs.set({ key: OTA_FILE_KEY, value: info.version });

        console.log('[OTA] Saved v' + info.version + ', navigating to file…');

        // Navigate to the saved file via Capacitor file URL (preserves native bridge)
        try {
          var uriResult = await Fs.getUri({ path: OTA_HTML_PATH, directory: 'DATA' });
          var webUrl = window.Capacitor.convertFileSrc(uriResult.uri);
          window.location.href = webUrl;
        } catch(navErr) {
          console.warn('[OTA] file navigation failed:', navErr);
        }

        return { success: true, version: info.version };
      } catch (e) {
        console.error('[OTA] applyUpdate failed:', e);
        return { success: false, error: 'فشل التحديث: ' + e.message };
      }
    }
  };

  // ═══════════════════════════════════════════
  //  OTA Startup Loader — Load saved OTA on cold start
  //  Navigates to the saved file via Capacitor file URL
  //  This preserves the native bridge (unlike document.write)
  // ═══════════════════════════════════════════
  (async function _kemetOTAStartup() {
    // Already on OTA file URL — don't redirect again
    if (window.location.href.indexOf('_capacitor_file_') !== -1) return;
    if (!isNative()) return;
    try {
      const Prefs = getCapPlugin('Preferences');
      const Fs    = getCapPlugin('Filesystem');
      if (!Prefs || !Fs) return;

      const { value: ver } = await Prefs.get({ key: OTA_FILE_KEY });
      if (!ver) return;

      // Verify OTA file exists
      await Fs.stat({ path: OTA_HTML_PATH, directory: 'DATA' });

      // Ensure <base href="/"> exists (fix older OTA files saved before this version)
      try {
        var rd = await Fs.readFile({ path: OTA_HTML_PATH, directory: 'DATA', encoding: 'utf8' });
        if (rd.data && rd.data.length > 100 && rd.data.indexOf('<base ') === -1) {
          var fixed = rd.data.replace('<head>', '<head>\n<base href="/">');
          await Fs.writeFile({ path: OTA_HTML_PATH, data: fixed, directory: 'DATA', encoding: 'utf8' });
        }
      } catch(fixErr) { /* ignore fix errors */ }

      var uriResult = await Fs.getUri({ path: OTA_HTML_PATH, directory: 'DATA' });
      var webUrl = window.Capacitor.convertFileSrc(uriResult.uri);
      console.log('[OTA] Cold start: navigating to OTA v' + ver + ' → ' + webUrl);
      window.location.href = webUrl;
    } catch (e) {
      // No OTA file saved — continue with bundled version
    }
  })();

  // ═══════════════════════════════════════════
  //  Override window.open for WhatsApp & external URLs
  // ═══════════════════════════════════════════
  const _origOpen = window.open.bind(window);
  window.open = function (url, target, features) {
    if (isNative() && url && (url.includes('wa.me') || url.includes('whatsapp.com'))) {
      window.kemetShell.openExternal(url);
      return null;
    }
    return _origOpen(url, target, features);
  };

  // ═══════════════════════════════════════════
  //  Override window.print for Android
  //  Note: In Capacitor WebView, the native window.print()
  //  triggers the Android system print dialog (including Save as PDF)
  //  so we do NOT override it — just let it work natively.
  // ═══════════════════════════════════════════

  // ═══════════════════════════════════════════
  //  kemetBackup — Android Filesystem Backup
  //  Uses @capacitor/filesystem to save/read .posb files
  // ═══════════════════════════════════════════
  const BACKUP_DIR = 'KEMET_POS_Backups';

  window.kemetBackup = {
    /**
     * Save a backup file to Documents/KEMET_POS_Backups/
     * @param {string} filename - e.g. "backup_2025-01-15_14-30.posb"
     * @param {ArrayBuffer|Uint8Array} data - raw encrypted bytes
     * @returns {Promise<{success:boolean, path?:string}>}
     */
    saveFile: async (filename, data) => {
      try {
        const Filesystem = getCapPlugin('Filesystem');
        if (!Filesystem) return { success: false, error: 'Filesystem plugin not available' };

        // Ensure directory exists
        try {
          await Filesystem.mkdir({
            path: BACKUP_DIR,
            directory: 'DOCUMENTS',
            recursive: true
          });
        } catch (e) { /* already exists */ }

        // Convert ArrayBuffer/Uint8Array to base64
        const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
        const b64 = btoa(String.fromCharCode(...bytes));

        await Filesystem.writeFile({
          path: BACKUP_DIR + '/' + filename,
          data: b64,
          directory: 'DOCUMENTS'
        });

        console.log('[KemetBackup] Saved:', filename);
        return { success: true, path: BACKUP_DIR + '/' + filename };
      } catch (e) {
        console.error('[KemetBackup] Save failed:', e);
        return { success: false, error: e.message };
      }
    },

    /**
     * List all backup files in Documents/KEMET_POS_Backups/
     * @returns {Promise<Array<{name:string, size:number, mtime:number}>>}
     */
    listFiles: async () => {
      try {
        const Filesystem = getCapPlugin('Filesystem');
        if (!Filesystem) return [];

        // Ensure directory exists
        try {
          await Filesystem.mkdir({
            path: BACKUP_DIR,
            directory: 'DOCUMENTS',
            recursive: true
          });
        } catch (e) { /* already exists */ }

        const result = await Filesystem.readdir({
          path: BACKUP_DIR,
          directory: 'DOCUMENTS'
        });

        const files = [];
        for (const f of (result.files || [])) {
          if (f.name && (f.name.endsWith('.posb') || f.name.endsWith('.json')) && f.name.startsWith('backup_')) {
            // Get file stat for size/mtime
            try {
              const stat = await Filesystem.stat({
                path: BACKUP_DIR + '/' + f.name,
                directory: 'DOCUMENTS'
              });
              files.push({
                name: f.name,
                size: stat.size || 0,
                mtime: stat.mtime || Date.now(),
                encrypted: f.name.endsWith('.posb')
              });
            } catch (e) {
              files.push({ name: f.name, size: 0, mtime: 0, encrypted: f.name.endsWith('.posb') });
            }
          }
        }

        // Sort newest first
        files.sort((a, b) => b.mtime - a.mtime);
        return files;
      } catch (e) {
        console.warn('[KemetBackup] listFiles failed:', e);
        return [];
      }
    },

    /**
     * Read a backup file and return its ArrayBuffer
     * @param {string} filename
     * @returns {Promise<ArrayBuffer|null>}
     */
    readFile: async (filename) => {
      try {
        const Filesystem = getCapPlugin('Filesystem');
        if (!Filesystem) return null;

        const result = await Filesystem.readFile({
          path: BACKUP_DIR + '/' + filename,
          directory: 'DOCUMENTS'
        });

        // result.data is base64 string
        const b64str = result.data;
        const bin = atob(b64str);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        return bytes.buffer;
      } catch (e) {
        console.error('[KemetBackup] readFile failed:', e);
        return null;
      }
    },

    /**
     * Delete a backup file
     * @param {string} filename
     * @returns {Promise<boolean>}
     */
    deleteFile: async (filename) => {
      try {
        const Filesystem = getCapPlugin('Filesystem');
        if (!Filesystem) return false;
        await Filesystem.deleteFile({
          path: BACKUP_DIR + '/' + filename,
          directory: 'DOCUMENTS'
        });
        return true;
      } catch (e) {
        console.warn('[KemetBackup] deleteFile failed:', e);
        return false;
      }
    },

    /**
     * Share a backup file via Android share sheet
     * @param {string} filename
     * @returns {Promise<boolean>}
     */
    shareFile: async (filename) => {
      try {
        const Filesystem = getCapPlugin('Filesystem');
        const Share = getCapPlugin('Share');
        if (!Filesystem || !Share) return false;

        const uri = await Filesystem.getUri({
          path: BACKUP_DIR + '/' + filename,
          directory: 'DOCUMENTS'
        });

        await Share.share({
          title: 'KEMET POS Backup',
          url: uri.uri,
          dialogTitle: 'مشاركة النسخة الاحتياطية'
        });
        return true;
      } catch (e) {
        console.warn('[KemetBackup] shareFile failed:', e);
        return false;
      }
    },

    /** Check if Android filesystem backup is available */
    isAvailable: () => !!getCapPlugin('Filesystem') && isNative()
  };

  console.log('[KemetAndroid] Bridge loaded ✅');
})();
