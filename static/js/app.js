/**
 * MCP Kali Server — Dashboard Application
 *
 * Vanilla ES6+ · IIFE pattern · Event delegation
 * Keyboard navigable · Accessible announcements
 * Debounced inputs · Clean state management
 */
; (function () {
    'use strict';

    /* ═══════════════════════════════
       TOOL DEFINITIONS
       ═══════════════════════════════ */
    const TOOLS = {
        nmap: {
            title: 'Nmap Scanner',
            category: 'Reconnaissance',
            endpoint: '/api/tools/nmap',
            method: 'POST',
            description: 'Network exploration and security auditing. Discovers hosts, services, OS versions, and vulnerabilities on a network.',
            fields: [
                { name: 'target', label: 'Target', placeholder: '192.168.1.1 or example.com', required: true },
                { name: 'scan_type', label: 'Scan Type', type: 'select', options: ['-sV', '-sCV', '-sS', '-sT', '-sU', '-sA', '-sP', '-sn'], value: '-sCV' },
                { name: 'ports', label: 'Ports', placeholder: '22,80,443 or 1-1000' },
                { name: 'additional_args', label: 'Additional Args', placeholder: '-T4 -Pn --script=vuln', value: '-T4 -Pn' }
            ]
        },
        gobuster: {
            title: 'Gobuster',
            category: 'Reconnaissance',
            endpoint: '/api/tools/gobuster',
            method: 'POST',
            description: 'Directory/file, DNS subdomain, and virtual host brute-forcing tool.',
            fields: [
                { name: 'url', label: 'Target URL', placeholder: 'http://example.com', required: true },
                { name: 'mode', label: 'Mode', type: 'select', options: ['dir', 'dns', 'fuzz', 'vhost'], value: 'dir' },
                { name: 'wordlist', label: 'Wordlist', placeholder: '/usr/share/wordlists/dirb/common.txt', value: '/usr/share/wordlists/dirb/common.txt' },
                { name: 'additional_args', label: 'Additional Args', placeholder: '-t 50 -x php,html' }
            ]
        },
        dirb: {
            title: 'Dirb Scanner',
            category: 'Reconnaissance',
            endpoint: '/api/tools/dirb',
            method: 'POST',
            description: 'Web content scanner that looks for existing and hidden web objects.',
            fields: [
                { name: 'url', label: 'Target URL', placeholder: 'http://example.com', required: true },
                { name: 'wordlist', label: 'Wordlist', value: '/usr/share/wordlists/dirb/common.txt' },
                { name: 'additional_args', label: 'Additional Args', placeholder: '-o output.txt' }
            ]
        },
        nikto: {
            title: 'Nikto Scanner',
            category: 'Reconnaissance',
            endpoint: '/api/tools/nikto',
            method: 'POST',
            description: 'Tests web servers for dangerous files, outdated software, and known vulnerabilities.',
            fields: [
                { name: 'target', label: 'Target', placeholder: 'http://example.com', required: true },
                { name: 'additional_args', label: 'Additional Args', placeholder: '-ssl -Tuning x' }
            ]
        },
        wpscan: {
            title: 'WPScan',
            category: 'Reconnaissance',
            endpoint: '/api/tools/wpscan',
            method: 'POST',
            description: 'WordPress vulnerability scanner — checks themes, plugins, and core.',
            fields: [
                { name: 'url', label: 'WordPress URL', placeholder: 'http://example.com/wp', required: true },
                { name: 'additional_args', label: 'Additional Args', placeholder: '--enumerate u,p,t' }
            ]
        },
        enum4linux: {
            title: 'Enum4linux',
            category: 'Reconnaissance',
            endpoint: '/api/tools/enum4linux',
            method: 'POST',
            description: 'Windows and Samba enumeration tool for shares, users, and groups.',
            fields: [
                { name: 'target', label: 'Target IP', placeholder: '192.168.1.100', required: true },
                { name: 'additional_args', label: 'Additional Args', value: '-a', placeholder: '-a (full enumeration)' }
            ]
        },
        sqlmap: {
            title: 'SQLMap',
            category: 'Exploitation',
            endpoint: '/api/tools/sqlmap',
            method: 'POST',
            description: 'Automatic SQL injection detection and database takeover tool.',
            fields: [
                { name: 'url', label: 'Target URL', placeholder: 'http://example.com/page?id=1', required: true },
                { name: 'data', label: 'POST Data', placeholder: 'username=test&password=test' },
                { name: 'additional_args', label: 'Additional Args', placeholder: '--dbs --level=5' }
            ]
        },
        metasploit: {
            title: 'Metasploit',
            category: 'Exploitation',
            endpoint: '/api/tools/metasploit',
            method: 'POST',
            description: 'Advanced exploit framework for penetration testing and module execution.',
            fields: [
                { name: 'module', label: 'Module Path', placeholder: 'exploit/multi/handler', required: true },
                { name: 'options', label: 'Options (JSON)', placeholder: '{"RHOSTS":"192.168.1.1","RPORT":"445"}', type: 'json' }
            ]
        },
        hydra: {
            title: 'Hydra',
            category: 'Credential Attacks',
            endpoint: '/api/tools/hydra',
            method: 'POST',
            description: 'Fast online password cracker supporting SSH, FTP, HTTP, RDP, and more.',
            fields: [
                { name: 'target', label: 'Target', placeholder: '192.168.1.1', required: true },
                { name: 'service', label: 'Service', type: 'select', options: ['ssh', 'ftp', 'http-post-form', 'http-get', 'rdp', 'smb', 'telnet', 'mysql', 'postgres', 'vnc'], required: true },
                { name: 'username', label: 'Username', placeholder: 'admin' },
                { name: 'username_file', label: 'Username File', placeholder: '/usr/share/wordlists/usernames.txt' },
                { name: 'password', label: 'Password', placeholder: 'password123' },
                { name: 'password_file', label: 'Password File', placeholder: '/usr/share/wordlists/rockyou.txt' },
                { name: 'additional_args', label: 'Additional Args', placeholder: '-t 4 -V' }
            ]
        },
        john: {
            title: 'John the Ripper',
            category: 'Credential Attacks',
            endpoint: '/api/tools/john',
            method: 'POST',
            description: 'Password cracker with auto-detection for many hash formats.',
            fields: [
                { name: 'hash_file', label: 'Hash File', placeholder: '/tmp/hashes.txt', required: true },
                { name: 'wordlist', label: 'Wordlist', value: '/usr/share/wordlists/rockyou.txt' },
                { name: 'format', label: 'Format Type', placeholder: 'raw-md5, sha256, bcrypt' },
                { name: 'additional_args', label: 'Additional Args', placeholder: '--rules --fork=4' }
            ]
        },
        health: {
            title: 'Health Check',
            category: 'System',
            endpoint: '/health',
            method: 'GET',
            description: 'Check server status and verify tool availability.',
            fields: []
        },
        aichat: {
            title: 'AI Chat',
            category: 'System',
            endpoint: '/api/chat',
            method: 'POST',
            description: 'Chat with an AI assistant that can orchestrate Kali security tools.',
            fields: []
        }
    };

    /* ═══════════════════════════════
       STATE
       ═══════════════════════════════ */
    var savedSettings = {};
    try { savedSettings = JSON.parse(localStorage.getItem('mcpKaliAI') || '{}'); } catch (e) { }

    const state = {
        currentTool: 'nmap',
        scanCount: 0,
        isRunning: false,
        welcomeVisible: true,
        sidebarOpen: false,
        chatMessages: [],
        chatBusy: false,
        aiProvider: savedSettings.provider || '',
        aiApiKey: savedSettings.apiKey || '',
        aiModel: savedSettings.model || '',
        providers: {}
    };

    /* ═══════════════════════════════
       DOM REFERENCES
       ═══════════════════════════════ */
    const el = {
        pageTitle: document.getElementById('pageTitle'),
        pageBadge: document.getElementById('pageBadge'),
        formFields: document.getElementById('formFields'),
        formLegend: document.getElementById('formLegend'),
        toolForm: document.getElementById('toolForm'),
        toolTitle: document.getElementById('toolTitle'),
        toolDescription: document.getElementById('toolDescription'),
        submitBtn: document.getElementById('submitBtn'),
        terminalContent: document.getElementById('terminalContent'),
        clearOutputBtn: document.getElementById('clearOutputBtn'),
        copyOutputBtn: document.getElementById('copyOutputBtn'),
        expandOutputBtn: document.getElementById('expandOutputBtn'),
        scanCount: document.getElementById('scanCount'),
        statusDot: document.getElementById('statusDot'),
        statusText: document.getElementById('statusText'),
        mobileMenuBtn: document.getElementById('mobileMenuBtn'),
        sidebar: document.getElementById('sidebar'),
        sidebarOverlay: document.getElementById('sidebarOverlay'),
        outputPanel: document.getElementById('outputPanel'),
        toastContainer: document.getElementById('toastContainer'),
        srAnnounce: document.getElementById('srAnnounce'),
        toolNav: document.getElementById('toolNav'),
        // Chat
        chatPanel: document.getElementById('chatPanel'),
        chatMessages: document.getElementById('chatMessages'),
        chatForm: document.getElementById('chatForm'),
        chatInput: document.getElementById('chatInput'),
        chatSendBtn: document.getElementById('chatSendBtn'),
        contentGrid: document.querySelector('.content'),
        toolPanel: document.getElementById('toolPanel'),
        // Settings
        settingsBtn: document.getElementById('settingsBtn'),
        settingsOverlay: document.getElementById('settingsOverlay'),
        settingsCloseBtn: document.getElementById('settingsCloseBtn'),
        settingsProvider: document.getElementById('settingsProvider'),
        settingsApiKey: document.getElementById('settingsApiKey'),
        settingsModel: document.getElementById('settingsModel'),
        settingsSaveBtn: document.getElementById('settingsSaveBtn'),
        apiKeyGroup: document.getElementById('apiKeyGroup'),
        settingsCustomModel: document.getElementById('settingsCustomModel'),
        chatDiscoverBtn: document.getElementById('chatDiscoverBtn'),
        welcomeDiscoverBtn: document.getElementById('welcomeDiscoverBtn'),
        chatActivityBar: document.getElementById('chatActivityBar'),
        chatActivityText: document.getElementById('chatActivityText')
    };

    /* ═══════════════════════════════
       UTILITIES
       ═══════════════════════════════ */
    function escapeHtml(text) {
        const d = document.createElement('div');
        d.textContent = text;
        return d.innerHTML;
    }

    function announce(msg) {
        if (el.srAnnounce) {
            el.srAnnounce.textContent = '';
            requestAnimationFrame(function () { el.srAnnounce.textContent = msg; });
        }
    }

    function showToast(msg) {
        var existing = el.toastContainer.querySelector('.toast');
        if (existing) existing.remove();

        var toast = document.createElement('div');
        toast.className = 'toast';
        toast.textContent = msg;
        el.toastContainer.appendChild(toast);

        setTimeout(function () { if (toast.parentNode) toast.remove(); }, 2600);
    }

    function debounce(fn, ms) {
        var timer;
        return function () {
            var ctx = this, args = arguments;
            clearTimeout(timer);
            timer = setTimeout(function () { fn.apply(ctx, args); }, ms);
        };
    }

    /* ═══════════════════════════════
       INITIALIZATION
       ═══════════════════════════════ */
    function init() {
        bindNavigation();
        bindFormSubmit();
        bindButtons();
        bindMobile();
        bindKeyboard();
        bindSettings();
        bindChat();
        loadProviders();
        selectTool('nmap');
        checkHealth();
        setInterval(checkHealth, 120000); // every 2 minutes
    }

    /* ═══════════════════════════════
       NAVIGATION — Event Delegation
       ═══════════════════════════════ */
    function bindNavigation() {
        el.toolNav.addEventListener('click', function (e) {
            var btn = e.target.closest('.nav-btn');
            if (!btn) return;

            var tool = btn.dataset.tool;
            if (tool) {
                selectTool(tool);
                closeMobileSidebar();
            }
        });
    }

    function selectTool(toolKey) {
        var tool = TOOLS[toolKey];
        if (!tool) return;

        state.currentTool = toolKey;

        // Update active nav button
        var allBtns = el.toolNav.querySelectorAll('.nav-btn');
        allBtns.forEach(function (b) {
            b.classList.remove('nav-btn--active');
            b.removeAttribute('aria-current');
        });

        var activeBtn = el.toolNav.querySelector('[data-tool="' + toolKey + '"]');
        if (activeBtn) {
            activeBtn.classList.add('nav-btn--active');
            activeBtn.setAttribute('aria-current', 'true');
        }

        // Update topbar
        el.pageTitle.textContent = tool.title;
        el.pageBadge.textContent = tool.category;

        // Toggle between chat panel and tool panels
        if (toolKey === 'aichat') {
            el.contentGrid.style.display = 'none';
            el.chatPanel.style.display = 'flex';
            el.chatInput.focus();
        } else {
            el.chatPanel.style.display = 'none';
            el.contentGrid.style.display = 'grid';

            // Update form panel
            el.toolTitle.textContent = toolKey === 'health' ? 'Server Health' : 'Configure Scan';
            el.toolDescription.textContent = tool.description;
            el.formLegend.textContent = tool.title + ' parameters';

            // Update submit button text
            var btnText = el.submitBtn.querySelector('.btn__text');
            btnText.textContent = toolKey === 'health' ? 'Check Health' : 'Launch Scan';

            renderFormFields(tool);
        }
        announce(tool.title + ' selected');
    }

    /* ═══════════════════════════════
       FORM RENDERING
       ═══════════════════════════════ */
    function renderFormFields(tool) {
        // Clear all children except the legend
        while (el.formFields.children.length > 1) {
            el.formFields.removeChild(el.formFields.lastChild);
        }

        if (!tool.fields || tool.fields.length === 0) {
            var emptyMsg = document.createElement('div');
            emptyMsg.className = 'form-empty';
            emptyMsg.textContent = 'No configuration needed. Click the button below to run.';
            el.formFields.appendChild(emptyMsg);
            return;
        }

        tool.fields.forEach(function (field) {
            var group = document.createElement('div');
            group.className = 'form-group';

            // Label
            var label = document.createElement('label');
            label.className = 'form-group__label';
            label.setAttribute('for', 'field-' + field.name);
            label.innerHTML = escapeHtml(field.label) +
                (field.required ? ' <span class="required" aria-hidden="true">*</span>' : '');
            group.appendChild(label);

            // Input / Select
            var input;
            if (field.type === 'select') {
                input = document.createElement('select');
                input.className = 'form-group__select';
                field.options.forEach(function (opt) {
                    var option = document.createElement('option');
                    option.value = opt;
                    option.textContent = opt;
                    if (opt === field.value) option.selected = true;
                    input.appendChild(option);
                });
            } else {
                input = document.createElement('input');
                input.className = 'form-group__input';
                input.type = 'text';
                input.placeholder = field.placeholder || '';
                input.autocomplete = 'off';
                if (field.value) input.value = field.value;
            }

            input.name = field.name;
            input.id = 'field-' + field.name;
            if (field.required) {
                input.required = true;
                input.setAttribute('aria-required', 'true');
            }
            group.appendChild(input);

            // Hint for JSON fields
            if (field.type === 'json') {
                var hint = document.createElement('span');
                hint.className = 'form-group__hint';
                hint.id = 'hint-' + field.name;
                hint.textContent = 'Enter a valid JSON object';
                input.setAttribute('aria-describedby', hint.id);
                group.appendChild(hint);
            }

            // Error message (hidden by default)
            var errorMsg = document.createElement('span');
            errorMsg.className = 'form-group__error';
            errorMsg.id = 'error-' + field.name;
            errorMsg.setAttribute('role', 'alert');
            input.setAttribute('aria-errormessage', errorMsg.id);
            group.appendChild(errorMsg);

            el.formFields.appendChild(group);
        });

        // Focus the first input for convenience
        var firstInput = el.formFields.querySelector('input, select');
        if (firstInput) firstInput.focus();
    }

    /* ═══════════════════════════════
       FORM VALIDATION & SUBMISSION
       ═══════════════════════════════ */
    function validateForm(tool) {
        var valid = true;

        tool.fields.forEach(function (field) {
            var input = document.getElementById('field-' + field.name);
            var group = input ? input.closest('.form-group') : null;
            var errorEl = document.getElementById('error-' + field.name);
            if (!input || !group) return;

            // Reset
            group.classList.remove('form-group--invalid');
            input.removeAttribute('aria-invalid');
            if (errorEl) errorEl.textContent = '';

            // Required check
            if (field.required && !input.value.trim()) {
                group.classList.add('form-group--invalid');
                input.setAttribute('aria-invalid', 'true');
                if (errorEl) errorEl.textContent = field.label + ' is required';
                valid = false;
                return;
            }

            // JSON check
            if (field.type === 'json' && input.value.trim()) {
                try {
                    JSON.parse(input.value.trim());
                } catch (e) {
                    group.classList.add('form-group--invalid');
                    input.setAttribute('aria-invalid', 'true');
                    if (errorEl) errorEl.textContent = 'Invalid JSON format';
                    valid = false;
                }
            }
        });

        return valid;
    }

    function bindFormSubmit() {
        el.toolForm.addEventListener('submit', function (e) {
            e.preventDefault();
            if (state.isRunning) return;

            var tool = TOOLS[state.currentTool];
            if (!tool) return;

            // Validate
            if (!validateForm(tool)) {
                announce('Please fix the form errors before submitting');
                return;
            }

            // Collect data
            var data = {};
            tool.fields.forEach(function (field) {
                var input = document.getElementById('field-' + field.name);
                if (!input) return;
                var val = input.value.trim();
                if (field.type === 'json' && val) {
                    val = JSON.parse(val);
                }
                if (val !== '') data[field.name] = val;
            });

            executeScan(tool, data);
        });
    }

    async function executeScan(tool, data) {
        setLoading(true);
        removeWelcome();
        announce('Running ' + tool.title + '…');

        // Spinner in terminal
        var loadingId = 'loading-' + Date.now();
        var loadingHtml =
            '<div id="' + loadingId + '" class="terminal__loading">' +
            '<svg class="spinner" width="20" height="20" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="6" stroke="currentColor" stroke-width="2" stroke-dasharray="30 10" stroke-linecap="round"/></svg>' +
            ' Running ' + escapeHtml(tool.title) + '…</div>';
        el.terminalContent.insertAdjacentHTML('afterbegin', loadingHtml);

        try {
            var startTime = Date.now();
            var response;

            if (tool.method === 'GET') {
                response = await fetch(tool.endpoint);
            } else {
                response = await fetch(tool.endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
            }

            var result = await response.json();
            var elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

            // Remove loading spinner
            var loader = document.getElementById(loadingId);
            if (loader) loader.remove();

            if (state.currentTool === 'health') {
                renderHealthResult(result);
                announce('Health check complete');
            } else {
                renderScanResult(tool.title, result, elapsed);
                announce(tool.title + ' completed in ' + elapsed + ' seconds');
            }

            state.scanCount++;
            el.scanCount.textContent = state.scanCount;
        } catch (err) {
            var loader = document.getElementById(loadingId);
            if (loader) loader.remove();
            renderErrorResult(tool.title, err.message);
            announce('Error: ' + err.message);
        }

        setLoading(false);
    }

    /* ═══════════════════════════════
       OUTPUT RENDERING
       ═══════════════════════════════ */
    function renderScanResult(toolName, result, elapsed) {
        var status = result.timed_out ? 'timeout' : (result.success ? 'success' : 'error');
        var statusLabel = result.timed_out ? 'Timeout' : (result.success ? 'Success' : 'Error');
        var time = new Date().toLocaleTimeString();
        var bodyHtml = '';

        if (result.error) {
            bodyHtml = '<div class="output-entry__error">⚠️ ' + escapeHtml(result.error) + '</div>';
        } else {
            if (result.stdout) bodyHtml += '<div class="output-entry__stdout">' + escapeHtml(result.stdout) + '</div>';
            if (result.stderr) bodyHtml += '<div class="output-entry__stderr">' + escapeHtml(result.stderr) + '</div>';
            if (!result.stdout && !result.stderr) bodyHtml = '<div class="form-empty">No output returned.</div>';
        }

        var html =
            '<article class="output-entry" role="article" aria-label="' + escapeHtml(toolName) + ' result">' +
            '<div class="output-entry__header">' +
            '<span class="output-entry__tool">⚡ ' + escapeHtml(toolName) + '</span>' +
            '<span class="output-entry__badge output-entry__badge--' + status + '">' + statusLabel + '</span>' +
            '<span class="output-entry__time">' + time + ' · ' + elapsed + 's</span>' +
            '</div>' +
            '<div class="output-entry__body">' + bodyHtml + '</div>' +
            '</article>';

        el.terminalContent.insertAdjacentHTML('afterbegin', html);
    }

    function renderHealthResult(result) {
        var html = '';

        if (result.message) {
            html += '<div class="health-msg">Status: <span class="health-msg__label">' +
                escapeHtml(result.status || 'unknown') + '</span> — ' + escapeHtml(result.message) + '</div>';
        }

        if (result.tools_status) {
            var icons = { nmap: '🔍', gobuster: '📂', dirb: '🗂️', nikto: '🕷️', wpscan: '📝', enum4linux: '🖥️', sqlmap: '💉', msfconsole: '⚔️', hydra: '🔑', john: '🔓' };
            html += '<div class="health-grid" role="list">';
            for (var name in result.tools_status) {
                var available = result.tools_status[name];
                html +=
                    '<div class="health-card" role="listitem">' +
                    '<div class="health-card__icon">' + (icons[name] || '🔧') + '</div>' +
                    '<div class="health-card__name">' + escapeHtml(name) + '</div>' +
                    '<span class="health-card__badge health-card__badge--' + (available ? 'ok' : 'fail') + '">' +
                    (available ? '● Available' : '○ Missing') +
                    '</span>' +
                    '</div>';
            }
            html += '</div>';
        }

        var entry =
            '<article class="output-entry" role="article" aria-label="Health check result">' +
            '<div class="output-entry__header">' +
            '<span class="output-entry__tool">💚 Health Check</span>' +
            '<span class="output-entry__badge output-entry__badge--success">OK</span>' +
            '<span class="output-entry__time">' + new Date().toLocaleTimeString() + '</span>' +
            '</div>' +
            '<div class="output-entry__body" style="padding:0;">' + html + '</div>' +
            '</article>';

        el.terminalContent.insertAdjacentHTML('afterbegin', entry);
    }

    function renderErrorResult(toolName, message) {
        var html =
            '<article class="output-entry" role="article" aria-label="Error result">' +
            '<div class="output-entry__header">' +
            '<span class="output-entry__tool">⚡ ' + escapeHtml(toolName) + '</span>' +
            '<span class="output-entry__badge output-entry__badge--error">Error</span>' +
            '<span class="output-entry__time">' + new Date().toLocaleTimeString() + '</span>' +
            '</div>' +
            '<div class="output-entry__body"><div class="output-entry__error">❌ Connection failed: ' + escapeHtml(message) + '</div></div>' +
            '</article>';

        el.terminalContent.insertAdjacentHTML('afterbegin', html);
    }

    /* ═══════════════════════════════
       BUTTON HANDLERS
       ═══════════════════════════════ */
    function bindButtons() {
        el.clearOutputBtn.addEventListener('click', function () {
            el.terminalContent.innerHTML = '';
            state.welcomeVisible = false;
            showToast('Output cleared');
            announce('Terminal output cleared');
        });

        el.copyOutputBtn.addEventListener('click', function () {
            var text = el.terminalContent.innerText;
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).then(function () {
                    showToast('Copied to clipboard');
                    announce('Output copied to clipboard');
                });
            }
        });

        el.expandOutputBtn.addEventListener('click', function () {
            el.outputPanel.classList.toggle('panel--expanded');
            var expanded = el.outputPanel.classList.contains('panel--expanded');
            announce(expanded ? 'Terminal expanded' : 'Terminal collapsed');
        });
    }

    /* ═══════════════════════════════
       MOBILE SIDEBAR
       ═══════════════════════════════ */
    function bindMobile() {
        el.mobileMenuBtn.addEventListener('click', openMobileSidebar);
        el.sidebarOverlay.addEventListener('click', closeMobileSidebar);
    }

    function openMobileSidebar() {
        el.sidebar.classList.add('sidebar--open');
        el.sidebarOverlay.classList.add('sidebar-overlay--active');
        el.sidebarOverlay.setAttribute('aria-hidden', 'false');
        el.mobileMenuBtn.setAttribute('aria-expanded', 'true');
        state.sidebarOpen = true;

        // Focus first nav button
        var first = el.sidebar.querySelector('.nav-btn');
        if (first) first.focus();
    }

    function closeMobileSidebar() {
        el.sidebar.classList.remove('sidebar--open');
        el.sidebarOverlay.classList.remove('sidebar-overlay--active');
        el.sidebarOverlay.setAttribute('aria-hidden', 'true');
        el.mobileMenuBtn.setAttribute('aria-expanded', 'false');
        state.sidebarOpen = false;

        el.mobileMenuBtn.focus();
    }

    /* ═══════════════════════════════
       KEYBOARD NAVIGATION
       ═══════════════════════════════ */
    function bindKeyboard() {
        document.addEventListener('keydown', function (e) {
            // Escape closes settings modal
            if (e.key === 'Escape' && el.settingsOverlay.style.display !== 'none') {
                closeSettings();
                return;
            }

            // Escape closes sidebar on mobile
            if (e.key === 'Escape' && state.sidebarOpen) {
                closeMobileSidebar();
                return;
            }

            // Escape closes expanded terminal
            if (e.key === 'Escape' && el.outputPanel.classList.contains('panel--expanded')) {
                el.outputPanel.classList.remove('panel--expanded');
                announce('Terminal collapsed');
                return;
            }

            // Ctrl+Enter submits form or sends chat
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                e.preventDefault();
                if (state.currentTool === 'aichat') {
                    el.chatForm.requestSubmit();
                } else {
                    el.toolForm.requestSubmit();
                }
            }
        });
    }

    /* ═══════════════════════════════
       HEALTH CHECK
       ═══════════════════════════════ */
    var checkHealth = debounce(async function () {
        try {
            var controller = new AbortController();
            var timeoutId = setTimeout(function () { controller.abort(); }, 5000);

            var res = await fetch('/health', { signal: controller.signal });
            clearTimeout(timeoutId);

            if (res.ok) {
                el.statusDot.className = 'server-status__dot server-status__dot--online';
                el.statusText.textContent = 'Server Online';
            } else {
                el.statusDot.className = 'server-status__dot server-status__dot--offline';
                el.statusText.textContent = 'Server Error';
            }
        } catch (err) {
            el.statusDot.className = 'server-status__dot server-status__dot--offline';
            el.statusText.textContent = 'Server Offline';
        }
    }, 300);

    /* ═══════════════════════════════
       SETTINGS MODAL
       ═══════════════════════════════ */
    async function loadProviders() {
        try {
            var res = await fetch('/api/providers');
            state.providers = await res.json();
            populateProviderDropdown();
        } catch (e) {
            console.error('Failed to load providers:', e);
        }
    }

    function populateProviderDropdown() {
        el.settingsProvider.innerHTML = '<option value="">Select a provider…</option>';
        for (var key in state.providers) {
            var p = state.providers[key];
            var opt = document.createElement('option');
            opt.value = key;
            opt.textContent = p.name;
            if (key === state.aiProvider) opt.selected = true;
            el.settingsProvider.appendChild(opt);
        }
        updateModelDropdown();
        updateKeyVisibility();
    }

    function updateModelDropdown() {
        el.settingsModel.innerHTML = '<option value="">Select a model…</option>';
        var provider = state.providers[el.settingsProvider.value];
        if (!provider) return;

        provider.models.forEach(function (m) {
            var opt = document.createElement('option');
            opt.value = m;
            opt.textContent = m;
            if (m === state.aiModel) opt.selected = true;
            el.settingsModel.appendChild(opt);
        });
    }

    function updateKeyVisibility() {
        var provider = state.providers[el.settingsProvider.value];
        el.apiKeyGroup.style.display = (provider && provider.needs_key) ? 'flex' : 'none';
    }

    function bindSettings() {
        el.settingsBtn.addEventListener('click', openSettings);
        el.settingsCloseBtn.addEventListener('click', closeSettings);
        el.settingsOverlay.addEventListener('click', function (e) {
            if (e.target === el.settingsOverlay) closeSettings();
        });

        el.settingsProvider.addEventListener('change', function () {
            updateModelDropdown();
            updateKeyVisibility();
        });

        el.settingsSaveBtn.addEventListener('click', function () {
            state.aiProvider = el.settingsProvider.value;
            state.aiApiKey = el.settingsApiKey.value;
            var custom = el.settingsCustomModel.value.trim();
            state.aiModel = custom || el.settingsModel.value;

            localStorage.setItem('mcpKaliAI', JSON.stringify({
                provider: state.aiProvider,
                apiKey: state.aiApiKey,
                model: state.aiModel
            }));

            closeSettings();
            showToast('AI settings saved');
            announce('AI settings saved');
        });
    }

    function openSettings() {
        el.settingsOverlay.style.display = 'flex';
        el.settingsApiKey.value = state.aiApiKey;
        el.settingsCustomModel.value = '';
        if (state.aiProvider) el.settingsProvider.value = state.aiProvider;
        updateModelDropdown();
        updateKeyVisibility();
        if (state.aiModel) {
            el.settingsModel.value = state.aiModel;
            // If the saved model isn't in the dropdown, put it in custom field
            if (el.settingsModel.value !== state.aiModel) {
                el.settingsCustomModel.value = state.aiModel;
            }
        }
        el.settingsProvider.focus();
    }

    function closeSettings() {
        el.settingsOverlay.style.display = 'none';
    }

    /* ═══════════════════════════════
       AI CHAT
       ═══════════════════════════════ */
    async function discoverTools() {
        if (state.chatBusy) return;

        setLoading(true);
        addChatMessage('ai', '🔍 Looking for tools in MCP server...', { isSystem: true });

        try {
            const res = await fetch('/api/mcp/tools');
            const data = await res.json();

            if (data.tools && data.tools.length > 0) {
                let html = '<div class="chat-tools-grid">';
                data.tools.forEach(tool => {
                    html += `
                        <div class="chat-tool-card">
                            <div class="chat-tool-card__name">${escapeHtml(tool.name)}</div>
                            <div class="chat-tool-card__desc">${escapeHtml(tool.description)}</div>
                        </div>
                    `;
                });
                html += '</div>';

                addChatMessage('ai', `I discovered **${data.tools.length}** tools in the MCP server. I am ready to use them:`, {
                    raw_html: html
                });
            } else {
                addChatMessage('ai', 'No tools were found in the MCP server. Make sure the MCP server is running and tools are defined.');
            }
        } catch (e) {
            addChatMessage('ai', '❌ Error discovering tools: ' + e.message);
        } finally {
            setLoading(false);
        }
    }

    function bindChat() {
        el.chatForm.addEventListener('submit', function (e) {
            e.preventDefault();
            var msg = el.chatInput.value.trim();
            if (!msg || state.chatBusy) return;
            sendChatMessage(msg);
            el.chatInput.value = '';
        });

        // Discover tools buttons
        if (el.chatDiscoverBtn) {
            el.chatDiscoverBtn.addEventListener('click', discoverTools);
        }
        if (el.welcomeDiscoverBtn) {
            el.welcomeDiscoverBtn.addEventListener('click', discoverTools);
        }

        // Example prompt buttons — event delegation
        el.chatMessages.addEventListener('click', function (e) {
            var example = e.target.closest('.chat-example');
            if (example) {
                var msg = example.dataset.msg;
                if (msg && !state.chatBusy) sendChatMessage(msg);
            }
        });
    }

    function addChatMessage(role, content, extra) {
        // Remove welcome screen on first message
        var welcome = el.chatMessages.querySelector('.chat-welcome');
        if (welcome) welcome.remove();

        var div = document.createElement('div');
        div.className = 'chat-msg chat-msg--' + role;

        var avatar = document.createElement('div');
        avatar.className = 'chat-msg__avatar';
        avatar.textContent = role === 'user' ? '👤' : '🤖';

        var bubble = document.createElement('div');
        bubble.className = 'chat-msg__bubble';

        // If tool was used, show badge
        if (extra && extra.tool_used) {
            var badge = document.createElement('div');
            badge.className = 'chat-tool-badge';
            badge.textContent = '🔧 ' + extra.tool_used;
            bubble.appendChild(badge);
        }

        var textNode = document.createElement('div');
        if (extra && extra.raw_html) {
            textNode.innerHTML = extra.raw_html;
        } else {
            // Simple markdown-like bold formatting
            var processed = content.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
            textNode.innerHTML = processed.replace(/\n/g, '<br>');
        }

        if (extra && extra.isSystem) {
            bubble.style.background = 'transparent';
            bubble.style.border = 'none';
            bubble.style.fontSize = 'var(--fs-xs)';
            bubble.style.color = 'var(--color-text-3)';
            bubble.style.boxShadow = 'none';
            bubble.style.textAlign = 'center';
            avatar.style.display = 'none';
        }

        bubble.appendChild(textNode);

        // Show tool output if available
        if (extra && extra.tool_result && extra.tool_result.stdout) {
            var output = document.createElement('div');
            output.className = 'chat-tool-output';
            output.textContent = extra.tool_result.stdout.substring(0, 2000);
            bubble.appendChild(output);
        }

        div.appendChild(avatar);
        div.appendChild(bubble);
        el.chatMessages.appendChild(div);
        el.chatMessages.scrollTop = el.chatMessages.scrollHeight;
    }

    function showTypingIndicator() {
        var typing = document.createElement('div');
        typing.className = 'chat-typing';
        typing.id = 'chatTyping';
        typing.innerHTML = '<div class="chat-typing__dot"></div><div class="chat-typing__dot"></div><div class="chat-typing__dot"></div>';
        el.chatMessages.appendChild(typing);
        el.chatMessages.scrollTop = el.chatMessages.scrollHeight;
    }

    function removeTypingIndicator() {
        var typing = document.getElementById('chatTyping');
        if (typing) typing.remove();
    }

    function setChatActivity(text) {
        if (!el.chatActivityBar) return;
        if (text) {
            el.chatActivityBar.style.display = 'flex';
            el.chatActivityText.textContent = text;
        } else {
            el.chatActivityBar.style.display = 'none';
        }
    }

    async function sendChatMessage(msg) {
        if (!state.aiProvider || !state.aiModel) {
            showToast('Configure AI provider in Settings first');
            openSettings();
            return;
        }

        state.chatBusy = true;
        el.chatSendBtn.disabled = true;
        el.chatInput.value = '';

        addChatMessage('user', msg);
        state.chatMessages.push({ role: 'user', content: msg });
        setChatActivity('AI is thinking…');

        try {
            var res = await fetch('/api/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    provider: state.aiProvider,
                    api_key: state.aiApiKey,
                    model: state.aiModel,
                    messages: state.chatMessages
                })
            });

            // Handle non-streaming responses (JSON fallback or errors)
            var contentType = res.headers.get('content-type') || '';
            if (!res.ok || contentType.indexOf('text/event-stream') === -1) {
                setChatActivity(null);
                try {
                    var jsonData = await res.json();
                    // Valid JSON reply (old format or fallback)
                    if (jsonData.reply) {
                        addChatMessage('ai', jsonData.reply, {
                            tool_used: jsonData.tool_used,
                            tool_result: jsonData.tool_result
                        });
                        state.chatMessages.push({ role: 'assistant', content: jsonData.reply });
                    } else if (jsonData.error) {
                        addChatMessage('ai', '❌ ' + (jsonData.error.message || jsonData.error));
                    } else {
                        addChatMessage('ai', '❌ Unexpected response (HTTP ' + res.status + ')');
                    }
                } catch (e) {
                    addChatMessage('ai', '❌ Server error (HTTP ' + res.status + ')');
                }
                return;
            }

            // ── SSE stream reader ──
            var reader = res.body.getReader();
            var decoder = new TextDecoder();
            var buffer = '';
            var toolExtra = null; // collect tool_result event for badge

            while (true) {
                var chunk = await reader.read();
                if (chunk.done) break;
                buffer += decoder.decode(chunk.value, { stream: true });

                // Process complete SSE frames (double newline delimited)
                var frames = buffer.split('\n\n');
                buffer = frames.pop(); // keep incomplete tail

                for (var i = 0; i < frames.length; i++) {
                    var frame = frames[i].trim();
                    if (!frame) continue;

                    var eventType = 'message';
                    var dataStr = '';

                    var lines = frame.split('\n');
                    for (var j = 0; j < lines.length; j++) {
                        var line = lines[j];
                        if (line.indexOf('event: ') === 0) {
                            eventType = line.substring(7);
                        } else if (line.indexOf('data: ') === 0) {
                            dataStr = line.substring(6);
                        }
                    }

                    var data = {};
                    try { data = JSON.parse(dataStr); } catch (e) { /* skip */ }

                    if (eventType === 'status') {
                        setChatActivity(data.message || 'Working…');
                    } else if (eventType === 'tool_result') {
                        // Store for the reply message badge
                        toolExtra = {
                            tool_used: data.tool_used,
                            tool_result: data.tool_result
                        };
                        // Show intermediate tool output immediately
                        addChatMessage('ai', '🔧 Ran **' + (data.tool_used || 'tool') + '** — analyzing output…', { isSystem: true });
                    } else if (eventType === 'reply') {
                        setChatActivity(null);
                        addChatMessage('ai', data.reply || 'No response.', toolExtra || {
                            tool_used: data.tool_used,
                            tool_result: data.tool_result
                        });
                        state.chatMessages.push({ role: 'assistant', content: data.reply || '' });
                    } else if (eventType === 'error') {
                        setChatActivity(null);
                        addChatMessage('ai', '❌ ' + (data.error || 'Unknown error'));
                    } else if (eventType === 'done') {
                        setChatActivity(null);
                    }
                }
            }
        } catch (err) {
            setChatActivity(null);
            addChatMessage('ai', '❌ Connection error: ' + err.message);
        } finally {
            state.chatBusy = false;
            el.chatSendBtn.disabled = false;
            el.chatInput.focus();
        }
    }

    /* ═══════════════════════════════
       UI STATE HELPERS
       ═══════════════════════════════ */
    function setLoading(loading) {
        state.isRunning = loading;
        el.submitBtn.disabled = loading;
        el.submitBtn.setAttribute('aria-busy', loading ? 'true' : 'false');

        var loader = el.submitBtn.querySelector('.btn__loader');
        var icon = el.submitBtn.querySelector('.btn__icon');
        if (loader) loader.style.display = loading ? 'inline-flex' : 'none';
        if (icon) icon.style.display = loading ? 'none' : 'inline-flex';
    }

    function removeWelcome() {
        if (state.welcomeVisible) {
            var welcome = el.terminalContent.querySelector('.terminal__welcome');
            if (welcome) welcome.remove();
            state.welcomeVisible = false;
        }
    }

    /* ═══════════════════════════════
       BOOT
       ═══════════════════════════════ */
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
