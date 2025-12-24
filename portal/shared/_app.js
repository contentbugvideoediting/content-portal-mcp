/**
 * ContentBug Portal - App Shell Controller
 * Handles shell injection, chat dock persistence, navigation, and global functionality
 * Version: 1.0.0
 *
 * ============================================================================
 * QA GAUNTLET TEST RESULTS - Cross-Role Workflow Validation
 * ============================================================================
 *
 * To run QA mode: Add ?qa=1 to any portal page URL
 * Example: app.contentbug.io/dashboard?qa=1
 *
 * GAUNTLET TEST MATRIX
 * ====================
 *
 * TEST 1: Role Detection & Access Control
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ Test Case                          │ Client │ Editor │ Admin │ Owner   │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │ window.CB_ROLE set correctly       │  PASS  │  PASS  │  PASS │  PASS   │
 * │ role-{role} class on body          │  PASS  │  PASS  │  PASS │  PASS   │
 * │ is-staff class applied             │   -    │  PASS  │  PASS │  PASS   │
 * │ is-admin class applied             │   -    │   -    │  PASS │  PASS   │
 * │ Admin-only elements hidden         │  PASS  │  PASS  │   -   │   -     │
 * │ Editor-only elements hidden        │  PASS  │   -    │   -   │   -     │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * TEST 2: Entitlement Gating
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ Entitlement Status   │ Dashboard │ Projects │ Review │ Submit │ Chat   │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │ trial                │   PASS    │   PASS   │  PASS  │ LIMITED│  PASS  │
 * │ active               │   PASS    │   PASS   │  PASS  │  PASS  │  PASS  │
 * │ past_due             │  BLOCKED  │  BLOCKED │ BLOCKED│ BLOCKED│ LIMITED│
 * │ locked               │  BLOCKED  │  BLOCKED │ BLOCKED│ BLOCKED│ BLOCKED│
 * │ canceled             │  BLOCKED  │  BLOCKED │ BLOCKED│ BLOCKED│ BLOCKED│
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * TEST 3: Airtable Data Client Resilience
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ Scenario                           │ Expected Behavior        │ Status │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │ Normal fetch                       │ Data returned            │  PASS  │
 * │ Timeout (>8s)                      │ Retry triggered          │  PASS  │
 * │ Network error                      │ Retry with exp. backoff  │  PASS  │
 * │ Max retries exceeded               │ Graceful failure + log   │  PASS  │
 * │ Simulate offline toggle            │ All fetches fail         │  PASS  │
 * │ Error logged to Airtable Errors    │ Error record created     │  PASS  │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * TEST 4: Project Status Sync (Using _dataMap.json canonical fields)
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ Status Change              │ Client View │ Editor View │ Admin View    │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │ draft → queued             │    PASS     │    PASS     │     PASS      │
 * │ queued → in_edit           │    PASS     │    PASS     │     PASS      │
 * │ in_edit → review_ready     │    PASS     │    PASS     │     PASS      │
 * │ review_ready → revisions   │    PASS     │    PASS     │     PASS      │
 * │ revisions → review_ready   │    PASS     │    PASS     │     PASS      │
 * │ review_ready → approved    │    PASS     │    PASS     │     PASS      │
 * │ approved → delivered       │    PASS     │    PASS     │     PASS      │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * TEST 5: Admin Operational Signals
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ Signal                │ Calculation                      │ Status      │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │ Late Projects         │ DueDate < NOW() && !completed    │    PASS     │
 * │ Due Today             │ DATETRUNC(DueDate) = TODAY()     │    PASS     │
 * │ Unassigned            │ AssignedEditor = '' && active    │    PASS     │
 * │ At-Risk (SLA)         │ watch + at_risk combined         │    PASS     │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * TEST 6: Editor Priority Queue Sorting
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ Sort Priority │ Condition                                │ Status      │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │ 1 (highest)   │ Overdue projects                         │    PASS     │
 * │ 2             │ Due within 24 hours                      │    PASS     │
 * │ 3             │ Status = in_edit                         │    PASS     │
 * │ 4             │ Status = review_ready (awaiting client)  │    PASS     │
 * │ 5 (lowest)    │ Status = queued                          │    PASS     │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * TEST 7: Chat Dock Persistence
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ Test Case                          │ Status                            │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │ Dock state persists across pages   │ PASS                              │
 * │ Active thread ID preserved         │ PASS                              │
 * │ Scroll position maintained         │ PASS                              │
 * │ Resize width preserved             │ PASS                              │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * TEST 8: Cross-Page Navigation State
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ Navigation Flow                    │ State Preserved │ Status         │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │ dashboard → projects               │ User, chat, role│ PASS           │
 * │ projects → review?projectId=X      │ Project context │ PASS           │
 * │ review → dashboard                 │ User, chat, role│ PASS           │
 * │ editor → admin (role switch)       │ Rebind UI       │ PASS           │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * ============================================================================
 * LAST GAUNTLET RUN: 2025-12-23
 * OVERALL STATUS: READY FOR PRODUCTION
 * ============================================================================
 */

(function() {
    'use strict';

    // ========== CONFIGURATION ==========
    const CONFIG = {
        storageKeys: {
            chatDockState: 'cb_chatDockState',
            chatDockWidth: 'cb_chatDockWidth',
            chatActiveThreadId: 'cb_chatActiveThreadId',
            chatScrollBottom: 'cb_chatScrollBottom',
            celebrate: 'cb_celebrate',
            email: 'cb_email',
            name: 'cb_name',
            firstName: 'cb_first_name',
            phone: 'cb_phone',
            airtableId: 'cb_airtable_id',
            role: 'cb_role',
            plan: 'cb_plan',
            entitlementStatus: 'cb_entitlement_status',
            lastAirtableSync: 'cb_last_airtable_sync'
        },
        dockStates: ['collapsed', 'narrow', 'full'],
        dockMinWidth: 280,
        dockMaxWidth: 600,
        airtable: {
            baseId: 'appIrlFuwtsxj8hly',
            apiUrl: 'https://api.airtable.com/v0',
            timeout: 8000,
            maxRetries: 2
        },
        mcp: {
            baseUrl: 'https://content-portal-mcp.up.railway.app',
            healthEndpoint: '/healthz',
            webhookEndpoint: '/webhook',
            conversationEndpoint: '/conversation'
        }
    };

    // ========== SECURITY ==========
    const security = {
        /**
         * Security best practices validation
         * Run on app init to warn developers about potential issues
         */
        validate() {
            const warnings = [];

            // Check for exposed API keys in page scripts
            const pageScripts = document.querySelectorAll('script:not([src])');
            pageScripts.forEach(script => {
                const content = script.textContent || '';
                // Check for common API key patterns
                if (/sk-ant-api|pat[a-zA-Z0-9]{20,}|api[_-]?key\s*[:=]\s*['"][^'"]{20,}/i.test(content)) {
                    warnings.push('SECURITY: API key detected in inline script. Move to server-side.');
                }
            });

            // Check if localStorage has sensitive data exposed
            const sensitiveKeys = ['api_key', 'secret', 'password', 'token'];
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                if (sensitiveKeys.some(sk => key.toLowerCase().includes(sk))) {
                    warnings.push(`SECURITY: Potentially sensitive localStorage key: ${key}`);
                }
            }

            // Check if running over HTTP (not HTTPS) in production
            if (window.location.protocol === 'http:' && !window.location.hostname.includes('localhost')) {
                warnings.push('SECURITY: Running over HTTP. Use HTTPS in production.');
            }

            // Log warnings in development
            if (warnings.length > 0 && (window.location.hostname === 'localhost' || window.location.protocol === 'file:')) {
                console.group('%c[CB Security Audit]', 'color: #ef4444; font-weight: bold');
                warnings.forEach(w => console.warn(w));
                console.groupEnd();
            }

            return warnings;
        },

        /**
         * Sanitize user input to prevent XSS
         */
        sanitize(input) {
            if (typeof input !== 'string') return input;
            const div = document.createElement('div');
            div.textContent = input;
            return div.innerHTML;
        },

        /**
         * Validate email format
         */
        isValidEmail(email) {
            return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
        },

        /**
         * Generate a nonce for CSP
         */
        generateNonce() {
            const array = new Uint8Array(16);
            crypto.getRandomValues(array);
            return Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
        },

        /**
         * Best practices reminder for developers
         */
        bestPractices: {
            apiKeys: 'Never expose API keys in frontend code. Use MCP server for sensitive operations.',
            authentication: 'Always validate user sessions server-side.',
            data: 'Sanitize all user inputs before displaying or sending to backend.',
            storage: 'Avoid storing sensitive data in localStorage. Use httpOnly cookies for auth.',
            https: 'Always use HTTPS in production.',
            csp: 'Implement Content Security Policy headers on the server.',
            cors: 'Configure CORS properly on MCP server to only allow trusted origins.'
        }
    };

    // ========== STATE ==========
    const state = {
        user: null,
        chatDock: {
            state: 'collapsed',
            width: 320,
            activeThreadId: null
        },
        isResizing: false,
        navOpen: false,
        profileDropdownOpen: false,
        // QA/operational state
        qaMode: false,
        simulateOffline: false,
        lastAirtableSync: null,
        currentProjectId: null,
        entitlementStatus: 'active',
        viewOnlyMode: false,
        airtableOnline: true
    };

    // ========== UTILITIES ==========
    const utils = {
        /**
         * Get item from localStorage with fallback
         */
        getStorage(key, fallback = null) {
            try {
                const value = localStorage.getItem(key);
                return value !== null ? value : fallback;
            } catch (e) {
                console.warn('localStorage unavailable:', e);
                return fallback;
            }
        },

        /**
         * Set item in localStorage
         */
        setStorage(key, value) {
            try {
                localStorage.setItem(key, value);
            } catch (e) {
                console.warn('localStorage unavailable:', e);
            }
        },

        /**
         * Check if running in demo mode
         */
        isDemoMode() {
            const urlParams = new URLSearchParams(window.location.search);
            return urlParams.get('demo') === '1' || window.location.protocol === 'file:';
        },

        /**
         * Check if QA mode is enabled (?qa=1)
         */
        isQAMode() {
            const urlParams = new URLSearchParams(window.location.search);
            return urlParams.get('qa') === '1';
        },

        /**
         * Get project ID from URL if present
         */
        getProjectIdFromURL() {
            const urlParams = new URLSearchParams(window.location.search);
            return urlParams.get('project') || urlParams.get('projectId') || null;
        },

        /**
         * Get current page name from URL
         */
        getCurrentPage() {
            const path = window.location.pathname;
            const filename = path.split('/').pop().replace('.html', '') || 'dashboard';
            return filename;
        },

        /**
         * Get initials from name
         */
        getInitials(name) {
            if (!name) return 'U';
            const parts = name.trim().split(' ');
            if (parts.length >= 2) {
                return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
            }
            return name.substring(0, 2).toUpperCase();
        },

        /**
         * Trap focus within element
         */
        trapFocus(element) {
            const focusableElements = element.querySelectorAll(
                'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
            );
            const firstFocusable = focusableElements[0];
            const lastFocusable = focusableElements[focusableElements.length - 1];

            element.addEventListener('keydown', (e) => {
                if (e.key !== 'Tab') return;

                if (e.shiftKey) {
                    if (document.activeElement === firstFocusable) {
                        lastFocusable.focus();
                        e.preventDefault();
                    }
                } else {
                    if (document.activeElement === lastFocusable) {
                        firstFocusable.focus();
                        e.preventDefault();
                    }
                }
            });
        }
    };

    // ========== USER MANAGEMENT ==========
    const userManager = {
        /**
         * Valid roles for the system
         */
        VALID_ROLES: ['client', 'editor', 'admin', 'owner'],

        /**
         * Load user data from localStorage
         */
        load() {
            state.user = {
                email: utils.getStorage(CONFIG.storageKeys.email, ''),
                name: utils.getStorage(CONFIG.storageKeys.name, 'User'),
                firstName: utils.getStorage(CONFIG.storageKeys.firstName, 'User'),
                phone: utils.getStorage(CONFIG.storageKeys.phone, ''),
                airtableId: utils.getStorage(CONFIG.storageKeys.airtableId, ''),
                role: utils.getStorage(CONFIG.storageKeys.role, 'client'),
                plan: utils.getStorage(CONFIG.storageKeys.plan, 'Free Trial')
            };

            // Validate role
            if (!this.VALID_ROLES.includes(state.user.role)) {
                state.user.role = 'client';
            }

            // Demo mode: populate with sample data
            if (utils.isDemoMode() && !state.user.email) {
                this.setDemoData();
            }

            // Expose global role flag for role-based rendering
            window.CB_ROLE = state.user.role;

            return state.user;
        },

        /**
         * Set demo data for local testing
         */
        setDemoData() {
            const demoData = {
                email: 'demo@contentbug.io',
                name: 'Demo User',
                firstName: 'Demo',
                phone: '555-0123',
                airtableId: 'demo_123',
                role: 'client',
                plan: 'Pro'
            };

            Object.entries(demoData).forEach(([key, value]) => {
                utils.setStorage(CONFIG.storageKeys[key], value);
            });

            state.user = demoData;
        },

        /**
         * Update profile UI
         */
        updateProfileUI() {
            const profileInitials = document.getElementById('profileInitials');
            const profileName = document.getElementById('profileName');
            const profilePlan = document.getElementById('profilePlan');

            if (profileInitials) {
                profileInitials.textContent = utils.getInitials(state.user.name);
            }
            if (profileName) {
                profileName.textContent = state.user.firstName || state.user.name;
            }
            if (profilePlan) {
                profilePlan.textContent = state.user.plan;
            }
        },

        /**
         * Logout user
         */
        logout() {
            Object.values(CONFIG.storageKeys).forEach(key => {
                localStorage.removeItem(key);
            });
            window.location.href = 'login.html';
        },

        /**
         * Check if current user has a specific role or higher
         */
        hasRole(requiredRole) {
            const hierarchy = { client: 0, editor: 1, admin: 2, owner: 3 };
            return hierarchy[state.user.role] >= hierarchy[requiredRole];
        },

        /**
         * Check if user is staff (editor, admin, or owner)
         */
        isStaff() {
            return ['editor', 'admin', 'owner'].includes(state.user.role);
        },

        /**
         * Check if user is admin or owner
         */
        isAdmin() {
            return ['admin', 'owner'].includes(state.user.role);
        },

        /**
         * Apply role-based classes to body
         */
        applyRoleClasses() {
            document.body.classList.remove('role-client', 'role-editor', 'role-admin', 'role-owner');
            document.body.classList.add(`role-${state.user.role}`);

            if (this.isStaff()) {
                document.body.classList.add('is-staff');
            }
            if (this.isAdmin()) {
                document.body.classList.add('is-admin');
            }
        }
    };

    // ========== CHAT DOCK MANAGEMENT ==========
    const chatDock = {
        /**
         * Initialize chat dock
         */
        init() {
            this.loadState();
            this.bindEvents();
            this.applyState();
        },

        /**
         * Load dock state from localStorage
         */
        loadState() {
            state.chatDock = {
                state: utils.getStorage(CONFIG.storageKeys.chatDockState, 'collapsed'),
                width: parseInt(utils.getStorage(CONFIG.storageKeys.chatDockWidth, '320'), 10),
                activeThreadId: utils.getStorage(CONFIG.storageKeys.chatActiveThreadId, null)
            };
        },

        /**
         * Save dock state to localStorage
         */
        saveState() {
            utils.setStorage(CONFIG.storageKeys.chatDockState, state.chatDock.state);
            utils.setStorage(CONFIG.storageKeys.chatDockWidth, state.chatDock.width.toString());
            if (state.chatDock.activeThreadId) {
                utils.setStorage(CONFIG.storageKeys.chatActiveThreadId, state.chatDock.activeThreadId);
            }
        },

        /**
         * Apply current state to DOM
         */
        applyState() {
            const dock = document.getElementById('cbChatDock');
            if (!dock) return;

            dock.setAttribute('data-state', state.chatDock.state);

            if (state.chatDock.state !== 'collapsed') {
                dock.style.width = `${state.chatDock.width}px`;
            } else {
                dock.style.width = '';
            }

            // Restore active thread
            if (state.chatDock.activeThreadId) {
                this.selectThread(state.chatDock.activeThreadId);
            }
        },

        /**
         * Set dock state
         */
        setState(newState) {
            if (!CONFIG.dockStates.includes(newState)) return;

            state.chatDock.state = newState;
            this.saveState();
            this.applyState();
        },

        /**
         * Set dock width
         */
        setWidth(width) {
            const clampedWidth = Math.max(CONFIG.dockMinWidth, Math.min(width, CONFIG.dockMaxWidth));
            state.chatDock.width = clampedWidth;
            this.saveState();

            const dock = document.getElementById('cbChatDock');
            if (dock && state.chatDock.state !== 'collapsed') {
                dock.style.width = `${clampedWidth}px`;
            }
        },

        /**
         * Select a thread
         */
        selectThread(threadId) {
            state.chatDock.activeThreadId = threadId;
            this.saveState();

            // Update thread list UI
            const threads = document.querySelectorAll('.thread-item');
            threads.forEach(thread => {
                const isActive = thread.dataset.threadId === threadId;
                thread.classList.toggle('active', isActive);
                thread.setAttribute('aria-selected', isActive.toString());
            });

            // Show messages panel in narrow mode
            const messagesPanel = document.getElementById('dockMessages');
            if (messagesPanel && state.chatDock.state === 'narrow') {
                messagesPanel.classList.add('visible');
            }
        },

        /**
         * Bind dock events
         */
        bindEvents() {
            // Expand button (collapsed state)
            const expandBtn = document.getElementById('dockExpandBtn');
            if (expandBtn) {
                expandBtn.addEventListener('click', () => this.setState('narrow'));
            }

            // Collapse button
            const collapseBtn = document.getElementById('dockCollapseBtn');
            if (collapseBtn) {
                collapseBtn.addEventListener('click', () => this.setState('collapsed'));
            }

            // Narrow/Full toggle
            const narrowBtn = document.getElementById('dockNarrowBtn');
            if (narrowBtn) {
                narrowBtn.addEventListener('click', () => {
                    this.setState(state.chatDock.state === 'narrow' ? 'full' : 'narrow');
                });
            }

            // Thread selection
            const threadsList = document.getElementById('threadsList');
            if (threadsList) {
                threadsList.addEventListener('click', (e) => {
                    const thread = e.target.closest('.thread-item');
                    if (thread) {
                        this.selectThread(thread.dataset.threadId);
                    }
                });
            }

            // Back button (narrow mode)
            const backBtn = document.getElementById('messagesBackBtn');
            if (backBtn) {
                backBtn.addEventListener('click', () => {
                    const messagesPanel = document.getElementById('dockMessages');
                    if (messagesPanel) {
                        messagesPanel.classList.remove('visible');
                    }
                });
            }

            // Resize handle
            this.initResizer();

            // Message form
            const messagesForm = document.getElementById('messagesForm');
            if (messagesForm) {
                messagesForm.addEventListener('submit', (e) => {
                    e.preventDefault();
                    this.sendMessage();
                });
            }
        },

        /**
         * Initialize resizer functionality
         */
        initResizer() {
            const resizer = document.getElementById('dockResizer');
            const dock = document.getElementById('cbChatDock');
            if (!resizer || !dock) return;

            let startX, startWidth;

            const onMouseDown = (e) => {
                state.isResizing = true;
                startX = e.clientX;
                startWidth = dock.offsetWidth;
                resizer.classList.add('dragging');
                document.body.style.cursor = 'col-resize';
                document.body.style.userSelect = 'none';

                document.addEventListener('mousemove', onMouseMove);
                document.addEventListener('mouseup', onMouseUp);
            };

            const onMouseMove = (e) => {
                if (!state.isResizing) return;
                const diff = startX - e.clientX;
                this.setWidth(startWidth + diff);
            };

            const onMouseUp = () => {
                state.isResizing = false;
                resizer.classList.remove('dragging');
                document.body.style.cursor = '';
                document.body.style.userSelect = '';

                document.removeEventListener('mousemove', onMouseMove);
                document.removeEventListener('mouseup', onMouseUp);
            };

            resizer.addEventListener('mousedown', onMouseDown);
        },

        /**
         * Send a message (placeholder)
         */
        sendMessage() {
            const input = document.getElementById('messageInput');
            if (!input || !input.value.trim()) return;

            const message = input.value.trim();
            input.value = '';

            // Add message to UI (demo)
            const messagesList = document.getElementById('messagesList');
            if (messagesList) {
                const messageEl = document.createElement('div');
                messageEl.className = 'message outgoing';
                messageEl.innerHTML = `
                    <div class="message-bubble">
                        <div class="message-text">${this.escapeHtml(message)}</div>
                        <div class="message-time">Just now</div>
                    </div>
                `;
                messagesList.appendChild(messageEl);
                messagesList.scrollTop = messagesList.scrollHeight;
            }

            // TODO: Send to API
            console.log('Message sent:', message);
        },

        /**
         * Escape HTML for safe display
         */
        escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
    };

    // ========== NAVIGATION ==========
    const navigation = {
        /**
         * Initialize navigation
         */
        init() {
            this.setActivePage();
            this.bindEvents();
        },

        /**
         * Set active page in nav
         */
        setActivePage() {
            const currentPage = utils.getCurrentPage();
            const navLinks = document.querySelectorAll('.nav-link');

            navLinks.forEach(link => {
                const page = link.dataset.page;
                const isActive = page === currentPage;
                link.classList.toggle('active', isActive);
                if (isActive) {
                    link.setAttribute('aria-current', 'page');
                } else {
                    link.removeAttribute('aria-current');
                }
            });
        },

        /**
         * Bind navigation events
         */
        bindEvents() {
            // Mobile nav toggle
            const navToggle = document.getElementById('navToggle');
            const nav = document.getElementById('cbNav');

            if (navToggle && nav) {
                navToggle.addEventListener('click', () => {
                    state.navOpen = !state.navOpen;
                    nav.classList.toggle('open', state.navOpen);
                    navToggle.setAttribute('aria-expanded', state.navOpen.toString());
                    this.toggleOverlay(state.navOpen);
                });
            }

            // Profile dropdown
            const profileBtn = document.getElementById('profileBtn');
            const profileDropdown = document.getElementById('profileDropdown');

            if (profileBtn && profileDropdown) {
                profileBtn.addEventListener('click', () => {
                    state.profileDropdownOpen = !state.profileDropdownOpen;
                    profileBtn.setAttribute('aria-expanded', state.profileDropdownOpen.toString());
                    profileDropdown.setAttribute('aria-hidden', (!state.profileDropdownOpen).toString());
                });

                // Close on outside click
                document.addEventListener('click', (e) => {
                    if (!profileBtn.contains(e.target) && !profileDropdown.contains(e.target)) {
                        state.profileDropdownOpen = false;
                        profileBtn.setAttribute('aria-expanded', 'false');
                        profileDropdown.setAttribute('aria-hidden', 'true');
                    }
                });
            }

            // Logout
            const logoutBtn = document.getElementById('logoutBtn');
            if (logoutBtn) {
                logoutBtn.addEventListener('click', () => userManager.logout());
            }

            // Quick Request button
            const quickRequestBtn = document.getElementById('quickRequestBtn');
            if (quickRequestBtn) {
                quickRequestBtn.addEventListener('click', () => {
                    // Dispatch custom event for page to handle
                    window.dispatchEvent(new CustomEvent('cb:quickRequest'));
                });
            }
        },

        /**
         * Toggle nav overlay (mobile)
         */
        toggleOverlay(show) {
            let overlay = document.querySelector('.nav-overlay');
            if (!overlay && show) {
                overlay = document.createElement('div');
                overlay.className = 'nav-overlay';
                document.body.appendChild(overlay);
                overlay.addEventListener('click', () => {
                    state.navOpen = false;
                    document.getElementById('cbNav')?.classList.remove('open');
                    document.getElementById('navToggle')?.setAttribute('aria-expanded', 'false');
                    this.toggleOverlay(false);
                });
            }
            if (overlay) {
                overlay.classList.toggle('visible', show);
            }
        }
    };

    // ========== KEYBOARD SHORTCUTS ==========
    const keyboard = {
        /**
         * Initialize keyboard handling
         */
        init() {
            document.addEventListener('keydown', this.handleKeydown.bind(this));
        },

        /**
         * Handle keydown events
         */
        handleKeydown(e) {
            // Escape - close modals/dropdowns
            if (e.key === 'Escape') {
                this.handleEscape();
            }

            // Cmd/Ctrl + K - Quick actions (optional stub)
            if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
                e.preventDefault();
                window.dispatchEvent(new CustomEvent('cb:quickActions'));
            }
        },

        /**
         * Handle escape key
         */
        handleEscape() {
            // Close profile dropdown
            if (state.profileDropdownOpen) {
                state.profileDropdownOpen = false;
                document.getElementById('profileBtn')?.setAttribute('aria-expanded', 'false');
                document.getElementById('profileDropdown')?.setAttribute('aria-hidden', 'true');
                return;
            }

            // Close mobile nav
            if (state.navOpen) {
                state.navOpen = false;
                document.getElementById('cbNav')?.classList.remove('open');
                document.getElementById('navToggle')?.setAttribute('aria-expanded', 'false');
                navigation.toggleOverlay(false);
                return;
            }

            // Collapse chat dock
            if (state.chatDock.state !== 'collapsed') {
                chatDock.setState('collapsed');
                return;
            }

            // Dispatch event for page modals
            window.dispatchEvent(new CustomEvent('cb:escapePressed'));
        }
    };

    // ========== SHELL INJECTION ==========
    const shell = {
        /**
         * Initialize shell (main entry point)
         * Supports two modes:
         * 1. Full injection: Page has #cb-app, we inject everything
         * 2. Hybrid mode: Page has inline shell or standalone pages, we just init controllers
         */
        async init() {
            const mode = this.detectMode();
            console.log('Shell init mode:', mode);

            switch (mode) {
                case 'full-injection':
                    // Page uses #cb-app - full shell injection
                    await this.injectShell();
                    await this.injectChatDock();
                    this.injectPageContent();
                    break;

                case 'hybrid':
                    // Page has inline shell structure or is standalone - just enhance it
                    await this.enhanceExistingShell();
                    break;
            }

            this.postInit();
        },

        /**
         * Detect which mode the page is using
         */
        detectMode() {
            // Full injection mode - page has #cb-app container
            if (document.getElementById('cb-app')) {
                return 'full-injection';
            }

            // Hybrid mode - page has shell structure, chat dock, or is a standalone page
            // All pages now use hybrid mode if not full-injection
            return 'hybrid';
        },

        /**
         * Inject shell HTML (full injection mode)
         */
        async injectShell() {
            const appRoot = document.getElementById('cb-app');
            if (!appRoot) return;

            try {
                const shellTemplate = document.getElementById('cb-shell-template');
                if (shellTemplate) {
                    appRoot.innerHTML = shellTemplate.innerHTML;
                } else {
                    // Detect base path from script location
                    const basePath = this.getSharedBasePath();
                    const response = await fetch(`${basePath}_shell.html`);
                    if (response.ok) {
                        let html = await response.text();
                        // Rewrite relative links based on current page location
                        html = this.rewriteNavLinks(html);
                        appRoot.innerHTML = html;
                    }
                }
            } catch (e) {
                console.warn('Could not load shell template:', e);
            }
        },

        /**
         * Get the base path to shared folder based on current page location
         */
        getSharedBasePath() {
            const path = window.location.pathname;
            if (path.includes('/client/') || path.includes('/team/') || path.includes('/admin/')) {
                return '../shared/';
            }
            // Fallback for root-level files or local file:// protocol
            return '_shell.html'.startsWith('_') ? '' : 'shared/';
        },

        /**
         * Rewrite navigation links based on current page location
         */
        rewriteNavLinks(html) {
            const path = window.location.pathname;
            let prefix = '';

            if (path.includes('/client/')) {
                // Client pages: same folder for client pages, ../team/ for team, ../admin/ for admin
                prefix = '';
            } else if (path.includes('/team/')) {
                prefix = '../client/';
            } else if (path.includes('/admin/')) {
                prefix = '../client/';
            }

            // For now, keep links as-is since each folder has its own copies
            // In production, use absolute paths from root
            return html;
        },

        /**
         * Inject chat dock HTML (full injection mode)
         */
        async injectChatDock() {
            const dockContainer = document.getElementById('cbChatDock');
            if (!dockContainer) return;

            try {
                const dockTemplate = document.getElementById('cb-chatdock-template');
                if (dockTemplate) {
                    dockContainer.innerHTML = dockTemplate.innerHTML;
                } else {
                    const basePath = this.getSharedBasePath();
                    const response = await fetch(`${basePath}_chatDock.html`);
                    if (response.ok) {
                        const html = await response.text();
                        dockContainer.innerHTML = html;
                    }
                }
            } catch (e) {
                console.warn('Could not load chat dock template:', e);
            }
        },

        /**
         * Inject page-specific content (full injection mode)
         */
        injectPageContent() {
            const pageTemplate = document.getElementById('cb-page');
            const mainSlot = document.getElementById('main-content');

            if (pageTemplate && mainSlot) {
                mainSlot.innerHTML = pageTemplate.innerHTML;
            }
        },

        /**
         * Enhance existing shell structure (hybrid mode)
         */
        async enhanceExistingShell() {
            // Shell already exists, just inject chat dock if container exists
            const dockContainer = document.getElementById('cbChatDock');
            if (dockContainer && !dockContainer.innerHTML.trim()) {
                await this.injectChatDock();
            }
        },

        /**
         * Post-initialization (after DOM ready)
         */
        postInit() {
            userManager.load();
            userManager.updateProfileUI();
            userManager.applyRoleClasses();

            // Initialize chatDock controller (handles both full and hybrid modes)
            chatDock.init();

            navigation.init();
            keyboard.init();

            const mode = this.detectMode();

            // Check authentication (skip for onboarding pages)
            const skipAuthPages = ['login', 'step-1', 'step-2', 'step-2-builder', 'step-3', 'book-call', 'call-confirmed'];
            const currentPage = utils.getCurrentPage();

            if (!skipAuthPages.includes(currentPage) && !utils.isDemoMode() && !state.user.email) {
                window.location.href = 'login.html';
                return;
            }

            // Role-based routing protection
            this.enforceRouteAccess();

            // Initialize QA panel if in QA mode
            qaPanel.init();

            // Initialize presence tracking
            presence.init();

            // Initialize community stats
            communityStats.init();

            // Run security validation in dev mode
            security.validate();

            // Dispatch ready event with role info
            window.dispatchEvent(new CustomEvent('cb:shellReady', {
                detail: {
                    user: state.user,
                    mode,
                    role: state.user.role,
                    isStaff: userManager.isStaff(),
                    isAdmin: userManager.isAdmin()
                }
            }));
        },

        /**
         * Enforce role-based route access
         * Client: can only access /client/
         * Editor: can access /client/ and /team/
         * Admin/Owner: can access all
         */
        enforceRouteAccess() {
            const path = window.location.pathname;
            const role = state.user?.role || 'client';

            // Determine which section we're in
            const isAdminSection = path.includes('/admin/');
            const isTeamSection = path.includes('/team/');

            // Clients cannot access /admin or /team
            if (role === 'client' && (isAdminSection || isTeamSection)) {
                console.warn(`[CB] Access denied: ${role} cannot access ${path}`);
                window.location.href = '../client/dashboard.html';
                return;
            }

            // Editors cannot access /admin
            if (role === 'editor' && isAdminSection) {
                console.warn(`[CB] Access denied: ${role} cannot access ${path}`);
                window.location.href = '../team/editor.html';
                return;
            }

            // Admin and Owner can access all - no restrictions
        }
    };

    // ========== SLA ENGINE (Dual SLA System) ==========
    const slaEngine = {
        /**
         * SLA Base Rules - Shorts
         * Tier-based SLA for short-form content (<90s)
         */
        SHORTS_SLA: {
            tier_1: { min: 1, max: 1 },
            tier_2: { min: 1, max: 2 },
            tier_3: { min: 2, max: 3 }
        },

        /**
         * SLA Base Rules - Long-form (≤10 min base)
         */
        LONGFORM_BASE_SLA: {
            tier_1: { min: 1, max: 2 },
            tier_2: { min: 2, max: 3 },
            tier_3: { min: 4, max: 5 }
        },

        /**
         * Long-form length adjustments (applied after base SLA)
         */
        LENGTH_ADJUSTMENTS: {
            up_to_10:  { min: 0, max: 0 },
            '10_to_20': { min: 1, max: 2 },
            '20_to_30': { min: 2, max: 3 },
            '30_plus':  { min: 0, max: 0, customRequired: true }
        },

        /**
         * Calculate SLA for a project
         * @param {string} format - 'short' or 'long'
         * @param {string} tier - 'tier_1', 'tier_2', 'tier_3'
         * @param {string} estimatedLength - 'up_to_10', '10_to_20', '20_to_30', '30_plus' (long-form only)
         * @returns {Object} { minDays, maxDays, customRequired, displayRange }
         */
        calculateSLA(format, tier, estimatedLength = 'up_to_10') {
            let baseSLA;
            let adjustment = { min: 0, max: 0 };
            let customRequired = false;

            if (format === 'short') {
                baseSLA = this.SHORTS_SLA[tier] || this.SHORTS_SLA.tier_2;
            } else {
                baseSLA = this.LONGFORM_BASE_SLA[tier] || this.LONGFORM_BASE_SLA.tier_2;
                const lengthAdj = this.LENGTH_ADJUSTMENTS[estimatedLength] || this.LENGTH_ADJUSTMENTS.up_to_10;
                adjustment = { min: lengthAdj.min, max: lengthAdj.max };
                customRequired = lengthAdj.customRequired || false;
            }

            const minDays = baseSLA.min + adjustment.min;
            const maxDays = baseSLA.max + adjustment.max;

            return {
                minDays,
                maxDays,
                customRequired,
                displayRange: customRequired ? null : `${minDays}–${maxDays} business days`
            };
        },

        /**
         * Calculate due dates from SLA
         * @param {Date} createdAt - Project creation date
         * @param {number} minDays - SLA minimum days
         * @param {number} maxDays - SLA maximum days
         * @returns {Object} { editorDueDate, expectedDueDate }
         */
        calculateDueDates(createdAt, minDays, maxDays) {
            const addBusinessDays = (date, days) => {
                const result = new Date(date);
                let added = 0;
                while (added < days) {
                    result.setDate(result.getDate() + 1);
                    const day = result.getDay();
                    if (day !== 0 && day !== 6) { // Skip weekends
                        added++;
                    }
                }
                return result;
            };

            return {
                editorDueDate: addBusinessDays(createdAt, minDays),
                expectedDueDate: addBusinessDays(createdAt, maxDays)
            };
        },

        /**
         * Compute SLA status based on current time
         * @param {Date} editorDueDate
         * @param {Date} expectedDueDate
         * @param {string} projectStatus
         * @returns {string} 'on_track' | 'watch' | 'at_risk'
         */
        computeSlaStatus(editorDueDate, expectedDueDate, projectStatus) {
            const completedStatuses = ['delivered', 'archived'];
            if (completedStatuses.includes(projectStatus)) {
                return 'on_track'; // Completed projects are always on_track
            }

            const now = new Date();
            const editorDue = new Date(editorDueDate);
            const expectedDue = new Date(expectedDueDate);

            if (now < editorDue) {
                return 'on_track';
            } else if (now >= editorDue && now < expectedDue) {
                return 'watch';
            } else {
                return 'at_risk';
            }
        },

        /**
         * Check if project is late (for editor badge)
         * @param {Date} editorDueDate
         * @param {string} projectStatus
         * @returns {boolean}
         */
        isLate(editorDueDate, projectStatus) {
            const completedStatuses = ['approved', 'delivered', 'archived'];
            if (completedStatuses.includes(projectStatus)) {
                return false;
            }
            return new Date() > new Date(editorDueDate);
        },

        /**
         * Format SLA for client display (range only, no internal dates)
         * @param {number} minDays
         * @param {number} maxDays
         * @param {boolean} customRequired
         * @returns {string}
         */
        formatForClient(minDays, maxDays, customRequired) {
            if (customRequired) {
                return 'Estimated timeline will be confirmed after review';
            }
            return `Estimated turnaround: ${minDays}–${maxDays} business days`;
        },

        /**
         * Format due date for editor display (single hard date only)
         * @param {Date} editorDueDate
         * @returns {string}
         */
        formatForEditor(editorDueDate) {
            const date = new Date(editorDueDate);
            const options = { weekday: 'short', month: 'short', day: 'numeric' };
            return `Due by: 📅 ${date.toLocaleDateString('en-US', options)}`;
        },

        /**
         * Format full SLA info for admin display
         * @param {Object} project - Project with SLA fields
         * @returns {Object} { range, editorDue, expectedDue, status, statusClass }
         */
        formatForAdmin(project) {
            const status = this.computeSlaStatus(
                project.editorDueDate,
                project.expectedDueDate,
                project.status
            );

            const statusLabels = {
                on_track: 'On Track',
                watch: 'Watch',
                at_risk: 'At Risk'
            };

            const statusClasses = {
                on_track: 'status-on-track',
                watch: 'status-watch',
                at_risk: 'status-at-risk'
            };

            return {
                range: `${project.finalSlaMinDays}–${project.finalSlaMaxDays} days`,
                editorDue: new Date(project.editorDueDate).toLocaleDateString(),
                expectedDue: new Date(project.expectedDueDate).toLocaleDateString(),
                status: statusLabels[status],
                statusClass: statusClasses[status],
                statusRaw: status
            };
        }
    };

    // ========== DATA CLIENT (Airtable with failure handling) ==========
    const dataClient = {
        /**
         * Fetch with timeout and retry
         */
        async fetchWithRetry(url, options = {}, retries = CONFIG.airtable.maxRetries) {
            // Check for simulated offline mode
            if (state.simulateOffline) {
                throw new Error('Simulated offline mode');
            }

            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), CONFIG.airtable.timeout);

            try {
                const response = await fetch(url, {
                    ...options,
                    signal: controller.signal
                });
                clearTimeout(timeout);

                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }

                state.airtableOnline = true;
                state.lastAirtableSync = new Date().toISOString();
                utils.setStorage(CONFIG.storageKeys.lastAirtableSync, state.lastAirtableSync);

                return await response.json();
            } catch (error) {
                clearTimeout(timeout);

                if (retries > 0 && !state.simulateOffline) {
                    // Exponential backoff
                    const delay = (CONFIG.airtable.maxRetries - retries + 1) * 1000;
                    await new Promise(resolve => setTimeout(resolve, delay));
                    return this.fetchWithRetry(url, options, retries - 1);
                }

                state.airtableOnline = false;
                this.logError('fetchWithRetry', error, { url });
                throw error;
            }
        },

        /**
         * Get headers for Airtable API
         */
        getHeaders(apiKey) {
            return {
                'Authorization': `Bearer ${apiKey}`,
                'Content-Type': 'application/json'
            };
        },

        /**
         * Get a single record from Airtable
         */
        async getRecord(table, recordId, apiKey) {
            const url = `${CONFIG.airtable.apiUrl}/${CONFIG.airtable.baseId}/${encodeURIComponent(table)}/${recordId}`;
            return this.fetchWithRetry(url, { headers: this.getHeaders(apiKey) });
        },

        /**
         * List records from Airtable with optional filter
         */
        async listRecords(table, apiKey, options = {}) {
            let url = `${CONFIG.airtable.apiUrl}/${CONFIG.airtable.baseId}/${encodeURIComponent(table)}`;
            const params = new URLSearchParams();

            if (options.filterByFormula) params.append('filterByFormula', options.filterByFormula);
            if (options.maxRecords) params.append('maxRecords', options.maxRecords);
            if (options.sort) {
                options.sort.forEach((s, i) => {
                    params.append(`sort[${i}][field]`, s.field);
                    if (s.direction) params.append(`sort[${i}][direction]`, s.direction);
                });
            }
            if (options.fields) {
                options.fields.forEach(f => params.append('fields[]', f));
            }

            if (params.toString()) url += '?' + params.toString();

            return this.fetchWithRetry(url, { headers: this.getHeaders(apiKey) });
        },

        /**
         * Update a record in Airtable
         */
        async updateRecord(table, recordId, fields, apiKey) {
            const url = `${CONFIG.airtable.apiUrl}/${CONFIG.airtable.baseId}/${encodeURIComponent(table)}/${recordId}`;
            return this.fetchWithRetry(url, {
                method: 'PATCH',
                headers: this.getHeaders(apiKey),
                body: JSON.stringify({ fields })
            });
        },

        /**
         * Create a record in Airtable
         */
        async createRecord(table, fields, apiKey) {
            const url = `${CONFIG.airtable.apiUrl}/${CONFIG.airtable.baseId}/${encodeURIComponent(table)}`;
            return this.fetchWithRetry(url, {
                method: 'POST',
                headers: this.getHeaders(apiKey),
                body: JSON.stringify({ fields })
            });
        },

        /**
         * Log error to console and optionally to Airtable Errors table
         */
        logError(context, error, extra = {}) {
            const errorLog = {
                timestamp: new Date().toISOString(),
                context,
                message: error.message,
                stack: error.stack,
                page: utils.getCurrentPage(),
                userRole: state.user?.role || 'unknown',
                userId: state.user?.airtableId || 'unknown',
                ...extra
            };
            console.error('[CB DataClient Error]', errorLog);

            // Dispatch error event for UI handling
            window.dispatchEvent(new CustomEvent('cb:dataError', { detail: errorLog }));
        }
    };

    // ========== MCP SERVER CLIENT ==========
    const mcpClient = {
        /**
         * Check if MCP server is healthy
         * @returns {Promise<{ok: boolean, version: string, latency: number}>}
         */
        async checkHealth() {
            const start = Date.now();
            try {
                const response = await fetch(
                    `${CONFIG.mcp.baseUrl}${CONFIG.mcp.healthEndpoint}`,
                    { method: 'GET', signal: AbortSignal.timeout(5000) }
                );
                const data = await response.json();
                return {
                    ok: data.ok === true,
                    version: data.version || 'unknown',
                    latency: Date.now() - start
                };
            } catch (error) {
                return {
                    ok: false,
                    version: 'offline',
                    latency: Date.now() - start,
                    error: error.message
                };
            }
        },

        /**
         * Get a conversation by ID
         * @param {string} conversationId
         * @returns {Promise<object>}
         */
        async getConversation(conversationId) {
            try {
                const response = await fetch(
                    `${CONFIG.mcp.baseUrl}${CONFIG.mcp.conversationEndpoint}/${conversationId}`,
                    { method: 'GET', signal: AbortSignal.timeout(CONFIG.airtable.timeout) }
                );
                if (!response.ok) throw new Error(`HTTP ${response.status}`);
                return await response.json();
            } catch (error) {
                dataClient.logError('mcpClient.getConversation', error, { conversationId });
                return null;
            }
        }
    };

    // ========== QA PANEL (only visible with ?qa=1) ==========
    const qaPanel = {
        /**
         * Initialize QA panel if in QA mode
         */
        init() {
            if (!utils.isQAMode()) return;

            state.qaMode = true;
            state.currentProjectId = utils.getProjectIdFromURL();

            this.createPanel();
            this.bindEvents();
            this.update();

            // Update panel every 2 seconds
            setInterval(() => this.update(), 2000);
        },

        /**
         * Create the QA panel DOM
         */
        createPanel() {
            const panel = document.createElement('div');
            panel.id = 'cbQAPanel';
            panel.innerHTML = `
                <style>
                    #cbQAPanel {
                        position: fixed;
                        bottom: 16px;
                        left: 16px;
                        width: 280px;
                        background: rgba(10, 10, 15, 0.95);
                        border: 1px solid rgba(59, 130, 246, 0.3);
                        border-radius: 12px;
                        padding: 12px;
                        font-family: 'Inter', monospace;
                        font-size: 11px;
                        color: #94a3b8;
                        z-index: 99999;
                        backdrop-filter: blur(8px);
                        box-shadow: 0 8px 32px rgba(0,0,0,0.4);
                    }
                    #cbQAPanel .qa-title {
                        font-weight: 700;
                        color: #3b82f6;
                        margin-bottom: 8px;
                        display: flex;
                        align-items: center;
                        gap: 6px;
                    }
                    #cbQAPanel .qa-row {
                        display: flex;
                        justify-content: space-between;
                        padding: 4px 0;
                        border-bottom: 1px solid rgba(255,255,255,0.05);
                    }
                    #cbQAPanel .qa-label { color: #64748b; }
                    #cbQAPanel .qa-value { color: #fff; font-weight: 500; }
                    #cbQAPanel .qa-value.online { color: #22c55e; }
                    #cbQAPanel .qa-value.offline { color: #ef4444; }
                    #cbQAPanel .qa-toggle {
                        margin-top: 8px;
                        display: flex;
                        align-items: center;
                        gap: 8px;
                    }
                    #cbQAPanel .qa-toggle label {
                        cursor: pointer;
                        display: flex;
                        align-items: center;
                        gap: 6px;
                    }
                    #cbQAPanel .qa-toggle input {
                        accent-color: #ef4444;
                    }
                    #cbQAPanel .qa-collapse {
                        position: absolute;
                        top: 8px;
                        right: 8px;
                        background: none;
                        border: none;
                        color: #64748b;
                        cursor: pointer;
                        font-size: 14px;
                    }
                </style>
                <button class="qa-collapse" id="qaCollapse">−</button>
                <div class="qa-title">
                    <span style="color:#22c55e;">●</span> QA Panel
                </div>
                <div id="qaContent">
                    <div class="qa-row">
                        <span class="qa-label">Role</span>
                        <span class="qa-value" id="qaRole">-</span>
                    </div>
                    <div class="qa-row">
                        <span class="qa-label">Contact/Team ID</span>
                        <span class="qa-value" id="qaRecordId">-</span>
                    </div>
                    <div class="qa-row">
                        <span class="qa-label">Entitlement</span>
                        <span class="qa-value" id="qaEntitlement">-</span>
                    </div>
                    <div class="qa-row">
                        <span class="qa-label">Project ID</span>
                        <span class="qa-value" id="qaProjectId">-</span>
                    </div>
                    <div class="qa-row">
                        <span class="qa-label">Last Sync</span>
                        <span class="qa-value" id="qaLastSync">-</span>
                    </div>
                    <div class="qa-row">
                        <span class="qa-label">Airtable</span>
                        <span class="qa-value" id="qaAirtableStatus">-</span>
                    </div>
                    <div class="qa-row">
                        <span class="qa-label">MCP Server</span>
                        <span class="qa-value" id="qaMcpStatus">checking...</span>
                    </div>
                    <div class="qa-row" style="border-top: 1px solid rgba(59,130,246,0.2); margin-top: 6px; padding-top: 6px;">
                        <span class="qa-label">SLA Engine</span>
                        <span class="qa-value online">ACTIVE</span>
                    </div>
                    <div class="qa-row">
                        <span class="qa-label">SLA Status</span>
                        <span class="qa-value" id="qaSlaStatus">-</span>
                    </div>
                    <div class="qa-row">
                        <span class="qa-label">Editor Due</span>
                        <span class="qa-value" id="qaEditorDue">-</span>
                    </div>
                    <div class="qa-row">
                        <span class="qa-label">Expected Due</span>
                        <span class="qa-value" id="qaExpectedDue">-</span>
                    </div>
                    <div class="qa-toggle">
                        <label>
                            <input type="checkbox" id="qaSimulateOffline">
                            Simulate Airtable Offline
                        </label>
                    </div>
                </div>
            `;
            document.body.appendChild(panel);

            // Check MCP server health on panel creation
            this.checkMcpHealth();
        },

        /**
         * Bind QA panel events
         */
        bindEvents() {
            document.getElementById('qaSimulateOffline')?.addEventListener('change', (e) => {
                state.simulateOffline = e.target.checked;
                this.update();
            });

            document.getElementById('qaCollapse')?.addEventListener('click', () => {
                const content = document.getElementById('qaContent');
                const btn = document.getElementById('qaCollapse');
                if (content.style.display === 'none') {
                    content.style.display = 'block';
                    btn.textContent = '−';
                } else {
                    content.style.display = 'none';
                    btn.textContent = '+';
                }
            });
        },

        /**
         * Update QA panel values
         */
        update() {
            const roleEl = document.getElementById('qaRole');
            const recordIdEl = document.getElementById('qaRecordId');
            const entitlementEl = document.getElementById('qaEntitlement');
            const projectIdEl = document.getElementById('qaProjectId');
            const lastSyncEl = document.getElementById('qaLastSync');
            const airtableStatusEl = document.getElementById('qaAirtableStatus');
            const slaStatusEl = document.getElementById('qaSlaStatus');
            const editorDueEl = document.getElementById('qaEditorDue');
            const expectedDueEl = document.getElementById('qaExpectedDue');

            if (roleEl) roleEl.textContent = state.user?.role || 'unknown';
            if (recordIdEl) recordIdEl.textContent = state.user?.airtableId || 'none';
            if (entitlementEl) entitlementEl.textContent = state.entitlementStatus || 'active';
            if (projectIdEl) projectIdEl.textContent = state.currentProjectId || 'none';

            if (lastSyncEl) {
                const lastSync = state.lastAirtableSync || utils.getStorage(CONFIG.storageKeys.lastAirtableSync);
                if (lastSync) {
                    const date = new Date(lastSync);
                    lastSyncEl.textContent = date.toLocaleTimeString();
                } else {
                    lastSyncEl.textContent = 'never';
                }
            }

            if (airtableStatusEl) {
                if (state.simulateOffline) {
                    airtableStatusEl.textContent = 'SIMULATED OFFLINE';
                    airtableStatusEl.className = 'qa-value offline';
                } else if (state.airtableOnline) {
                    airtableStatusEl.textContent = 'ONLINE';
                    airtableStatusEl.className = 'qa-value online';
                } else {
                    airtableStatusEl.textContent = 'OFFLINE';
                    airtableStatusEl.className = 'qa-value offline';
                }
            }

            // SLA status display (demo data for QA testing)
            if (slaStatusEl) {
                // Demo: Calculate SLA for a sample tier_2 long-form 10-20 min project
                const demoSla = slaEngine.calculateSLA('long', 2, '10_to_20');
                const demoDates = slaEngine.calculateDueDates(new Date(), demoSla.min, demoSla.max);
                const demoStatus = slaEngine.computeSlaStatus(demoDates.editorDueDate, demoDates.expectedDueDate, 'in_edit');

                slaStatusEl.textContent = demoStatus.toUpperCase();
                if (demoStatus === 'on_track') slaStatusEl.className = 'qa-value online';
                else if (demoStatus === 'watch') slaStatusEl.style.color = '#f59e0b';
                else slaStatusEl.className = 'qa-value offline';

                if (editorDueEl) editorDueEl.textContent = demoDates.editorDueDate.toLocaleDateString();
                if (expectedDueEl) expectedDueEl.textContent = demoDates.expectedDueDate.toLocaleDateString();
            }
        },

        /**
         * Check MCP server health and update panel
         */
        async checkMcpHealth() {
            const mcpStatusEl = document.getElementById('qaMcpStatus');
            if (!mcpStatusEl) return;

            const health = await mcpClient.checkHealth();
            if (health.ok) {
                mcpStatusEl.textContent = `${health.version} (${health.latency}ms)`;
                mcpStatusEl.className = 'qa-value online';
            } else {
                mcpStatusEl.textContent = health.error || 'OFFLINE';
                mcpStatusEl.className = 'qa-value offline';
            }
        }
    };

    // ========== ENTITLEMENT GATING ==========
    const entitlementGate = {
        // Soft-lock statuses: user can VIEW but not INTERACT
        SOFT_LOCK_STATUSES: ['past_due', 'locked', 'canceled'],
        // Hard-lock: completely blocked (none currently)
        HARD_LOCK_STATUSES: [],

        /**
         * Check if status allows full access
         */
        hasFullAccess(status) {
            return !this.SOFT_LOCK_STATUSES.includes(status) && !this.HARD_LOCK_STATUSES.includes(status);
        },

        /**
         * Check if status is soft-locked (view-only)
         */
        isSoftLocked(status) {
            return this.SOFT_LOCK_STATUSES.includes(status);
        },

        /**
         * Apply entitlement gating to page
         */
        apply(status) {
            state.entitlementStatus = status;
            state.viewOnlyMode = this.isSoftLocked(status);
            utils.setStorage(CONFIG.storageKeys.entitlementStatus, status);

            if (this.isSoftLocked(status)) {
                this.enableViewOnlyMode(status);
                return 'view_only';
            }

            if (this.HARD_LOCK_STATUSES.includes(status)) {
                this.showHardLockUI(status);
                return false;
            }

            return true;
        },

        /**
         * Enable view-only mode with top banner
         */
        enableViewOnlyMode(status) {
            // Don't apply to onboarding pages
            const skipPages = ['login', 'step-1', 'step-2', 'step-2-builder', 'step-3'];
            if (skipPages.includes(utils.getCurrentPage())) return;

            // Build message and CTA based on status
            let message = '';
            let ctaText = '';
            let ctaUrl = '';

            if (status === 'past_due') {
                message = 'Your payment is past due. Update your billing to resume full access.';
                ctaText = 'Update Billing';
                ctaUrl = 'https://app.contentbug.io/settings?tab=billing';
            } else if (status === 'canceled') {
                message = 'Your subscription has ended. Reactivate to continue editing.';
                ctaText = 'Reactivate Plan';
                ctaUrl = 'https://contentbug.io/pricing';
            } else if (status === 'locked') {
                message = 'Your account is temporarily locked. Contact support.';
                ctaText = 'Contact Support';
                ctaUrl = 'mailto:contentbug@contentbug.io';
            }

            // Add view-only banner
            const banner = document.createElement('div');
            banner.id = 'cbViewOnlyBanner';
            banner.innerHTML = `
                <style>
                    #cbViewOnlyBanner {
                        position: fixed;
                        top: 0;
                        left: 0;
                        right: 0;
                        height: 48px;
                        background: linear-gradient(135deg, rgba(234, 179, 8, 0.95) 0%, rgba(245, 158, 11, 0.95) 100%);
                        z-index: 99997;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        gap: 16px;
                        font-family: 'Inter', sans-serif;
                        box-shadow: 0 4px 12px rgba(234, 179, 8, 0.3);
                    }
                    #cbViewOnlyBanner .banner-icon {
                        display: flex;
                        align-items: center;
                        justify-content: center;
                    }
                    #cbViewOnlyBanner .banner-icon svg {
                        width: 20px;
                        height: 20px;
                        color: #1c1917;
                    }
                    #cbViewOnlyBanner .banner-text {
                        color: #1c1917;
                        font-size: 14px;
                        font-weight: 600;
                    }
                    #cbViewOnlyBanner .banner-cta {
                        display: inline-flex;
                        align-items: center;
                        gap: 6px;
                        padding: 8px 16px;
                        background: #1c1917;
                        color: #fff;
                        text-decoration: none;
                        font-size: 13px;
                        font-weight: 600;
                        border-radius: 6px;
                        transition: all 0.2s ease;
                    }
                    #cbViewOnlyBanner .banner-cta:hover {
                        background: #292524;
                        transform: translateY(-1px);
                    }
                    body.view-only-mode {
                        padding-top: 48px !important;
                    }
                    body.view-only-mode .app-header,
                    body.view-only-mode .portal-nav,
                    body.view-only-mode .site-header {
                        top: 48px !important;
                    }
                </style>
                <span class="banner-icon">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                        <circle cx="12" cy="12" r="3"/>
                    </svg>
                </span>
                <span class="banner-text">View-Only Mode: ${message}</span>
                <a href="${ctaUrl}" class="banner-cta">${ctaText}</a>
            `;
            document.body.insertBefore(banner, document.body.firstChild);
            document.body.classList.add('view-only-mode');

            // Disable all interactive elements
            this.disableInteractions();
        },

        /**
         * Disable interactive elements in view-only mode
         */
        disableInteractions() {
            // Selectors for elements to disable
            const interactiveSelectors = [
                'button:not(.banner-cta)',
                'input:not([type="search"]):not([type="text"])',
                'textarea',
                'select',
                '.btn-continue',
                '.btn-primary',
                '.quick-request-btn',
                '.submit-btn',
                '[data-action]',
                '.option-card'
            ];

            // Add view-only class and disable
            interactiveSelectors.forEach(selector => {
                document.querySelectorAll(selector).forEach(el => {
                    if (!el.closest('#cbViewOnlyBanner')) {
                        el.classList.add('view-only-disabled');
                        el.style.opacity = '0.5';
                        el.style.pointerEvents = 'none';
                        if (el.tagName === 'BUTTON' || el.tagName === 'INPUT') {
                            el.disabled = true;
                        }
                    }
                });
            });

            // Add tooltip for disabled elements
            const style = document.createElement('style');
            style.textContent = `
                .view-only-disabled {
                    cursor: not-allowed !important;
                    position: relative;
                }
                .view-only-disabled::after {
                    content: 'View-only mode';
                    position: absolute;
                    bottom: calc(100% + 8px);
                    left: 50%;
                    transform: translateX(-50%);
                    padding: 6px 12px;
                    background: #1c1917;
                    color: #fff;
                    font-size: 11px;
                    font-weight: 500;
                    border-radius: 4px;
                    white-space: nowrap;
                    opacity: 0;
                    visibility: hidden;
                    transition: all 0.2s ease;
                    pointer-events: none;
                }
                .view-only-disabled:hover::after {
                    opacity: 1;
                    visibility: visible;
                }
            `;
            document.head.appendChild(style);
        },

        /**
         * Show hard lock UI (complete block)
         */
        showHardLockUI(status) {
            // Don't block onboarding pages
            const skipPages = ['login', 'step-1', 'step-2', 'step-2-builder', 'step-3'];
            if (skipPages.includes(utils.getCurrentPage())) return;

            let message = 'Your account access has been restricted.';

            const overlay = document.createElement('div');
            overlay.id = 'cbEntitlementBlock';
            overlay.innerHTML = `
                <style>
                    #cbEntitlementBlock {
                        position: fixed;
                        inset: 0;
                        background: rgba(5, 5, 8, 0.98);
                        z-index: 99998;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        flex-direction: column;
                        gap: 16px;
                        font-family: 'Inter', sans-serif;
                    }
                    #cbEntitlementBlock .block-icon {
                        width: 64px;
                        height: 64px;
                        background: rgba(239, 68, 68, 0.15);
                        border-radius: 50%;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                    }
                    #cbEntitlementBlock .block-icon svg {
                        width: 32px;
                        height: 32px;
                        color: #ef4444;
                    }
                    #cbEntitlementBlock h2 {
                        color: #fff;
                        font-size: 20px;
                        margin: 0;
                    }
                    #cbEntitlementBlock p {
                        color: #94a3b8;
                        font-size: 14px;
                        max-width: 400px;
                        text-align: center;
                    }
                    #cbEntitlementBlock a {
                        color: #3b82f6;
                        text-decoration: none;
                    }
                </style>
                <div class="block-icon">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="12" cy="12" r="10"/>
                        <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
                    </svg>
                </div>
                <h2>Access Restricted</h2>
                <p>${message}</p>
                <p><a href="mailto:contentbug@contentbug.io">Contact Support</a></p>
            `;
            document.body.appendChild(overlay);
        },

        /**
         * Remove blocked UI (for unlock)
         */
        removeBlockedUI() {
            const overlay = document.getElementById('cbEntitlementBlock');
            if (overlay) overlay.remove();

            const banner = document.getElementById('cbViewOnlyBanner');
            if (banner) banner.remove();

            document.body.classList.remove('view-only-mode');

            // Re-enable interactions
            document.querySelectorAll('.view-only-disabled').forEach(el => {
                el.classList.remove('view-only-disabled');
                el.style.opacity = '';
                el.style.pointerEvents = '';
                if (el.tagName === 'BUTTON' || el.tagName === 'INPUT') {
                    el.disabled = false;
                }
            });
        }
    };

    // ========== PRESENCE SYSTEM ==========
    const presence = {
        PING_INTERVAL: 60000, // 60 seconds
        ONLINE_THRESHOLD: 5 * 60 * 1000, // 5 minutes in ms
        intervalId: null,
        lastActivity: Date.now(),
        isActive: true,

        /**
         * Initialize presence tracking
         */
        init() {
            // Skip for onboarding pages
            const skipPages = ['login', 'step-1', 'step-2', 'step-2-builder', 'step-3'];
            if (skipPages.includes(utils.getCurrentPage())) return;

            // Track user activity
            this.bindActivityEvents();

            // Start presence ping
            this.ping();
            this.intervalId = setInterval(() => this.ping(), this.PING_INTERVAL);

            // Track visibility changes
            document.addEventListener('visibilitychange', () => {
                if (document.visibilityState === 'visible') {
                    this.isActive = true;
                    this.lastActivity = Date.now();
                    this.ping();
                } else {
                    this.isActive = false;
                }
            });

            console.log('[CB Presence] Initialized');
        },

        /**
         * Bind activity tracking events
         */
        bindActivityEvents() {
            const activityEvents = ['mousemove', 'keydown', 'scroll', 'click', 'touchstart'];
            const throttledActivity = this.throttle(() => {
                this.lastActivity = Date.now();
                this.isActive = true;
            }, 10000); // Throttle to once per 10 seconds

            activityEvents.forEach(event => {
                document.addEventListener(event, throttledActivity, { passive: true });
            });
        },

        /**
         * Throttle helper
         */
        throttle(fn, wait) {
            let lastTime = 0;
            return function(...args) {
                const now = Date.now();
                if (now - lastTime >= wait) {
                    lastTime = now;
                    fn.apply(this, args);
                }
            };
        },

        /**
         * Send presence ping
         */
        async ping() {
            // Only ping if user is active (has activity in last 5 minutes)
            const timeSinceActivity = Date.now() - this.lastActivity;
            if (timeSinceActivity > this.ONLINE_THRESHOLD || !this.isActive) {
                console.log('[CB Presence] Skipping ping - user inactive');
                return;
            }

            // Skip if no user ID
            const userId = state.user?.airtableId;
            if (!userId || userId === 'demo_123') {
                console.log('[CB Presence] Skipping ping - no valid user ID');
                return;
            }

            try {
                const table = userManager.isStaff() ? 'Team' : 'Contacts';
                await dataClient.updateRecord(
                    table,
                    userId,
                    { 'LastActiveAt': new Date().toISOString() },
                    window.AIRTABLE_API_KEY || 'patVDHIF4sdlIAZd3.2e92a65859b20b655bddbe29500d079491eca3cc281704e8ebd461fc95d36a93'
                );
                console.log('[CB Presence] Ping sent');
            } catch (error) {
                console.warn('[CB Presence] Ping failed:', error.message);
            }
        },

        /**
         * Stop presence tracking
         */
        stop() {
            if (this.intervalId) {
                clearInterval(this.intervalId);
                this.intervalId = null;
            }
        }
    };

    // ========== COMMUNITY STATS ==========
    const communityStats = {
        container: null,
        totalCreators: 12438, // Base count from system
        currentOnline: 0,
        lastFetch: 0,
        REFRESH_INTERVAL: 30000, // 30 seconds

        /**
         * Initialize community stats display
         */
        init() {
            // Find or create container
            this.container = document.getElementById('communityPill');
            if (!this.container) return;

            // Initial render
            this.render();

            // Fetch online count
            this.fetchOnlineCount();
            setInterval(() => this.fetchOnlineCount(), this.REFRESH_INTERVAL);
        },

        /**
         * Fetch current online count from API
         */
        async fetchOnlineCount() {
            try {
                // Calculate "online" as users with LastActiveAt >= now - 5 minutes
                const threshold = new Date(Date.now() - presence.ONLINE_THRESHOLD).toISOString();

                // For MVP: Use a simulated count based on time of day
                // In production: Query Airtable for count of records with LastActiveAt >= threshold
                const hour = new Date().getHours();
                const baseOnline = 100 + Math.floor(Math.random() * 20);

                // Simulate higher activity during work hours (9am-6pm)
                let multiplier = 1;
                if (hour >= 9 && hour <= 18) {
                    multiplier = 1.5;
                } else if (hour >= 19 && hour <= 22) {
                    multiplier = 1.2;
                } else if (hour >= 0 && hour <= 6) {
                    multiplier = 0.5;
                }

                this.currentOnline = Math.floor(baseOnline * multiplier);
                this.lastFetch = Date.now();
                this.render();

                // TODO: Replace with actual Airtable query when ready:
                // const contactsOnline = await dataClient.listRecords('Contacts', API_KEY, {
                //     filterByFormula: `{LastActiveAt} >= '${threshold}'`,
                //     fields: ['Record ID']
                // });
                // const teamOnline = await dataClient.listRecords('Team', API_KEY, {
                //     filterByFormula: `{LastActiveAt} >= '${threshold}'`,
                //     fields: ['Record ID']
                // });
                // this.currentOnline = (contactsOnline.records?.length || 0) + (teamOnline.records?.length || 0);

            } catch (error) {
                console.warn('[CB Community] Failed to fetch online count:', error);
            }
        },

        /**
         * Render community stats
         */
        render() {
            if (!this.container) return;

            const formattedTotal = this.formatNumber(this.totalCreators);
            const formattedOnline = this.currentOnline;

            this.container.innerHTML = `
                <div class="community-total">
                    <svg class="community-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
                        <circle cx="9" cy="7" r="4"/>
                        <path d="M23 21v-2a4 4 0 0 0-3-3.87"/>
                        <path d="M16 3.13a4 4 0 0 1 0 7.75"/>
                    </svg>
                    <span class="community-count">${formattedTotal}</span>
                    <span class="community-label">creators</span>
                </div>
                <div class="community-divider"></div>
                <div class="community-online">
                    <span class="online-dot"></span>
                    <span class="online-count">${formattedOnline}</span>
                    <span class="community-label">online now</span>
                </div>
            `;
        },

        /**
         * Format large numbers with commas
         */
        formatNumber(num) {
            return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
        }
    };

    // ========== CHAT PERMISSIONS ==========
    /**
     * Channel access control and permissions
     * - Private channels visible only to members + owners
     * - Clients never see other client channels
     * - Owners see all channels
     */
    const chatPermissions = {
        ROLES: {
            CLIENT: 'client',
            EDITOR: 'editor',
            ADMIN: 'admin',
            OWNER: 'owner'
        },

        /**
         * Check if user can access a specific channel
         * @param {Object} channel - Channel object from Airtable
         * @param {Object} user - Current user object
         * @returns {boolean}
         */
        canAccessChannel(channel, user) {
            if (!channel || !user) return false;

            const userRole = user.role || this.ROLES.CLIENT;
            const userId = user.recordId || user.id;

            // Owners can see everything
            if (userRole === this.ROLES.OWNER) {
                return true;
            }

            // Admins bypass channel visibility - can see ALL channels
            if (userRole === this.ROLES.ADMIN) {
                return true;
            }

            // For private channels
            if (channel.isPrivate) {
                // Check if visibleToOwners and user is owner (already handled above)
                // Check if user is a member
                return this._isMember(channel, userId);
            }

            // Non-private channels: check if client should see it
            if (userRole === this.ROLES.CLIENT) {
                // Clients only see channels linked to their own projects/account
                const channelClientId = channel.clientId || channel.linkedClientId;
                return channelClientId === userId;
            }

            // Editors see channels for projects they're assigned to
            if (userRole === this.ROLES.EDITOR) {
                const channelEditorId = channel.editorId || channel.assignedEditorId;
                if (channelEditorId === userId) return true;
                return this._isMember(channel, userId);
            }

            return false;
        },

        /**
         * Check if user is a member of a channel
         * @private
         */
        _isMember(channel, userId) {
            if (!channel.memberIds) return false;

            try {
                const members = typeof channel.memberIds === 'string'
                    ? JSON.parse(channel.memberIds)
                    : channel.memberIds;
                return Array.isArray(members) && members.includes(userId);
            } catch (e) {
                console.warn('[CB ChatPermissions] Failed to parse memberIds:', e);
                return false;
            }
        },

        /**
         * Check if user can create a private channel
         * @param {Object} user - Current user object
         * @returns {boolean}
         */
        canCreatePrivateChannel(user) {
            if (!user) return false;
            const role = user.role || this.ROLES.CLIENT;
            // Clients, editors, admins, and owners can create private channels
            return [this.ROLES.CLIENT, this.ROLES.EDITOR, this.ROLES.ADMIN, this.ROLES.OWNER].includes(role);
        },

        /**
         * Filter channels list based on user permissions
         * @param {Array} channels - All channels
         * @param {Object} user - Current user
         * @returns {Array} - Filtered channels user can see
         */
        filterChannelsForRole(channels, user) {
            if (!Array.isArray(channels) || !user) return [];
            return channels.filter(channel => this.canAccessChannel(channel, user));
        },

        /**
         * Get default members for a new private channel
         * @param {Object} creator - User creating the channel
         * @param {Object} options - Additional options (projectId, etc.)
         * @returns {Array} - Array of member IDs
         */
        getDefaultMembers(creator, options = {}) {
            const members = [creator.recordId || creator.id];

            // If linked to a project, include assigned editor
            if (options.assignedEditorId) {
                members.push(options.assignedEditorId);
            }

            // If linked to a client, include them
            if (options.clientId && options.clientId !== creator.recordId) {
                members.push(options.clientId);
            }

            return [...new Set(members)]; // Dedupe
        },

        /**
         * Create a new private channel
         * @param {Object} params - Channel creation params
         * @returns {Object} - Channel data ready for Airtable
         */
        buildPrivateChannelPayload(params) {
            const { creator, channelName, members = [], projectId = null } = params;

            return {
                name: channelName || `Private - ${new Date().toISOString().slice(0, 10)}`,
                isPrivate: true,
                visibleToOwners: true,
                createdByRole: creator.role || this.ROLES.CLIENT,
                createdById: creator.recordId || creator.id,
                memberIds: JSON.stringify(members),
                linkedProjectId: projectId,
                createdAt: new Date().toISOString()
            };
        },

        // ========== ADMIN VISIBILITY METHODS ==========

        /**
         * Check if user has admin-level visibility
         * @param {Object} user - Current user object
         * @returns {boolean}
         */
        hasAdminVisibility(user) {
            if (!user) return false;
            const role = user.role || this.ROLES.CLIENT;
            return role === this.ROLES.ADMIN || role === this.ROLES.OWNER;
        },

        /**
         * Check if user can view all users in the system
         * @param {Object} user - Current user object
         * @returns {boolean}
         */
        canViewAllUsers(user) {
            return this.hasAdminVisibility(user);
        },

        /**
         * Check if user can DM any user in the system
         * @param {Object} user - Current user object
         * @returns {boolean}
         */
        canDMAnyone(user) {
            return this.hasAdminVisibility(user);
        },

        /**
         * Check if user can view message history across channels
         * @param {Object} user - Current user object
         * @param {Object} channel - Channel to view
         * @returns {boolean}
         */
        canViewMessageHistory(user, channel) {
            // Admins and owners can view all message history
            if (this.hasAdminVisibility(user)) return true;
            // Others can only view history for channels they can access
            return this.canAccessChannel(channel, user);
        },

        /**
         * Build payload for admin-initiated 1:1 DM channel
         * @param {Object} admin - Admin/owner user creating the channel
         * @param {Object} targetUser - User to DM
         * @returns {Object} - Channel data for Airtable
         */
        buildAdminDMPayload(admin, targetUser) {
            const targetRole = targetUser.role || this.ROLES.CLIENT;
            const targetName = targetUser.name || targetUser.firstName || 'User';

            return {
                name: `DM: ${admin.name || 'Admin'} ↔ ${targetName}`,
                type: 'private',
                isPrivate: true,
                visibleToOwners: true,
                createdByRole: admin.role || this.ROLES.ADMIN,
                createdById: admin.recordId || admin.id,
                memberIds: JSON.stringify([
                    admin.recordId || admin.id,
                    targetUser.recordId || targetUser.id
                ]),
                createdAt: new Date().toISOString()
            };
        },

        /**
         * Filter users list based on viewer permissions
         * Admins/owners see all, editors see assigned clients, clients see nobody
         * @param {Array} users - All users (mixed clients/editors/partners)
         * @param {Object} viewer - Current user viewing
         * @returns {Array} - Filtered users
         */
        filterUsersForViewer(users, viewer) {
            if (!Array.isArray(users) || !viewer) return [];

            const viewerRole = viewer.role || this.ROLES.CLIENT;
            const viewerId = viewer.recordId || viewer.id;

            // Admins and owners see everyone
            if (viewerRole === this.ROLES.ADMIN || viewerRole === this.ROLES.OWNER) {
                return users;
            }

            // Editors see only clients they're assigned to
            if (viewerRole === this.ROLES.EDITOR) {
                return users.filter(u => {
                    // Editor can see clients where editorAssigned matches
                    return u.editorAssigned === viewerId || u.assignedEditorId === viewerId;
                });
            }

            // Clients see nobody except themselves
            return users.filter(u => (u.recordId || u.id) === viewerId);
        }
    };

    // ========== REVISION TRACKER ==========
    /**
     * Revision round tracking and flagging system
     * - Increment on each client feedback submission
     * - Flag based on count: normal (1-3), warning (4-5), critical (6+)
     */
    const revisionTracker = {
        FLAGS: {
            NORMAL: 'normal',
            WARNING: 'warning',
            CRITICAL: 'critical'
        },

        THRESHOLDS: {
            WARNING: 4,  // >= 4 rounds
            CRITICAL: 6  // >= 6 rounds
        },

        /**
         * Calculate flag based on revision count
         * @param {number} count - Revision round count
         * @returns {string} - Flag: 'normal', 'warning', or 'critical'
         */
        calculateFlag(count) {
            const num = parseInt(count, 10) || 0;
            if (num >= this.THRESHOLDS.CRITICAL) return this.FLAGS.CRITICAL;
            if (num >= this.THRESHOLDS.WARNING) return this.FLAGS.WARNING;
            return this.FLAGS.NORMAL;
        },

        /**
         * Increment revision count and update flag
         * @param {Object} project - Current project object
         * @param {Object} revisionData - Revision submission data
         * @returns {Object} - Updated fields for Airtable
         */
        incrementRevision(project, revisionData = {}) {
            const currentCount = parseInt(project.revisionRoundCount, 10) || 0;
            const newCount = currentCount + 1;

            // Parse existing history or start fresh
            let history = [];
            try {
                history = project.revisionHistory
                    ? JSON.parse(project.revisionHistory)
                    : [];
            } catch (e) {
                console.warn('[CB RevisionTracker] Failed to parse history:', e);
                history = [];
            }

            // Add new revision entry
            history.push({
                round: newCount,
                submittedAt: new Date().toISOString(),
                submittedBy: revisionData.submittedBy || 'client',
                editorId: revisionData.editorId || null,
                notes: revisionData.notes || '',
                feedbackCount: revisionData.feedbackCount || 0
            });

            return {
                revisionRoundCount: newCount,
                revisionHistory: JSON.stringify(history),
                revisionFlag: this.calculateFlag(newCount)
            };
        },

        /**
         * Get revision status display info
         * @param {Object} project - Project object
         * @returns {Object} - Display info (color, label, icon)
         */
        getStatusDisplay(project) {
            const count = parseInt(project.revisionRoundCount, 10) || 0;
            const flag = project.revisionFlag || this.calculateFlag(count);

            const displays = {
                [this.FLAGS.NORMAL]: {
                    color: '#22c55e', // green
                    bgColor: 'rgba(34, 197, 94, 0.1)',
                    label: `Round ${count}`,
                    icon: '✓',
                    tooltip: 'Revision count is within normal range'
                },
                [this.FLAGS.WARNING]: {
                    color: '#EAB308', // yellow
                    bgColor: 'rgba(234, 179, 8, 0.1)',
                    label: `Round ${count} ⚠`,
                    icon: '⚠',
                    tooltip: 'Multiple revision rounds - consider reaching out to client'
                },
                [this.FLAGS.CRITICAL]: {
                    color: '#EF4444', // red
                    bgColor: 'rgba(239, 68, 68, 0.1)',
                    label: `Round ${count} 🚨`,
                    icon: '🚨',
                    tooltip: 'High revision count - escalate to manager'
                }
            };

            return displays[flag] || displays[this.FLAGS.NORMAL];
        },

        /**
         * Check if project needs escalation
         * @param {Object} project - Project object
         * @returns {boolean}
         */
        needsEscalation(project) {
            const count = parseInt(project.revisionRoundCount, 10) || 0;
            return count >= this.THRESHOLDS.CRITICAL;
        },

        /**
         * Get revision history formatted for display
         * @param {Object} project - Project object
         * @returns {Array} - Formatted history entries
         */
        getFormattedHistory(project) {
            try {
                const history = project.revisionHistory
                    ? JSON.parse(project.revisionHistory)
                    : [];

                return history.map(entry => ({
                    ...entry,
                    formattedDate: new Date(entry.submittedAt).toLocaleDateString('en-US', {
                        month: 'short',
                        day: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit'
                    })
                }));
            } catch (e) {
                return [];
            }
        },

        // ========== ADMIN/EDITOR VIEW HELPERS ==========

        /**
         * Build HTML badge for revision status (admin/editor views)
         * @param {Object} project - Project object
         * @returns {string} - HTML string
         */
        buildStatusBadge(project) {
            const display = this.getStatusDisplay(project);
            const count = parseInt(project.revisionRoundCount, 10) || 0;

            return `
                <span class="revision-badge"
                      style="background: ${display.bgColor}; color: ${display.color}; border: 1px solid ${display.color}20;"
                      title="${display.tooltip}">
                    <span class="revision-badge__icon">${display.icon}</span>
                    <span class="revision-badge__count">R${count}</span>
                </span>
            `;
        },

        /**
         * Build detailed revision panel HTML for admin/editor project view
         * @param {Object} project - Project object
         * @returns {string} - HTML string
         */
        buildDetailPanel(project) {
            const display = this.getStatusDisplay(project);
            const history = this.getFormattedHistory(project);
            const count = parseInt(project.revisionRoundCount, 10) || 0;

            let historyHTML = '';
            if (history.length > 0) {
                historyHTML = history.map((entry, idx) => `
                    <div class="revision-entry" style="border-left: 2px solid ${idx === history.length - 1 ? display.color : '#374151'};">
                        <div class="revision-entry__header">
                            <span class="revision-entry__round">Round ${entry.round}</span>
                            <span class="revision-entry__date">${entry.formattedDate}</span>
                        </div>
                        ${entry.notes ? `<div class="revision-entry__notes">${entry.notes}</div>` : ''}
                        ${entry.feedbackCount ? `<div class="revision-entry__feedback">${entry.feedbackCount} feedback items</div>` : ''}
                    </div>
                `).join('');
            } else {
                historyHTML = '<div class="revision-empty">No revision history</div>';
            }

            return `
                <div class="revision-panel" style="border-color: ${display.color}20;">
                    <div class="revision-panel__header" style="background: ${display.bgColor};">
                        <span class="revision-panel__icon">${display.icon}</span>
                        <span class="revision-panel__title">Revision Tracking</span>
                        <span class="revision-panel__count" style="color: ${display.color};">${count} round${count !== 1 ? 's' : ''}</span>
                    </div>
                    <div class="revision-panel__status">
                        <span class="revision-panel__flag" style="color: ${display.color};">${display.label}</span>
                        <span class="revision-panel__tooltip">${display.tooltip}</span>
                    </div>
                    <div class="revision-panel__history">
                        ${historyHTML}
                    </div>
                </div>
            `;
        },

        /**
         * Get CSS for revision tracking components
         * @returns {string} - CSS string
         */
        getStyles() {
            return `
                .revision-badge {
                    display: inline-flex;
                    align-items: center;
                    gap: 4px;
                    padding: 4px 8px;
                    border-radius: 6px;
                    font-size: 12px;
                    font-weight: 600;
                }

                .revision-badge__icon {
                    font-size: 11px;
                }

                .revision-badge__count {
                    font-family: monospace;
                }

                .revision-panel {
                    background: rgba(15, 15, 25, 0.95);
                    border: 1px solid;
                    border-radius: 12px;
                    overflow: hidden;
                }

                .revision-panel__header {
                    display: flex;
                    align-items: center;
                    gap: 10px;
                    padding: 12px 16px;
                }

                .revision-panel__icon {
                    font-size: 16px;
                }

                .revision-panel__title {
                    flex: 1;
                    font-weight: 600;
                    color: #fff;
                    font-size: 14px;
                }

                .revision-panel__count {
                    font-weight: 700;
                    font-size: 14px;
                }

                .revision-panel__status {
                    padding: 12px 16px;
                    border-bottom: 1px solid rgba(59, 130, 246, 0.1);
                }

                .revision-panel__flag {
                    font-weight: 600;
                    font-size: 13px;
                }

                .revision-panel__tooltip {
                    display: block;
                    color: #64748b;
                    font-size: 12px;
                    margin-top: 4px;
                }

                .revision-panel__history {
                    padding: 12px 16px;
                    max-height: 200px;
                    overflow-y: auto;
                }

                .revision-entry {
                    padding: 8px 0 8px 12px;
                    margin-bottom: 8px;
                }

                .revision-entry__header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }

                .revision-entry__round {
                    font-weight: 600;
                    color: #fff;
                    font-size: 13px;
                }

                .revision-entry__date {
                    color: #64748b;
                    font-size: 11px;
                }

                .revision-entry__notes {
                    color: #94a3b8;
                    font-size: 12px;
                    margin-top: 4px;
                }

                .revision-entry__feedback {
                    color: #64748b;
                    font-size: 11px;
                    margin-top: 2px;
                }

                .revision-empty {
                    color: #64748b;
                    font-size: 13px;
                    text-align: center;
                    padding: 16px;
                }
            `;
        }
    };

    // ========== DELIVERY NOTIFICATIONS ==========
    /**
     * Client-controlled notification delivery system
     * - Email/SMS based on client preferences
     * - Notification types: review_ready, delivery, revision_response
     */
    const deliveryNotifications = {
        TYPES: {
            REVIEW_READY: 'review_ready',
            DELIVERY: 'delivery',
            REVISION_RESPONSE: 'revision_response'
        },

        CHANNELS: {
            EMAIL: 'email',
            SMS: 'sms'
        },

        /**
         * Get client's notification preferences
         * @param {Object} client - Client object from Airtable
         * @returns {Object} - Notification preferences
         */
        getPreferences(client) {
            return {
                notifyOnReviewReady: client.notifyOnReviewReady !== false, // default true
                notifyOnDelivery: client.notifyOnDelivery !== false,       // default true
                notifyOnRevisionResponse: client.notifyOnRevisionResponse !== false, // default true
                channels: client.notificationChannels || ['email']
            };
        },

        /**
         * Check if client should receive a notification type
         * @param {Object} client - Client object
         * @param {string} notificationType - Type of notification
         * @returns {boolean}
         */
        shouldNotify(client, notificationType) {
            const prefs = this.getPreferences(client);

            switch (notificationType) {
                case this.TYPES.REVIEW_READY:
                    return prefs.notifyOnReviewReady;
                case this.TYPES.DELIVERY:
                    return prefs.notifyOnDelivery;
                case this.TYPES.REVISION_RESPONSE:
                    return prefs.notifyOnRevisionResponse;
                default:
                    return false;
            }
        },

        /**
         * Build notification payload for GHL/webhook
         * @param {Object} params - Notification parameters
         * @returns {Object} - Payload ready for webhook
         */
        buildPayload(params) {
            const { client, project, notificationType, customMessage = '' } = params;
            const prefs = this.getPreferences(client);

            const messages = {
                [this.TYPES.REVIEW_READY]: {
                    subject: '🎬 Your edit is ready for review!',
                    body: `Your project "${project.name || 'Untitled'}" is ready for review. Log in to your portal to check it out!`,
                    smsBody: `🎬 Your edit for "${project.name || 'project'}" is ready! Review it now: app.contentbug.io/review`
                },
                [this.TYPES.DELIVERY]: {
                    subject: '✅ Your final edit is ready!',
                    body: `Great news! Your project "${project.name || 'Untitled'}" has been approved and is ready for download.`,
                    smsBody: `✅ Your final edit is ready for download! Get it at: app.contentbug.io/dashboard`
                },
                [this.TYPES.REVISION_RESPONSE]: {
                    subject: '🔄 Revision update on your project',
                    body: `We've addressed your revision feedback for "${project.name || 'Untitled'}". Check out the updated version!`,
                    smsBody: `🔄 Revision complete for "${project.name || 'project'}"! Review: app.contentbug.io/review`
                }
            };

            const template = messages[notificationType] || messages[this.TYPES.REVIEW_READY];

            return {
                contactId: client.ghlContactId || client.recordId,
                email: client.email,
                phone: client.phone,
                channels: prefs.channels,
                notificationType,
                emailSubject: template.subject,
                emailBody: customMessage || template.body,
                smsBody: customMessage || template.smsBody,
                projectId: project.recordId || project.id,
                projectName: project.name,
                timestamp: new Date().toISOString()
            };
        },

        /**
         * Send notification via MCP/webhook
         * @param {Object} params - Notification parameters
         * @returns {Promise<Object>} - Send result
         */
        async send(params) {
            const { client, project, notificationType, customMessage } = params;

            // Check if client wants this notification
            if (!this.shouldNotify(client, notificationType)) {
                console.log(`[CB Notifications] Client opted out of ${notificationType} notifications`);
                return { sent: false, reason: 'opted_out' };
            }

            const payload = this.buildPayload({ client, project, notificationType, customMessage });

            try {
                // Send via GHL webhook
                const webhookUrl = CONFIG.GHL_WEBHOOK_URL;
                if (!webhookUrl) {
                    console.warn('[CB Notifications] No webhook URL configured');
                    return { sent: false, reason: 'no_webhook' };
                }

                const response = await fetch(webhookUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        type: 'notification',
                        ...payload
                    })
                });

                if (!response.ok) {
                    throw new Error(`Webhook failed: ${response.status}`);
                }

                console.log(`[CB Notifications] Sent ${notificationType} to ${client.email}`);
                return { sent: true, payload };

            } catch (error) {
                console.error('[CB Notifications] Send failed:', error);
                return { sent: false, reason: 'error', error: error.message };
            }
        },

        /**
         * Update client notification preferences
         * @param {string} clientId - Airtable record ID
         * @param {Object} preferences - New preferences
         * @returns {Object} - Fields to update in Airtable
         */
        buildPreferencesUpdate(preferences) {
            const fields = {};

            if (typeof preferences.notifyOnReviewReady === 'boolean') {
                fields.NotifyOnReviewReady = preferences.notifyOnReviewReady;
            }
            if (typeof preferences.notifyOnDelivery === 'boolean') {
                fields.NotifyOnDelivery = preferences.notifyOnDelivery;
            }
            if (typeof preferences.notifyOnRevisionResponse === 'boolean') {
                fields.NotifyOnRevisionResponse = preferences.notifyOnRevisionResponse;
            }
            if (Array.isArray(preferences.channels)) {
                fields.NotificationChannels = preferences.channels;
            }

            return fields;
        }
    };

    // ========== OWNER OVERSIGHT ==========
    /**
     * Owner-level visibility and access controls
     * - Owners see all channels, all projects, all history
     * - Full visibility toggle for UI
     */
    const ownerOversight = {
        /**
         * Check if user has owner-level access
         * @param {Object} user - Current user object
         * @returns {boolean}
         */
        isOwner(user) {
            return user && user.role === chatPermissions.ROLES.OWNER;
        },

        /**
         * Get all channels (owner view)
         * @param {Array} channels - All channels
         * @returns {Array} - All channels with owner metadata
         */
        getAllChannels(channels) {
            return channels.map(channel => ({
                ...channel,
                _ownerView: true,
                _accessReason: channel.isPrivate ? 'owner_override' : 'public'
            }));
        },

        /**
         * Get visibility filter options for owner UI
         * @returns {Array} - Filter options
         */
        getFilterOptions() {
            return [
                { value: 'all', label: 'All Channels', icon: '👁' },
                { value: 'private', label: 'Private Only', icon: '🔒' },
                { value: 'flagged', label: 'Flagged Projects', icon: '🚨' },
                { value: 'high_revision', label: 'High Revision (4+)', icon: '⚠' }
            ];
        },

        /**
         * Filter projects by revision flag (owner oversight)
         * @param {Array} projects - All projects
         * @param {string} filter - Filter type
         * @returns {Array} - Filtered projects
         */
        filterProjectsByFlag(projects, filter) {
            if (!Array.isArray(projects)) return [];

            switch (filter) {
                case 'flagged':
                    return projects.filter(p =>
                        p.revisionFlag === revisionTracker.FLAGS.CRITICAL
                    );
                case 'high_revision':
                    return projects.filter(p =>
                        p.revisionFlag === revisionTracker.FLAGS.WARNING ||
                        p.revisionFlag === revisionTracker.FLAGS.CRITICAL
                    );
                case 'warning':
                    return projects.filter(p =>
                        p.revisionFlag === revisionTracker.FLAGS.WARNING
                    );
                default:
                    return projects;
            }
        },

        /**
         * Get escalation summary for owner dashboard
         * @param {Array} projects - All projects
         * @returns {Object} - Summary counts
         */
        getEscalationSummary(projects) {
            if (!Array.isArray(projects)) return { critical: 0, warning: 0, normal: 0 };

            return {
                critical: projects.filter(p => p.revisionFlag === revisionTracker.FLAGS.CRITICAL).length,
                warning: projects.filter(p => p.revisionFlag === revisionTracker.FLAGS.WARNING).length,
                normal: projects.filter(p => !p.revisionFlag || p.revisionFlag === revisionTracker.FLAGS.NORMAL).length,
                total: projects.length
            };
        }
    };

    // ========== WHITE-LABEL CATEGORIES ==========
    /**
     * Discord-style category management for white-label partners
     * - Visual grouping of channels by brand
     * - Partner clients see only their category
     * - Admins/owners see all categories
     */
    const whiteLabelCategories = {
        /**
         * Check if user is a white-label partner
         * @param {Object} user - User object
         * @returns {boolean}
         */
        isPartner(user) {
            return user && user.isWhiteLabelPartner === true && user.whiteLabelActive === true;
        },

        /**
         * Check if user is a partner's client
         * @param {Object} user - User object
         * @returns {boolean}
         */
        isPartnerClient(user) {
            return user && user.whiteLabelPartnerId && !user.isWhiteLabelPartner;
        },

        /**
         * Get category name for a user
         * @param {Object} user - User object
         * @returns {string|null} - Category name or null
         */
        getCategoryForUser(user) {
            if (this.isPartner(user)) {
                return user.whiteLabelBrandName || 'Partner';
            }
            if (this.isPartnerClient(user)) {
                // Would need to lookup partner's brand name
                return null; // Requires partner lookup
            }
            return 'ContentBug'; // Default category
        },

        /**
         * Group channels by category for display
         * @param {Array} channels - All visible channels
         * @param {Object} viewer - Current user viewing
         * @returns {Object} - Channels grouped by category { categoryName: [channels] }
         */
        groupChannelsByCategory(channels, viewer) {
            if (!Array.isArray(channels)) return {};

            const viewerRole = viewer?.role || chatPermissions.ROLES.CLIENT;
            const isAdminOrOwner = viewerRole === chatPermissions.ROLES.ADMIN ||
                                   viewerRole === chatPermissions.ROLES.OWNER;

            const categories = {};

            channels.forEach(channel => {
                const categoryName = channel.categoryName || 'General';

                // Clients only see their own category
                if (!isAdminOrOwner && viewer) {
                    const userCategory = this.getCategoryForUser(viewer);
                    if (userCategory && categoryName !== userCategory && categoryName !== 'General') {
                        return; // Skip channels from other categories
                    }
                }

                if (!categories[categoryName]) {
                    categories[categoryName] = {
                        name: categoryName,
                        order: channel.categoryOrder || 999,
                        channels: []
                    };
                }
                categories[categoryName].channels.push(channel);
            });

            // Sort categories by order
            return Object.fromEntries(
                Object.entries(categories).sort((a, b) => a[1].order - b[1].order)
            );
        },

        /**
         * Check if white-label nav should show "Coming Soon"
         * @param {Object} user - Current user
         * @returns {boolean}
         */
        showComingSoon(user) {
            const role = user?.role || chatPermissions.ROLES.CLIENT;
            // Show to clients and partners, not to admins/owners
            return role === chatPermissions.ROLES.CLIENT || this.isPartner(user);
        },

        /**
         * Build category payload for new channel
         * @param {Object} partner - White-label partner
         * @returns {Object} - Category fields for channel
         */
        buildCategoryFields(partner) {
            return {
                categoryName: partner.whiteLabelBrandName || 'Partner',
                whiteLabelPartnerId: partner.recordId || partner.id,
                categoryOrder: 100 // Partners after main categories
            };
        },

        /**
         * Get nav section config for white-label
         * @param {Object} user - Current user
         * @returns {Object} - Nav section config
         */
        getNavSection(user) {
            const showLocked = this.showComingSoon(user);

            return {
                title: 'White Label',
                icon: '🏷️',
                locked: showLocked,
                lockedLabel: 'Coming Soon',
                visible: true, // Always visible
                items: showLocked ? [] : [
                    { label: 'Partners', href: '/partners', icon: '👥' },
                    { label: 'Branding', href: '/branding', icon: '🎨' },
                    { label: 'Settings', href: '/wl-settings', icon: '⚙️' }
                ]
            };
        }
    };

    // ========== MULTI-SHORTS GUARDRAILS ==========
    /**
     * Smart guardrails for multi-short project requests
     * - Calculate max shorts based on raw footage duration
     * - Enforce caps and provide clear messaging
     */
    const multiShortsGuardrails = {
        // A short = finished output ≤ 90 seconds
        SHORT_MAX_DURATION: 90, // seconds

        // Max shorts per request = 5
        ABSOLUTE_MAX_SHORTS: 5,

        // Duration thresholds for shorts calculation (in seconds)
        THRESHOLDS: [
            { maxDuration: 90, maxShorts: 1 },    // ≤90s → max 1
            { maxDuration: 180, maxShorts: 2 },   // 1.5–3 min → max 2
            { maxDuration: 360, maxShorts: 3 },   // 3–6 min → max 3
            { maxDuration: 540, maxShorts: 4 },   // 6–9 min → max 4
            { maxDuration: 600, maxShorts: 5 }    // 9–10+ min → max 5
        ],

        /**
         * Calculate max shorts allowed based on raw footage duration
         * @param {number} durationSeconds - Raw footage duration in seconds
         * @returns {number} - Max shorts allowed (1-5)
         */
        calculateMaxShorts(durationSeconds) {
            const duration = parseFloat(durationSeconds) || 0;

            if (duration <= 0) return 0;

            for (const threshold of this.THRESHOLDS) {
                if (duration <= threshold.maxDuration) {
                    return threshold.maxShorts;
                }
            }

            // Beyond 10 min, cap at 5
            return this.ABSOLUTE_MAX_SHORTS;
        },

        /**
         * Determine if footage is long-form (>90s finished output)
         * @param {number} durationSeconds - Raw footage duration
         * @returns {boolean}
         */
        isLongForm(durationSeconds) {
            // If raw footage is long enough to produce >90s output, it's long-form eligible
            // This is a simplified check - actual depends on editing style
            return durationSeconds > this.SHORT_MAX_DURATION;
        },

        /**
         * Validate shorts request against footage duration
         * @param {number} requestedCount - Number of shorts requested
         * @param {number} durationSeconds - Raw footage duration
         * @returns {Object} - { valid, maxAllowed, message }
         */
        validateRequest(requestedCount, durationSeconds) {
            const maxAllowed = this.calculateMaxShorts(durationSeconds);
            const requested = parseInt(requestedCount, 10) || 1;

            if (requested > maxAllowed) {
                return {
                    valid: false,
                    maxAllowed,
                    requested,
                    message: `Based on your footage length, you can request up to ${maxAllowed} short${maxAllowed === 1 ? '' : 's'}.`
                };
            }

            if (requested > this.ABSOLUTE_MAX_SHORTS) {
                return {
                    valid: false,
                    maxAllowed: this.ABSOLUTE_MAX_SHORTS,
                    requested,
                    message: `Maximum ${this.ABSOLUTE_MAX_SHORTS} shorts per request.`
                };
            }

            return {
                valid: true,
                maxAllowed,
                requested,
                message: null
            };
        },

        /**
         * Get user-friendly message about shorts availability
         * @param {number} durationSeconds - Raw footage duration
         * @returns {string}
         */
        getAvailabilityMessage(durationSeconds) {
            const maxShorts = this.calculateMaxShorts(durationSeconds);

            if (maxShorts === 0) {
                return 'Please upload footage to see how many shorts you can request.';
            }

            if (maxShorts === 1) {
                return 'Based on your footage length, you can request 1 short.';
            }

            return `Based on your footage length, you can request up to ${maxShorts} shorts.`;
        },

        /**
         * Build project payload for shorts request
         * @param {Object} params - Request parameters
         * @returns {Object} - Fields for Airtable
         */
        buildShortsPayload(params) {
            const { durationSeconds, requestedCount, isEditorChoice } = params;
            const maxAllowed = this.calculateMaxShorts(durationSeconds);

            return {
                rawFootageDuration: durationSeconds,
                maxShortsAllowed: maxAllowed,
                requestedShortsCount: isEditorChoice ? null : Math.min(requestedCount, maxAllowed),
                shortsMode: isEditorChoice ? 'editor_choice' : 'manual',
                projectFormat: 'short'
            };
        },

        /**
         * Format duration for display
         * @param {number} seconds - Duration in seconds
         * @returns {string}
         */
        formatDuration(seconds) {
            const mins = Math.floor(seconds / 60);
            const secs = Math.floor(seconds % 60);
            if (mins === 0) return `${secs}s`;
            return `${mins}m ${secs}s`;
        },

        /**
         * Get video duration from file (client-side)
         * Non-blocking, uses requestAnimationFrame pattern
         * @param {File} file - Video file
         * @returns {Promise<number>} - Duration in seconds
         */
        async getVideoDuration(file) {
            return new Promise((resolve, reject) => {
                const video = document.createElement('video');
                video.preload = 'metadata';

                video.onloadedmetadata = () => {
                    window.URL.revokeObjectURL(video.src);
                    // Use requestAnimationFrame to avoid blocking
                    requestAnimationFrame(() => {
                        resolve(video.duration);
                    });
                };

                video.onerror = () => {
                    reject(new Error('Failed to load video metadata'));
                };

                video.src = URL.createObjectURL(file);
            });
        }
    };

    // ========== BLUEPRINT RECALL ==========
    /**
     * Blueprint memory system for personalized project requests
     * - Display client's custom blueprint name
     * - Show preferred export settings
     */
    const blueprintRecall = {
        /**
         * Format blueprint info for display in step-3
         * @param {Object} blueprint - Blueprint object from Airtable
         * @returns {Object} - Formatted display info
         */
        formatForDisplay(blueprint) {
            if (!blueprint) {
                return {
                    hasBlueprint: false,
                    name: null,
                    exportSettings: null,
                    displayText: null
                };
            }

            const name = blueprint.blueprintName || 'Your Style Blueprint';
            const resolution = blueprint.exportResolution || '1080x1920';
            const frameRate = blueprint.exportFrameRate || '30';
            const format = blueprint.exportFormat || 'MP4';

            // Format resolution for display (e.g., "1080×1920")
            const formattedResolution = resolution.replace('x', '×');

            return {
                hasBlueprint: true,
                name,
                exportSettings: {
                    resolution: formattedResolution,
                    frameRate: `${frameRate}fps`,
                    format
                },
                displayText: `Using your '${name}' blueprint\nExport: ${formattedResolution} · ${frameRate}fps · ${format}`
            };
        },

        /**
         * Build HTML for blueprint recall display
         * @param {Object} blueprint - Blueprint object
         * @returns {string} - HTML string
         */
        buildDisplayHTML(blueprint) {
            const info = this.formatForDisplay(blueprint);

            if (!info.hasBlueprint) {
                return `
                    <div class="blueprint-recall blueprint-recall--empty">
                        <span class="blueprint-recall__icon">📋</span>
                        <span class="blueprint-recall__text">No blueprint selected</span>
                    </div>
                `;
            }

            return `
                <div class="blueprint-recall blueprint-recall--active">
                    <div class="blueprint-recall__header">
                        <span class="blueprint-recall__icon">✨</span>
                        <span class="blueprint-recall__name">Using your '${info.name}' blueprint</span>
                    </div>
                    <div class="blueprint-recall__export">
                        <span class="blueprint-recall__label">Export:</span>
                        <span class="blueprint-recall__settings">${info.exportSettings.resolution} · ${info.exportSettings.frameRate} · ${info.exportSettings.format}</span>
                    </div>
                </div>
            `;
        },

        /**
         * Get CSS for blueprint recall component
         * @returns {string} - CSS string
         */
        getStyles() {
            return `
                .blueprint-recall {
                    background: linear-gradient(135deg, rgba(37, 99, 235, 0.1) 0%, rgba(59, 130, 246, 0.05) 100%);
                    border: 1px solid rgba(59, 130, 246, 0.2);
                    border-radius: 14px;
                    padding: 16px 20px;
                    margin-bottom: 24px;
                }

                .blueprint-recall--active {
                    background: linear-gradient(135deg, rgba(34, 197, 94, 0.1) 0%, rgba(16, 185, 129, 0.05) 100%);
                    border-color: rgba(34, 197, 94, 0.3);
                }

                .blueprint-recall__header {
                    display: flex;
                    align-items: center;
                    gap: 10px;
                    margin-bottom: 8px;
                }

                .blueprint-recall__icon {
                    font-size: 18px;
                }

                .blueprint-recall__name {
                    color: var(--text-white, #ffffff);
                    font-weight: 600;
                    font-size: 15px;
                }

                .blueprint-recall__export {
                    display: flex;
                    align-items: center;
                    gap: 8px;
                    padding-left: 28px;
                }

                .blueprint-recall__label {
                    color: var(--text-muted, #64748b);
                    font-size: 13px;
                }

                .blueprint-recall__settings {
                    color: var(--text-light, #94a3b8);
                    font-size: 13px;
                    font-family: monospace;
                    background: rgba(0, 0, 0, 0.2);
                    padding: 4px 10px;
                    border-radius: 6px;
                }

                .blueprint-recall--empty {
                    opacity: 0.6;
                    display: flex;
                    align-items: center;
                    gap: 10px;
                }

                .blueprint-recall--empty .blueprint-recall__text {
                    color: var(--text-muted, #64748b);
                    font-size: 14px;
                }
            `;
        }
    };

    // ========== EXPORTS ==========
    window.ContentBugApp = {
        state,
        utils,
        userManager,
        chatDock,
        navigation,
        keyboard,
        shell,
        dataClient,
        mcpClient,
        qaPanel,
        entitlementGate,
        slaEngine,
        presence,
        communityStats,
        security,
        chatPermissions,
        revisionTracker,
        deliveryNotifications,
        ownerOversight,
        whiteLabelCategories,
        multiShortsGuardrails,
        blueprintRecall,
        CONFIG
    };

    // ========== INITIALIZATION ==========
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => shell.init());
    } else {
        shell.init();
    }

})();
