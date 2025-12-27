// ==================== CONFIG ====================
const ROLES = {
    CLIENT: 'client',
    EDITOR: 'editor',
    ADMIN: 'admin',
    OWNER: 'owner'
};

// Demo clients data (replace with API)
const DEMO_CLIENTS = [
    {
        id: 1, name: 'Jake Martinez', tier: 'creator', initials: 'JM', online: true, urgent: true,
        projects: [
            { id: 101, name: 'Product Launch Video', status: 'review' },
            { id: 102, name: 'Instagram Reel #12', status: 'active' },
            { id: 103, name: 'YouTube Intro', status: 'queue' }
        ]
    },
    {
        id: 2, name: 'Sarah Chen', tier: 'pro', initials: 'SC', online: true, urgent: false,
        projects: [
            { id: 201, name: 'Course Promo', status: 'approved' },
            { id: 202, name: 'TikTok Series Ep.3', status: 'active' }
        ]
    },
    {
        id: 3, name: 'Mike Roberts', tier: 'basic', initials: 'MR', online: false, urgent: false,
        projects: [
            { id: 301, name: 'Podcast Clip', status: 'revisions' }
        ]
    },
    {
        id: 4, name: 'Emma Davis', tier: 'growth', initials: 'ED', online: false, urgent: true,
        projects: [
            { id: 401, name: 'Brand Story', status: 'review' },
            { id: 402, name: 'Ad Campaign V1', status: 'queue' },
            { id: 403, name: 'Short Form Pack', status: 'active' },
            { id: 404, name: 'Event Highlight', status: 'approved' }
        ]
    },
];

// ==================== STATE ====================
let currentUser = null;
let selectedClientId = null;

// ==================== INIT ====================
document.addEventListener('DOMContentLoaded', function() {
    loadUser();
    initUI();
});

function loadUser() {
    // Get user from localStorage (set by login)
    currentUser = {
        role: localStorage.getItem('cb_role') || 'client',
        name: localStorage.getItem('cb_name') || 'Demo User',
        firstName: localStorage.getItem('cb_first_name') || 'Demo',
        email: localStorage.getItem('cb_email') || '',
        phone: localStorage.getItem('cb_phone') || '',
        clientId: parseInt(localStorage.getItem('cb_client_id')) || 1,
        plan: localStorage.getItem('cb_plan') || 'basic',
        activeSlots: parseInt(localStorage.getItem('cb_active_slots')) || 1,
        profilePic: localStorage.getItem('cb_profile_pic') || null
    };

    // Demo mode for local testing - DEFAULT TO OWNER for full visibility
    if (window.location.protocol === 'file:' && !currentUser.email) {
        currentUser = {
            role: 'owner',
            name: 'Sean Conley',
            firstName: 'Sean',
            email: 'sean@contentbug.io',
            phone: '385-200-7582',
            clientId: null,
            plan: 'owner',
            activeSlots: 999,
            profilePic: null
        };
    }

    // Redirect to login if no user
    if (!currentUser.email && window.location.protocol !== 'file:') {
        window.location.href = 'https://portalv2.contentbug.io/login';
        return;
    }
}

// ==================== ROLE SWITCHER (OWNER ONLY) ====================
let viewAsRole = null; // null = viewing as own role

function initRoleSwitcher() {
    if (currentUser.role !== ROLES.OWNER) return;
    const switcher = document.getElementById('roleSwitcher');
    if (switcher) switcher.classList.remove('hidden');
}

function switchViewRole(role) {
    viewAsRole = role === 'owner' ? null : role;

    // Update button states
    document.querySelectorAll('.role-switch-btn').forEach(btn => {
        btn.classList.remove('active');
        if (btn.dataset.role === role) btn.classList.add('active');
    });

    // Temporarily switch role for UI
    const savedRole = currentUser.role;
    currentUser.role = viewAsRole || 'owner';

    // Simulate different users
    if (viewAsRole === ROLES.CLIENT) {
        currentUser.name = 'Jake Martinez';
        currentUser.firstName = 'Jake';
        currentUser.clientId = 1;
        currentUser.plan = 'creator';
        currentUser.activeSlots = 2;
    } else if (viewAsRole === ROLES.EDITOR) {
        currentUser.name = 'Alex Editor';
        currentUser.firstName = 'Alex';
        currentUser.email = 'alex@contentbug.io';
    } else if (viewAsRole === ROLES.ADMIN) {
        currentUser.name = 'Admin Manager';
        currentUser.firstName = 'Admin';
    } else {
        currentUser.name = 'Sean Conley';
        currentUser.firstName = 'Sean';
        currentUser.email = 'sean@contentbug.io';
    }

    updateUserDisplay();
    initRoleBasedUI();
    renderProjectCards();

    // Restore owner role for switcher
    currentUser.role = savedRole;
}

function initUI() {
    updateUserDisplay();
    initRoleBasedUI();
    initDropdowns();
    initNavigation();
    initRoleSwitcher();
    renderProjectCards();
}

// ==================== USER DISPLAY ====================
function updateUserDisplay() {
    const role = currentUser.role;
    const name = currentUser.name;
    const initials = name.split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2);

    // Top bar
    document.getElementById('userName').textContent = name;
    document.getElementById('userAvatar').textContent = initials;
    document.getElementById('userAvatar').className = `user-avatar ${role}`;
    document.getElementById('userRoleLabel').textContent = role.charAt(0).toUpperCase() + role.slice(1);
    document.getElementById('userRoleLabel').className = `user-role-label ${role}`;

    // Chat panel user info
    document.getElementById('chatUserName').textContent = name;
    const chatAvatarEl = document.getElementById('chatUserAvatar');

    // Check for profile picture
    if (currentUser.profilePic) {
        chatAvatarEl.innerHTML = `<img src="${currentUser.profilePic}" alt="${name}"><span class="status-indicator"></span>`;
    } else {
        chatAvatarEl.innerHTML = `${initials}<span class="status-indicator"></span>`;
        chatAvatarEl.style.background = `var(--role-${role})`;
    }

    // Update role badge
    const roleLabel = role.charAt(0).toUpperCase() + role.slice(1);
    document.getElementById('chatUserRole').textContent = roleLabel;
    document.getElementById('chatUserRole').className = `user-panel-role ${role}`;

    // Welcome
    document.getElementById('welcomeTitle').textContent = `Welcome back, ${currentUser.firstName}!`;
}

// ==================== ROLE-BASED UI ====================
function initRoleBasedUI() {
    const role = currentUser.role;
    const isTeam = role === ROLES.EDITOR || role === ROLES.ADMIN || role === ROLES.OWNER;
    const isAdmin = role === ROLES.ADMIN || role === ROLES.OWNER;
    const isEditor = role === ROLES.EDITOR;
    const isClient = role === ROLES.CLIENT;

    // Client list (team only - at top of sidebar)
    const clientList = document.getElementById('clientList');
    if (isTeam) {
        clientList.classList.remove('hidden');
        renderClientList();
    }

    // Sub-nav visibility
    // - Clients: See full sub-nav (their own navigation)
    // - Editors: Hide sub-nav (use client dropdown navigation instead)
    // - Admin/Owner: See full sub-nav
    const subNav = document.getElementById('subNav');
    if (isEditor) {
        subNav.classList.add('hidden');
    }

    // Team section (admin/owner only)
    const teamSection = document.getElementById('teamSection');
    if (isAdmin) {
        teamSection.classList.remove('hidden');
    }

    // Team avatars in top bar (team members only - editors, admins, owners)
    const teamAvatars = document.getElementById('teamAvatars');
    if (isTeam) {
        teamAvatars.classList.remove('hidden');
    }

    // Admin-only chat controls (invite, permissions, settings)
    document.querySelectorAll('.admin-only').forEach(el => {
        if (isAdmin) {
            el.classList.remove('hidden');
        }
    });

    // Context indicator (team only - shows selected client)
    if (isTeam) {
        // Don't auto-select for editors, let them pick
        // selectClient(DEMO_CLIENTS[0].id);
    }

    // For clients, show their own data
    if (isClient) {
        document.getElementById('welcomeSubtitle').textContent =
            "Here's what's happening with your projects.";
        loadClientData(null); // Load their own data
    }
}

// ==================== CLIENT LIST ====================
function renderClientList() {
    const container = document.getElementById('clientListItems');
    const count = document.getElementById('clientCount');

    count.textContent = DEMO_CLIENTS.length;

    container.innerHTML = DEMO_CLIENTS.map(client => {
        const isExpanded = selectedClientId === client.id;
        const projectCount = client.projects.length;

        return `
        <div class="client-item ${isExpanded ? 'selected expanded' : ''}"
             onclick="toggleClient(${client.id})">
            <div class="client-avatar" style="background: var(--tier-${client.tier})">
                ${client.initials}
                ${client.online ? '<span class="status-dot"></span>' : ''}
            </div>
            <div class="client-info">
                <div class="client-name">${client.name}</div>
                <div class="client-meta">${client.tier.charAt(0).toUpperCase() + client.tier.slice(1)} • ${projectCount} projects</div>
            </div>
            ${client.urgent ? '<div class="client-indicator urgent"></div>' : ''}
            <div class="client-expand">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
            </div>
        </div>
        ${isExpanded ? `
        <div class="client-projects">
            ${client.projects.map(project => `
                <div class="client-project-item" onclick="openProject(${project.id}, '${project.status}')">
                    <div class="client-project-status ${project.status}"></div>
                    <span class="client-project-name">${project.name}</span>
                </div>
            `).join('')}
        </div>
        <div class="client-nav-items">
            <div class="client-nav-item" onclick="openClientPage(${client.id}, 'dashboard')">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/></svg>
                Dashboard
            </div>
            <div class="client-nav-item" onclick="openClientPage(${client.id}, 'studio')">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="23 7 16 12 23 17 23 7"/><rect x="1" y="5" width="15" height="14" rx="2" ry="2"/></svg>
                Studio
            </div>
            <div class="client-nav-item" onclick="openClientPage(${client.id}, 'blueprint')">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
                Blueprint
            </div>
            <div class="client-nav-item" onclick="openClientPage(${client.id}, 'storage')">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                Storage
            </div>
        </div>
        ` : ''}
    `;
    }).join('');
}

function toggleClient(clientId) {
    if (selectedClientId === clientId) {
        // Collapse if clicking same client
        selectedClientId = null;
        document.getElementById('currentContext').classList.add('hidden');
    } else {
        selectedClientId = clientId;
        const client = DEMO_CLIENTS.find(c => c.id === clientId);
        if (client) {
            document.getElementById('currentContext').classList.remove('hidden');
            document.getElementById('contextName').textContent = client.name;
            document.getElementById('welcomeSubtitle').textContent =
                `Viewing ${client.name}'s projects and dashboard.`;
            loadClientData(clientId);
        }
    }
    renderClientList();
}

function openProject(projectId, status) {
    console.log('Opening project:', projectId, 'Status:', status);
    // Navigate to appropriate page based on status
    if (status === 'review' || status === 'revisions') {
        // Open review player
        console.log('Opening review player for project:', projectId);
    } else {
        // Open project details
        console.log('Opening project details:', projectId);
    }
}

function openClientPage(clientId, page) {
    console.log('Opening client page:', clientId, page);
    // Load the specific page content for this client
    document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
    const navItem = document.querySelector(`.nav-item[data-page="${page}"]`);
    if (navItem) navItem.classList.add('active');

    // Show/hide pages
    showPage(page);
}

function showPage(page) {
    // Hide all page panels
    document.querySelectorAll('.page-panel').forEach(p => p.style.display = 'none');

    // Hide main dashboard content when showing other pages
    const dashboardContent = document.querySelector('.welcome-header');
    const statsGrid = document.querySelector('.stats-grid');
    const projectBoard = document.querySelector('.project-board');

    if (page === 'storage') {
        dashboardContent.style.display = 'none';
        statsGrid.style.display = 'none';
        projectBoard.style.display = 'none';
        document.getElementById('storagePage').style.display = 'block';
    } else {
        dashboardContent.style.display = 'block';
        statsGrid.style.display = 'grid';
        projectBoard.style.display = 'block';
    }
}

// ==================== STORAGE FUNCTIONS ====================
const uploadedFiles = {
    logos: [],
    intros: [],
    happy: [],
    shocked: [],
    sus: []
};

function triggerUpload(category) {
    document.getElementById(`upload-${category}`).click();
}

function handleDragOver(e) {
    e.preventDefault();
    e.currentTarget.classList.add('dragover');
}

function handleDragLeave(e) {
    e.preventDefault();
    e.currentTarget.classList.remove('dragover');
}

function handleDrop(e, category) {
    e.preventDefault();
    e.currentTarget.classList.remove('dragover');
    const files = e.dataTransfer.files;
    processFiles(files, category);
}

function handleFileSelect(e, category) {
    const files = e.target.files;
    processFiles(files, category);
}

function processFiles(files, category) {
    const preview = document.getElementById(`preview-${category}`);

    Array.from(files).forEach(file => {
        if (uploadedFiles[category].length >= 10 && ['happy', 'shocked', 'sus'].includes(category)) {
            alert('Maximum 10 photos allowed for this category');
            return;
        }

        const reader = new FileReader();
        reader.onload = function(e) {
            const fileData = {
                name: file.name,
                type: file.type,
                data: e.target.result,
                id: Date.now() + Math.random()
            };
            uploadedFiles[category].push(fileData);

            // Create preview element
            const item = document.createElement('div');
            item.className = 'preview-item';
            item.dataset.id = fileData.id;

            if (file.type.startsWith('image/')) {
                item.innerHTML = `
                    <img src="${e.target.result}" alt="${file.name}">
                    <div class="preview-item-name">${file.name}</div>
                    <button class="preview-item-remove" onclick="removeFile('${category}', ${fileData.id})">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
                        </svg>
                    </button>
                `;
            } else if (file.type.startsWith('video/')) {
                item.innerHTML = `
                    <video src="${e.target.result}" muted></video>
                    <div class="preview-item-name">${file.name}</div>
                    <button class="preview-item-remove" onclick="removeFile('${category}', ${fileData.id})">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
                        </svg>
                    </button>
                `;
            }

            preview.appendChild(item);
            updatePhotoCount(category);
        };
        reader.readAsDataURL(file);
    });
}

function removeFile(category, id) {
    uploadedFiles[category] = uploadedFiles[category].filter(f => f.id !== id);
    const item = document.querySelector(`.preview-item[data-id="${id}"]`);
    if (item) item.remove();
    updatePhotoCount(category);
}

function updatePhotoCount(category) {
    const countEl = document.getElementById(`${category}Count`);
    if (countEl) {
        countEl.textContent = `${uploadedFiles[category].length}/10`;
    }
}

function updateColorSwatch(num) {
    const input = document.getElementById(`color${num}`);
    const swatch = document.getElementById(`color${num}Swatch`);
    if (input && swatch) {
        swatch.style.background = input.value;
    }
}

let colorCount = 3;
function addColorInput() {
    colorCount++;
    const palette = document.getElementById('colorPalette');
    const addBtn = palette.querySelector('.add-color-btn');

    const row = document.createElement('div');
    row.className = 'color-input-row';
    row.innerHTML = `
        <div class="color-swatch" id="color${colorCount}Swatch" style="background: #ffffff;"></div>
        <input type="text" class="color-hex-input" id="color${colorCount}" value="#ffffff" placeholder="#000000" onchange="updateColorSwatch(${colorCount})">
        <span class="color-label">Color ${colorCount}</span>
    `;

    palette.insertBefore(row, addBtn);
}

function saveBrandAssets() {
    // Collect all data
    const colors = [];
    document.querySelectorAll('.color-hex-input').forEach(input => {
        colors.push(input.value);
    });

    const assets = {
        colors: colors,
        logos: uploadedFiles.logos,
        intros: uploadedFiles.intros,
        thumbnails: {
            happy: uploadedFiles.happy,
            shocked: uploadedFiles.shocked,
            sus: uploadedFiles.sus
        }
    };

    console.log('Saving brand assets:', assets);
    // Would save to API/Airtable here

    alert('Brand assets saved successfully!');
}

// Wire up nav clicks for storage
document.querySelector('.nav-item[data-page="storage"]')?.addEventListener('click', function() {
    document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
    this.classList.add('active');
    showPage('storage');
});

// Wire up dashboard nav to return to main view
document.querySelector('.nav-item[data-page="dashboard"]')?.addEventListener('click', function() {
    document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
    this.classList.add('active');
    showPage('dashboard');
});

function selectClient(clientId) {
    selectedClientId = clientId;
    const client = DEMO_CLIENTS.find(c => c.id === clientId);

    if (client) {
        // Update context indicator
        const context = document.getElementById('currentContext');
        context.classList.remove('hidden');
        document.getElementById('contextName').textContent = client.name;

        // Update welcome
        document.getElementById('welcomeSubtitle').textContent =
            `Viewing ${client.name}'s projects and dashboard.`;

        // Re-render client list with selection
        renderClientList();

        // Load client's data (would be API call)
        loadClientData(clientId);
    }
}

function loadClientData(clientId) {
    // Placeholder - would load from API
    console.log('Loading data for client:', clientId);

    // Demo stats
    document.getElementById('statQueue').textContent = Math.floor(Math.random() * 5);
    document.getElementById('statActive').textContent = Math.floor(Math.random() * 3) + 1;
    document.getElementById('statReview').textContent = Math.floor(Math.random() * 2);
    document.getElementById('statCompleted').textContent = Math.floor(Math.random() * 10) + 5;
}

// ==================== DROPDOWNS ====================
function initDropdowns() {
    // User dropdown
    const userSection = document.getElementById('userSection');
    const userDropdown = document.getElementById('userDropdown');

    userSection.addEventListener('click', (e) => {
        e.stopPropagation();
        userDropdown.classList.toggle('visible');
    });

    // Server dropdown
    const serverHeader = document.getElementById('serverHeader');
    const serverDropdown = document.getElementById('serverDropdown');

    serverHeader.addEventListener('click', (e) => {
        e.stopPropagation();
        serverHeader.classList.toggle('open');
        serverDropdown.classList.toggle('visible');
    });

    // Close on outside click
    document.addEventListener('click', () => {
        userDropdown.classList.remove('visible');
        serverHeader.classList.remove('open');
        serverDropdown.classList.remove('visible');
    });
}

// ==================== NAVIGATION ====================
function initNavigation() {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', function() {
            document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
            this.classList.add('active');

            const page = this.dataset.page;
            console.log('Navigate to:', page);
            // Would load page content
        });
    });
}

function toggleCategory(categoryId) {
    document.getElementById(categoryId).classList.toggle('collapsed');
}

// ==================== LOGOUT ====================
function logout() {
    localStorage.removeItem('cb_email');
    localStorage.removeItem('cb_name');
    localStorage.removeItem('cb_first_name');
    localStorage.removeItem('cb_role');
    localStorage.removeItem('cb_airtable_id');
    window.location.href = 'https://portalv2.contentbug.io/login';
}

// ==================== PROJECT CARDS (ROLE-BASED VISIBILITY) ====================
// Clients: See ONLY their own project cards when status updates occur
// Editors: See ONLY their assigned clients' project cards
// Admin/Owners: See ALL clients' project cards (can see all channels)

const ALL_PROJECTS = [
    { id: 101, name: 'Product Launch Video', status: 'review', clientId: 1, clientName: 'Jake Martinez', assignedEditor: 'alex@contentbug.io', time: '2 hours ago', isNew: true },
    { id: 102, name: 'Instagram Reel #12', status: 'active', clientId: 1, clientName: 'Jake Martinez', assignedEditor: 'alex@contentbug.io', time: '1 day ago', isNew: false },
    { id: 201, name: 'Course Promo', status: 'approved', clientId: 2, clientName: 'Sarah Chen', assignedEditor: 'mike@contentbug.io', time: '1 hour ago', isNew: true },
    { id: 301, name: 'Podcast Clip', status: 'revisions', clientId: 3, clientName: 'Mike Roberts', assignedEditor: 'alex@contentbug.io', time: '30 mins ago', isNew: true },
    { id: 401, name: 'Brand Story', status: 'review', clientId: 4, clientName: 'Emma Davis', assignedEditor: 'mike@contentbug.io', time: '5 hours ago', isNew: true },
];

function renderProjectCards() {
    const section = document.getElementById('projectCardsSection');
    const container = document.getElementById('projectCardsList');
    const titleEl = document.querySelector('.project-cards-title');

    const role = currentUser.role;
    section.classList.remove('hidden');

    let projectsToShow = [];
    let title = 'Project Updates';

    if (role === ROLES.CLIENT) {
        // Clients: Only THEIR projects with status updates
        title = 'Your Updates';
        projectsToShow = ALL_PROJECTS.filter(p => p.clientId === currentUser.clientId && p.isNew);
    } else if (role === ROLES.EDITOR) {
        // Editors: Only ASSIGNED clients' projects
        title = 'Your Clients';
        projectsToShow = ALL_PROJECTS.filter(p => p.assignedEditor === currentUser.email);
    } else {
        // Admin/Owner: ALL project cards
        title = 'All Updates';
        projectsToShow = ALL_PROJECTS.filter(p => p.isNew || p.status === 'review' || p.status === 'revisions');
    }

    titleEl.textContent = title;

    const labels = { queue: 'In Queue', active: 'In Progress', review: 'Ready for Review', revisions: 'Revisions', approved: 'Approved' };
    const msgs = { queue: 'In queue', active: 'Being edited', review: 'Ready for review!', revisions: 'Changes requested', approved: 'Ready to download' };
    const actions = { queue: 'View', active: 'View', review: 'Review Now', revisions: 'View', approved: 'Download' };

    if (!projectsToShow.length) {
        container.innerHTML = '<div style="padding:16px;text-align:center;color:#71717a;font-size:13px;">No updates</div>';
        return;
    }

    container.innerHTML = projectsToShow.map(p => `
        <div class="project-card-notification ${p.status} ${p.isNew ? 'new' : ''}" onclick="openProjectFromChat(${p.id},'${p.status}')">
            <div class="project-card-header">
                <span class="project-card-name">${p.name}</span>
                <span class="project-card-status-badge ${p.status}">${labels[p.status]}</span>
            </div>
            <div class="project-card-body">${msgs[p.status]}</div>
            <div class="project-card-footer">
                ${role !== ROLES.CLIENT ? `<span class="project-card-client">${p.clientName}</span>` : ''}
                <span class="project-card-time">${p.time}</span>
                <span class="project-card-action">${actions[p.status]} →</span>
            </div>
        </div>
    `).join('');
}

function openProjectFromChat(projectId, status) {
    console.log('Opening project from chat:', projectId, 'Status:', status);

    // Navigate to appropriate page based on status
    if (status === 'review') {
        // Go to review page
        window.location.href = `https://portalv2.contentbug.io/review?project=${projectId}`;
    } else if (status === 'approved') {
        // Go to download/approved section
        document.querySelector('.nav-item[data-page="approved"]')?.click();
    } else {
        // Go to projects page with filter
        document.querySelector('.nav-item[data-page="projects"]')?.click();
    }
}

// ==================== CHAT SETTINGS ====================
function openChatSettings() {
    document.getElementById('chatSettingsModal').classList.add('visible');
}

function closeChatSettings() {
    document.getElementById('chatSettingsModal').classList.remove('visible');
}

function updateChatFontSize(size) {
    document.documentElement.style.setProperty('--chat-font-size', size + 'px');
    localStorage.setItem('cb_chat_font_size', size);
}

function sendInvite() {
    const input = document.getElementById('inviteEmailPhone').value.trim();
    if (!input) {
        alert('Please enter an email or phone number');
        return;
    }

    // Determine if email or phone
    const isEmail = input.includes('@');
    console.log('Sending invite to:', input, 'Type:', isEmail ? 'email' : 'phone');

    // Would call API to send invite
    alert('Invite sent to ' + input + '!');
    document.getElementById('inviteEmailPhone').value = '';
}

function copyInviteLink() {
    const linkInput = document.getElementById('inviteLinkInput');
    linkInput.select();
    document.execCommand('copy');

    const btn = document.querySelector('.copy-link-btn');
    btn.classList.add('copied');
    btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg> Copied!';

    setTimeout(() => {
        btn.classList.remove('copied');
        btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg> Copy';
    }, 2000);
}

// ==================== MEETING ROOM (ZOOM-STYLE) ====================
let meetingTimerInterval = null;
let meetingSeconds = 0;
let isMicMuted = false;
let isVideoOff = false;

function openMeetingModal() {
    document.getElementById('meetingModal').classList.add('visible');
    startMeetingTimer();
}

function closeMeetingModal() {
    document.getElementById('meetingModal').classList.remove('visible');
    stopMeetingTimer();
}

function startMeetingTimer() {
    meetingSeconds = 0;
    updateMeetingTimerDisplay();
    meetingTimerInterval = setInterval(() => {
        meetingSeconds++;
        updateMeetingTimerDisplay();
    }, 1000);
}

function stopMeetingTimer() {
    if (meetingTimerInterval) {
        clearInterval(meetingTimerInterval);
        meetingTimerInterval = null;
    }
    meetingSeconds = 0;
}

function updateMeetingTimerDisplay() {
    const mins = Math.floor(meetingSeconds / 60).toString().padStart(2, '0');
    const secs = (meetingSeconds % 60).toString().padStart(2, '0');
    const display = document.getElementById('meetingTimerDisplay');
    if (display) display.textContent = `${mins}:${secs}`;
}

function toggleMeetingMic() {
    isMicMuted = !isMicMuted;
    const btn = document.getElementById('btnMic');
    const indicator = document.getElementById('selfMutedIndicator');
    if (isMicMuted) {
        btn.classList.add('muted');
        btn.querySelector('span').textContent = 'Unmute';
        if (indicator) indicator.style.display = 'flex';
    } else {
        btn.classList.remove('muted');
        btn.querySelector('span').textContent = 'Mute';
        if (indicator) indicator.style.display = 'none';
    }
}

function toggleMeetingVideo() {
    isVideoOff = !isVideoOff;
    const btn = document.getElementById('btnVideo');
    if (isVideoOff) {
        btn.classList.add('muted');
        btn.querySelector('span').textContent = 'Start Video';
    } else {
        btn.classList.remove('muted');
        btn.querySelector('span').textContent = 'Video';
    }
}

function toggleMeetingScreen() {
    console.log('Screen share toggled');
    // Would integrate with screen share API
}

function toggleMeetingChat() {
    const btn = event.currentTarget;
    btn.classList.toggle('active');
}

function toggleMeetingParticipants() {
    const btn = event.currentTarget;
    btn.classList.toggle('active');
}

function toggleMeetingReactions() {
    console.log('Reactions panel toggled');
}

function openMeetingSettings() {
    console.log('Meeting settings opened');
}

function toggleMeetingFullscreen() {
    const modal = document.getElementById('meetingModal');
    if (document.fullscreenElement) {
        document.exitFullscreen();
    } else {
        modal.requestFullscreen();
    }
}

// Legacy function stubs for compatibility
function selectMeetingType(type) {}
function confirmMeeting() {}

// Hook up the settings button in chat panel to open settings
document.querySelector('.user-panel-btn[title="Settings"]')?.addEventListener('click', openChatSettings);

// Close modals on outside click
document.getElementById('chatSettingsModal')?.addEventListener('click', function(e) {
    if (e.target === this) closeChatSettings();
});

document.getElementById('meetingModal')?.addEventListener('click', function(e) {
    if (e.target === this) closeMeetingModal();
});

// Load saved font size
const savedFontSize = localStorage.getItem('cb_chat_font_size');
if (savedFontSize) {
    document.getElementById('chatFontSize').value = savedFontSize;
    updateChatFontSize(savedFontSize);
}

// Expose functions
window.selectClient = selectClient;
window.toggleClient = toggleClient;
window.toggleCategory = toggleCategory;
window.logout = logout;
window.openProject = openProject;
window.openClientPage = openClientPage;
window.openProjectFromChat = openProjectFromChat;

// ==================== CHAT FUNCTIONALITY ====================
const API_BASE = window.location.hostname === 'localhost' || window.location.protocol === 'file:'
    ? 'https://portalv2.contentbug.io'
    : '';

let currentChannel = 'general';
let chatMessages = [];
let chatPollingInterval = null;

// Default channels (fallback when API not available)
const DEFAULT_CHANNELS = [
    { channelId: 'general', name: 'general', type: 'text', unreadCount: 0 },
    { channelId: 'project-updates', name: 'project-updates', type: 'text', unreadCount: 0 },
    { channelId: 'feedback', name: 'feedback', type: 'text', unreadCount: 0 }
];

// Demo messages for local testing
const DEMO_MESSAGES = {
    'general': [
        { id: 1, senderName: 'Sean Conley', senderRole: 'owner', content: 'Welcome to the Content Bug team chat! 🎉', createdAt: new Date(Date.now() - 3600000).toISOString(), senderAvatar: null },
        { id: 2, senderName: 'Alex Editor', senderRole: 'editor', content: 'Hey everyone! Ready to crush some edits today.', createdAt: new Date(Date.now() - 1800000).toISOString(), senderAvatar: null },
        { id: 3, senderName: 'System', senderRole: 'system', content: 'New team member Jake Martinez has joined the portal.', createdAt: new Date(Date.now() - 900000).toISOString(), senderAvatar: null }
    ],
    'project-updates': [
        { id: 4, senderName: 'Alex Editor', senderRole: 'editor', content: 'Just finished the Product Launch Video for Jake - ready for review!', createdAt: new Date(Date.now() - 7200000).toISOString(), senderAvatar: null },
        { id: 5, senderName: 'Mike Chen', senderRole: 'editor', content: 'Course Promo for Sarah is approved and delivered. Great feedback!', createdAt: new Date(Date.now() - 3600000).toISOString(), senderAvatar: null }
    ],
    'feedback': [
        { id: 6, senderName: 'Jake Martinez', senderRole: 'client', content: 'The last edit was amazing! Love the transitions.', createdAt: new Date(Date.now() - 86400000).toISOString(), senderAvatar: null }
    ]
};

// Select a channel
function selectChannel(channelId) {
    console.log('[Chat] Selecting channel:', channelId);
    currentChannel = channelId;

    // Update active state in UI
    document.querySelectorAll('.channel-item').forEach(item => {
        item.classList.remove('active');
        if (item.dataset.channel === channelId) {
            item.classList.add('active');
            item.classList.remove('unread');
            // Remove badge if exists
            const badge = item.querySelector('.channel-badge');
            if (badge) badge.remove();
        }
    });

    // Update header
    document.getElementById('currentChannelName').textContent = channelId;
    document.getElementById('chatInput').placeholder = `Message #${channelId}`;

    // Update empty state channel name
    const emptyState = document.getElementById('chatEmptyState');
    if (emptyState) {
        emptyState.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
            </svg>
            <div>Welcome to <strong>#${channelId}</strong></div>
            <div style="font-size: 13px; margin-top: 4px;">This is the start of the channel</div>
        `;
    }

    // Load messages
    loadChannelMessages(channelId);
}

// Load messages for a channel
async function loadChannelMessages(channelId) {
    const listEl = document.getElementById('chatMessagesList');
    const emptyEl = document.getElementById('chatEmptyState');

    // Show loading state
    listEl.innerHTML = `
        <div class="chat-loading">
            <div class="chat-loading-spinner"></div>
            Loading messages...
        </div>
    `;

    try {
        // Try to fetch from API
        const response = await fetch(`${API_BASE}/api/chat/channels/${channelId}/messages`, {
            method: 'GET',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json'
            }
        });

        if (response.ok) {
            const data = await response.json();
            chatMessages = data.messages || [];
            renderMessages(chatMessages);
        } else {
            // Fallback to demo messages
            console.log('[Chat] API not available, using demo messages');
            chatMessages = DEMO_MESSAGES[channelId] || [];
            renderMessages(chatMessages);
        }
    } catch (err) {
        console.log('[Chat] Error loading messages, using demo:', err);
        chatMessages = DEMO_MESSAGES[channelId] || [];
        renderMessages(chatMessages);
    }
}

// Render messages to the chat list
function renderMessages(messages) {
    const listEl = document.getElementById('chatMessagesList');

    if (!messages || messages.length === 0) {
        listEl.innerHTML = `
            <div class="chat-empty-state">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
                </svg>
                <div>Welcome to <strong>#${currentChannel}</strong></div>
                <div style="font-size: 13px; margin-top: 4px;">This is the start of the channel</div>
            </div>
        `;
        return;
    }

    listEl.innerHTML = messages.map(msg => {
        const initials = msg.senderName ? msg.senderName.split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2) : '?';
        const role = msg.senderRole || 'client';
        const time = formatMessageTime(msg.createdAt);
        const isSystem = role === 'system';

        const avatarContent = msg.senderAvatar
            ? `<img src="${msg.senderAvatar}" alt="${msg.senderName}">`
            : initials;

        return `
            <div class="chat-message ${isSystem ? 'system' : ''}">
                <div class="chat-message-avatar" style="background: var(--role-${role})">
                    ${avatarContent}
                </div>
                <div class="chat-message-content">
                    <div class="chat-message-header">
                        <span class="chat-message-author">${msg.senderName || 'Unknown'}</span>
                        <span class="chat-message-role ${role}">${role}</span>
                        <span class="chat-message-time">${time}</span>
                    </div>
                    <div class="chat-message-text">${escapeHtml(msg.content)}</div>
                </div>
            </div>
        `;
    }).join('');

    // Scroll to bottom
    listEl.scrollTop = listEl.scrollHeight;
}

// Format message time
function formatMessageTime(isoString) {
    if (!isoString) return '';
    const date = new Date(isoString);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    return date.toLocaleDateString();
}

// Escape HTML to prevent XSS
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Handle Enter key in chat input
function handleChatKeypress(event) {
    if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        sendChatMessage();
    }
}

// Send a chat message
async function sendChatMessage() {
    const input = document.getElementById('chatInput');
    const content = input.value.trim();

    if (!content) return;

    const sendBtn = document.querySelector('.chat-send-btn');
    sendBtn.disabled = true;

    try {
        // Try to send via API
        const response = await fetch(`${API_BASE}/api/chat/channels/${currentChannel}/messages`, {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ content })
        });

        if (response.ok) {
            input.value = '';
            // Reload messages to show the new one
            loadChannelMessages(currentChannel);
        } else {
            // Fallback: Add message locally
            addLocalMessage(content);
            input.value = '';
        }
    } catch (err) {
        console.log('[Chat] Error sending message, adding locally:', err);
        addLocalMessage(content);
        input.value = '';
    }

    sendBtn.disabled = false;
    input.focus();
}

// Add message locally (for demo/offline mode)
function addLocalMessage(content) {
    const newMessage = {
        id: Date.now(),
        senderName: currentUser.name,
        senderRole: currentUser.role,
        senderAvatar: currentUser.profilePic,
        content: content,
        createdAt: new Date().toISOString()
    };

    chatMessages.push(newMessage);
    renderMessages(chatMessages);

    // Also update demo messages for persistence in session
    if (!DEMO_MESSAGES[currentChannel]) {
        DEMO_MESSAGES[currentChannel] = [];
    }
    DEMO_MESSAGES[currentChannel].push(newMessage);
}

// Create a new channel (admin only)
function createNewChannel() {
    const name = prompt('Enter channel name:');
    if (!name) return;

    const channelId = name.toLowerCase().replace(/[^a-z0-9]/g, '-');

    // Add to channel list
    const channelList = document.getElementById('channelList');
    const newChannelHtml = `
        <div class="channel-item" data-channel="${channelId}" onclick="selectChannel('${channelId}')">
            <svg class="channel-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 9l3-3 3 3M4 15l3 3 3-3M14 9h6M14 15h6"/></svg>
            <span class="channel-name">${name}</span>
        </div>
    `;
    channelList.insertAdjacentHTML('beforeend', newChannelHtml);

    // Initialize empty messages for the channel
    DEMO_MESSAGES[channelId] = [];

    // Select the new channel
    selectChannel(channelId);
}

// Initialize chat on page load
function initChat() {
    // Select default channel
    selectChannel('general');
}

// Expose chat functions
window.selectChannel = selectChannel;
window.handleChatKeypress = handleChatKeypress;
window.sendChatMessage = sendChatMessage;
window.createNewChannel = createNewChannel;

// ==================== FULL CHAT VIEW FUNCTIONS ====================
let fullChatChannel = 'general';

// Open full chat view
function openFullChat() {
    console.log('[Chat] Opening full chat view');
    document.querySelector('.app-body').classList.add('full-chat-active');

    // Update nav item
    document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
    const chatNavItem = document.querySelector('.nav-item[data-page="chat"]');
    if (chatNavItem) chatNavItem.classList.add('active');

    // Load messages for current channel
    loadFullChatMessages(fullChatChannel);
}

// Close full chat view
function closeFullChat() {
    console.log('[Chat] Closing full chat view');
    document.querySelector('.app-body').classList.remove('full-chat-active');

    // Switch nav back to dashboard
    document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
    const dashNavItem = document.querySelector('.nav-item[data-page="dashboard"]');
    if (dashNavItem) dashNavItem.classList.add('active');
}

// Select a channel in full chat view
function selectFullChatChannel(channelId) {
    console.log('[Chat] Full chat selecting channel:', channelId);
    fullChatChannel = channelId;

    // Update active state
    document.querySelectorAll('.full-chat-channel').forEach(item => {
        item.classList.remove('active');
        if (item.dataset.channel === channelId) {
            item.classList.add('active');
        }
    });

    // Update header
    document.getElementById('fullChatChannelName').textContent = channelId;
    document.getElementById('fullChatInput').placeholder = `Message #${channelId}`;

    // Load messages
    loadFullChatMessages(channelId);
}

// Load messages for full chat view
async function loadFullChatMessages(channelId) {
    const listEl = document.getElementById('fullChatMessagesList');
    listEl.innerHTML = `<div class="chat-loading"><div class="chat-loading-spinner"></div>Loading messages...</div>`;

    try {
        const response = await fetch(`${API_BASE}/api/chat/channels/${channelId}/messages`, {
            method: 'GET',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' }
        });

        if (response.ok) {
            const data = await response.json();
            renderFullChatMessages(data.messages || []);
        } else {
            renderFullChatMessages(DEMO_MESSAGES[channelId] || []);
        }
    } catch (err) {
        renderFullChatMessages(DEMO_MESSAGES[channelId] || []);
    }
}

// Render messages in full chat view
function renderFullChatMessages(messages) {
    const listEl = document.getElementById('fullChatMessagesList');

    if (!messages || messages.length === 0) {
        listEl.innerHTML = `
            <div class="chat-empty-state">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
                </svg>
                <div>Welcome to <strong>#${fullChatChannel}</strong></div>
                <div style="font-size: 13px; margin-top: 4px;">This is the start of the channel</div>
            </div>
        `;
        return;
    }

    listEl.innerHTML = messages.map(msg => {
        const initials = msg.senderName ? msg.senderName.split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2) : '?';
        const role = msg.senderRole || 'client';
        const avatarStyle = msg.senderAvatar
            ? `background-image: url('${msg.senderAvatar}'); background-size: cover;`
            : `background: var(--role-${role});`;

        return `
            <div class="chat-message ${msg.isSystem ? 'system' : ''}">
                <div class="chat-message-avatar" style="${avatarStyle}">${msg.senderAvatar ? '' : initials}</div>
                <div class="chat-message-content">
                    <div class="chat-message-header">
                        <span class="chat-message-author">${escapeHtml(msg.senderName || 'Unknown')}</span>
                        <span class="chat-message-role ${role}">${role}</span>
                        <span class="chat-message-time">${formatMessageTime(msg.createdAt)}</span>
                    </div>
                    <div class="chat-message-text">${escapeHtml(msg.content)}</div>
                </div>
            </div>
        `;
    }).join('');

    listEl.scrollTop = listEl.scrollHeight;
}

// Handle keypress in full chat input
function handleFullChatKeypress(event) {
    if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        sendFullChatMessage();
    }
}

// Send message from full chat view
async function sendFullChatMessage() {
    const input = document.getElementById('fullChatInput');
    const content = input.value.trim();
    if (!content) return;

    input.value = '';

    // Add message locally first for instant feedback
    const newMsg = {
        id: Date.now(),
        senderName: currentUser.name,
        senderRole: viewAsRole || currentUser.role,
        content: content,
        createdAt: new Date().toISOString(),
        senderAvatar: currentUser.profilePic
    };

    // Re-render with new message
    const existingMessages = DEMO_MESSAGES[fullChatChannel] || [];
    existingMessages.push(newMsg);
    DEMO_MESSAGES[fullChatChannel] = existingMessages;
    renderFullChatMessages(existingMessages);

    // Also update quick chat if on same channel
    if (currentChannel === fullChatChannel) {
        chatMessages = existingMessages;
        renderMessages(existingMessages);
    }

    // Try to send to API
    try {
        await fetch(`${API_BASE}/api/chat/channels/${fullChatChannel}/messages`, {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content, channelId: fullChatChannel })
        });
    } catch (err) {
        console.log('[Chat] API send failed, message kept locally');
    }
}

// Expose full chat functions
window.openFullChat = openFullChat;
window.closeFullChat = closeFullChat;
window.selectFullChatChannel = selectFullChatChannel;
window.handleFullChatKeypress = handleFullChatKeypress;
window.sendFullChatMessage = sendFullChatMessage;

// Initialize chat when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initChat);
} else {
    // DOM already loaded, init immediately
    setTimeout(initChat, 100);
}

// ==================== PROFILE SETTINGS ====================
function openProfileSettings() {
    const modal = document.getElementById('profileModal');
    modal.classList.add('visible');

    // Populate with current user data
    const role = viewAsRole || currentUser.role;
    document.getElementById('profileName').textContent = currentUser.name;
    document.getElementById('profileEmail').textContent = currentUser.email;
    document.getElementById('profileEmailValue').textContent = currentUser.email;
    document.getElementById('profilePhoneValue').textContent = currentUser.phone || 'Not set';

    // Update avatar
    const initials = currentUser.name.split(' ').map(n => n[0]).join('').toUpperCase();
    const avatarEl = document.getElementById('profileAvatarLarge');
    avatarEl.textContent = '';
    avatarEl.innerHTML = initials + `<div class="profile-avatar-edit" onclick="changeProfilePic()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></div>`;
    avatarEl.style.background = `var(--role-${role})`;

    // Update role badge
    const roleEl = document.getElementById('profileRoleValue');
    roleEl.textContent = role.charAt(0).toUpperCase() + role.slice(1);
    roleEl.className = `profile-info-value plan ${role}`;

    // Subscription section - only for clients
    const subSection = document.getElementById('subscriptionSection');
    if (role === ROLES.CLIENT) {
        subSection.style.display = 'block';
        document.getElementById('profilePlanValue').textContent = currentUser.plan;
        document.getElementById('profilePlanValue').className = `profile-info-value plan ${currentUser.plan}`;
        document.getElementById('profileSlotsValue').textContent = currentUser.activeSlots;
    } else {
        subSection.style.display = 'none';
    }

    // Load saved font size
    const savedSize = localStorage.getItem('cb_chat_font_size') || '14';
    document.getElementById('profileFontSize').value = savedSize;
}

function closeProfileSettings() {
    document.getElementById('profileModal').classList.remove('visible');
}

function changeProfilePic() {
    // Would open file picker or avatar selector
    alert('Profile picture upload coming soon!');
}

function updateProfileFontSize(size) {
    document.documentElement.style.setProperty('--chat-font-size', size + 'px');
    localStorage.setItem('cb_chat_font_size', size);
}

// ==================== EDITOR MANAGEMENT ====================
const DEMO_EDITORS = [
    { id: 1, name: 'Alex Johnson', email: 'alex@contentbug.io', status: 'active', initials: 'AJ' },
    { id: 2, name: 'Mike Chen', email: 'mike@contentbug.io', status: 'active', initials: 'MC' },
    { id: 3, name: 'Sarah Williams', email: 'sarah@contentbug.io', status: 'pending', initials: 'SW' },
];

function openEditorMgmt() {
    document.getElementById('editorMgmtModal').classList.add('visible');
    renderEditorList();
}

function closeEditorMgmt() {
    document.getElementById('editorMgmtModal').classList.remove('visible');
}

function renderEditorList() {
    const container = document.getElementById('editorList');
    document.getElementById('editorCount').textContent = `${DEMO_EDITORS.length} editors`;

    container.innerHTML = DEMO_EDITORS.map(editor => `
        <div class="editor-item" data-id="${editor.id}">
            <div class="editor-item-avatar">${editor.initials}</div>
            <div class="editor-item-info">
                <div class="editor-item-name">${editor.name}</div>
                <div class="editor-item-email">${editor.email}</div>
            </div>
            <span class="editor-item-status ${editor.status}">${editor.status}</span>
            <div class="editor-item-actions">
                <button class="editor-action-btn" title="Edit" onclick="editEditor(${editor.id})">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
                        <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
                    </svg>
                </button>
                <button class="editor-action-btn danger" title="Remove" onclick="removeEditor(${editor.id})">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="3 6 5 6 21 6"/>
                        <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
                    </svg>
                </button>
            </div>
        </div>
    `).join('');
}

function sendEditorInvite() {
    const email = document.getElementById('editorInviteEmail').value.trim();
    if (!email || !email.includes('@')) {
        alert('Please enter a valid email address');
        return;
    }

    // Generate invite link
    const inviteCode = Math.random().toString(36).substring(2, 10);
    const inviteLink = `https://portalv2.contentbug.io/editor-signup?invite=${inviteCode}`;

    console.log('Sending editor invite to:', email);
    console.log('Invite link:', inviteLink);

    // In production: Send via GHL email
    alert(`Invite sent to ${email}!\n\nLink: ${inviteLink}`);
    document.getElementById('editorInviteEmail').value = '';
}

function editEditor(id) {
    const editor = DEMO_EDITORS.find(e => e.id === id);
    if (editor) {
        console.log('Editing editor:', editor);
        alert(`Edit ${editor.name}'s profile (coming soon)`);
    }
}

function removeEditor(id) {
    const editor = DEMO_EDITORS.find(e => e.id === id);
    if (editor && confirm(`Are you sure you want to remove ${editor.name} from the team?`)) {
        console.log('Removing editor:', editor);
        // Would call API to remove
        alert(`${editor.name} has been removed`);
        renderEditorList();
    }
}

// Close modals on outside click
document.getElementById('profileModal')?.addEventListener('click', function(e) {
    if (e.target === this) closeProfileSettings();
});

document.getElementById('editorMgmtModal')?.addEventListener('click', function(e) {
    if (e.target === this) closeEditorMgmt();
});

// Expose functions
window.selectClient = selectClient;
window.toggleClient = toggleClient;
window.toggleCategory = toggleCategory;
window.logout = logout;
window.openProject = openProject;
window.openClientPage = openClientPage;
window.openProjectFromChat = openProjectFromChat;
window.openChatSettings = openChatSettings;
window.closeChatSettings = closeChatSettings;
window.updateChatFontSize = updateChatFontSize;
window.sendInvite = sendInvite;
window.copyInviteLink = copyInviteLink;
window.openMeetingModal = openMeetingModal;
window.closeMeetingModal = closeMeetingModal;
window.toggleMeetingMic = toggleMeetingMic;
window.toggleMeetingVideo = toggleMeetingVideo;
window.toggleMeetingScreen = toggleMeetingScreen;
window.toggleMeetingChat = toggleMeetingChat;
window.toggleMeetingParticipants = toggleMeetingParticipants;
window.toggleMeetingReactions = toggleMeetingReactions;
window.openMeetingSettings = openMeetingSettings;
window.toggleMeetingFullscreen = toggleMeetingFullscreen;
window.showPage = showPage;
window.triggerUpload = triggerUpload;
window.handleDragOver = handleDragOver;
window.handleDragLeave = handleDragLeave;
window.handleDrop = handleDrop;
window.handleFileSelect = handleFileSelect;
window.removeFile = removeFile;
window.updateColorSwatch = updateColorSwatch;
window.addColorInput = addColorInput;
window.saveBrandAssets = saveBrandAssets;
window.openProfileSettings = openProfileSettings;
window.closeProfileSettings = closeProfileSettings;
window.changeProfilePic = changeProfilePic;
window.updateProfileFontSize = updateProfileFontSize;
window.openEditorMgmt = openEditorMgmt;
window.closeEditorMgmt = closeEditorMgmt;
window.sendEditorInvite = sendEditorInvite;
window.editEditor = editEditor;
window.removeEditor = removeEditor;
window.switchViewRole = switchViewRole;
