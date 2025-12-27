// ==================== ZOOM MEETING SDK INTEGRATION ====================
const ZOOM_SDK_KEY = 'neGOqCPSRUe9Z2taRkRU3A';
let zoomClient = null;
let zoomMeetingActive = false;
let zoomMeetingNumber = null;

// Initialize Zoom SDK
async function initZoomSDK() {
    if (typeof ZoomMtg === 'undefined') {
        console.warn('[Zoom] SDK not loaded yet');
        return false;
    }

    try {
        ZoomMtg.preLoadWasm();
        ZoomMtg.prepareWebSDK();

        // Set SDK language
        ZoomMtg.i18n.load('en-US');
        ZoomMtg.i18n.reload('en-US');

        console.log('[Zoom] SDK initialized successfully');
        return true;
    } catch (err) {
        console.error('[Zoom] SDK init error:', err);
        return false;
    }
}

// Get meeting signature from server
async function getZoomSignature(meetingNumber, role = 0) {
    try {
        const response = await fetch(`${API_BASE}/api/zoom/signature`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('cb_auth_token')}`
            },
            body: JSON.stringify({ meetingNumber, role })
        });

        if (!response.ok) {
            throw new Error('Failed to get signature');
        }

        return await response.json();
    } catch (err) {
        console.error('[Zoom] Signature error:', err);
        throw err;
    }
}

// Join a Zoom meeting
async function joinZoomMeeting(meetingNumber, password = '', userName = null) {
    try {
        // Show loading state
        const mainVideo = document.getElementById('mainVideo');
        if (mainVideo) {
            mainVideo.innerHTML = `
                <div class="video-placeholder">
                    <div class="video-avatar">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="40" height="40" class="spin">
                            <circle cx="12" cy="12" r="10" opacity="0.3"/>
                            <path d="M12 2a10 10 0 0 1 10 10" stroke-linecap="round"/>
                        </svg>
                    </div>
                    <div class="video-name">Connecting to Zoom...</div>
                    <div class="video-status">Please wait while we set up the meeting</div>
                </div>
            `;
        }

        // Initialize SDK if not already done
        await initZoomSDK();

        // Get user info
        const displayName = userName || currentUser?.name || 'Content Bug User';
        const userEmail = currentUser?.email || '';

        // Determine role (admins/owners are hosts)
        const role = ['admin', 'owner'].includes(currentUser?.role) ? 1 : 0;

        // Get signature from server
        const signatureData = await getZoomSignature(meetingNumber, role);

        if (!signatureData.success) {
            throw new Error('Failed to generate meeting signature');
        }

        // Store meeting number
        zoomMeetingNumber = meetingNumber;

        // Configure where Zoom renders
        document.getElementById('zoomMeetingContainer').style.display = 'block';

        // Join the meeting
        ZoomMtg.init({
            leaveUrl: window.location.href,
            isSupportAV: true,
            isSupportChat: true,
            isSupportQA: false,
            isSupportCC: true,
            isSupportPolling: false,
            isSupportBreakout: false,
            screenShare: true,
            videoDrag: true,
            sharingMode: 'both',
            videoHeader: true,
            isLockBottom: true,
            isSupportNonverbal: true,
            isShowJoiningErrorDialog: true,
            inviteUrlFormat: '',
            loginWindow: {
                width: 400,
                height: 380
            },
            success: function() {
                console.log('[Zoom] Init success, joining meeting...');

                ZoomMtg.join({
                    meetingNumber: signatureData.meetingNumber,
                    userName: displayName,
                    signature: signatureData.signature,
                    sdkKey: signatureData.sdkKey,
                    passWord: password,
                    userEmail: userEmail,
                    success: function(res) {
                        console.log('[Zoom] Joined meeting successfully:', res);
                        zoomMeetingActive = true;
                        startMeetingTimer();

                        // Update UI
                        if (mainVideo) {
                            mainVideo.innerHTML = `
                                <div class="video-placeholder">
                                    <div class="video-avatar">
                                        <svg viewBox="0 0 24 24" fill="currentColor" width="40" height="40">
                                            <path d="M15 10l4.553-2.276A1 1 0 0121 8.618v6.764a1 1 0 01-1.447.894L15 14v-4z"/>
                                            <rect x="3" y="6" width="12" height="12" rx="2"/>
                                        </svg>
                                    </div>
                                    <div class="video-name">Meeting Active</div>
                                    <div class="video-status">Zoom meeting embedded above</div>
                                </div>
                            `;
                        }
                    },
                    error: function(err) {
                        console.error('[Zoom] Join error:', err);
                        showMeetingError('Failed to join meeting: ' + (err.reason || err.message || 'Unknown error'));
                    }
                });
            },
            error: function(err) {
                console.error('[Zoom] Init error:', err);
                showMeetingError('Failed to initialize Zoom: ' + (err.reason || err.message || 'Unknown error'));
            }
        });

    } catch (err) {
        console.error('[Zoom] Join meeting error:', err);
        showMeetingError(err.message);
    }
}

// Leave current Zoom meeting
function leaveZoomMeeting() {
    if (zoomMeetingActive && typeof ZoomMtg !== 'undefined') {
        ZoomMtg.leaveMeeting({
            success: function() {
                console.log('[Zoom] Left meeting');
                zoomMeetingActive = false;
                zoomMeetingNumber = null;
                document.getElementById('zoomMeetingContainer').style.display = 'none';
            },
            error: function(err) {
                console.error('[Zoom] Leave error:', err);
            }
        });
    }
    closeMeetingModal();
}

// Show meeting error
function showMeetingError(message) {
    const mainVideo = document.getElementById('mainVideo');
    if (mainVideo) {
        mainVideo.innerHTML = `
            <div class="video-placeholder">
                <div class="video-avatar" style="background: var(--accent-red-soft); color: var(--accent-red);">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="40" height="40">
                        <circle cx="12" cy="12" r="10"/>
                        <line x1="15" y1="9" x2="9" y2="15"/>
                        <line x1="9" y1="9" x2="15" y2="15"/>
                    </svg>
                </div>
                <div class="video-name" style="color: var(--accent-red);">Connection Failed</div>
                <div class="video-status">${message}</div>
                <button onclick="showJoinMeetingForm()" style="margin-top: 16px; padding: 10px 20px; background: var(--accent-blue); color: white; border: none; border-radius: 8px; cursor: pointer;">Try Again</button>
            </div>
        `;
    }
}

// Meeting room state
let upcomingMeetings = [];
let isCreatingMeeting = false;

// Show meetings dashboard (no manual ID entry!)
function showMeetingsDashboard() {
    const mainVideo = document.getElementById('mainVideo');
    const isAdmin = ['admin', 'owner', 'editor'].includes(currentUser?.role);

    if (mainVideo) {
        mainVideo.innerHTML = `
            <div class="video-placeholder" style="max-width: 600px; text-align: center;">
                <div class="video-avatar">
                    <svg viewBox="0 0 24 24" fill="currentColor" width="40" height="40">
                        <path d="M15 10l4.553-2.276A1 1 0 0121 8.618v6.764a1 1 0 01-1.447.894L15 14v-4z"/>
                        <rect x="3" y="6" width="12" height="12" rx="2"/>
                    </svg>
                </div>
                <div class="video-name">Content Bug Meetings</div>

                ${isAdmin ? `
                <div style="margin: 24px 0;">
                    <button onclick="startInstantMeeting()" id="instantMeetingBtn"
                        style="padding: 16px 32px; background: linear-gradient(135deg, #059669, #10b981); color: white; border: none; border-radius: 12px; font-size: 16px; font-weight: 600; cursor: pointer; transition: all 0.3s; display: inline-flex; align-items: center; gap: 10px;">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20">
                            <path d="M15 10l4.553-2.276A1 1 0 0121 8.618v6.764a1 1 0 01-1.447.894L15 14v-4z"/>
                            <rect x="3" y="6" width="12" height="12" rx="2"/>
                        </svg>
                        Start Instant Meeting
                    </button>
                </div>
                ` : ''}

                <div id="upcomingMeetingsSection" style="margin-top: 24px; text-align: left;">
                    <div style="color: var(--text-muted); font-size: 13px; margin-bottom: 12px; text-transform: uppercase; letter-spacing: 1px;">
                        Upcoming Meetings
                    </div>
                    <div id="meetingsList" style="display: flex; flex-direction: column; gap: 8px;">
                        <div style="color: var(--text-muted); padding: 16px; text-align: center;">Loading...</div>
                    </div>
                </div>
            </div>
        `;

        // Load upcoming meetings
        loadUpcomingMeetings();
    }
}

// Load upcoming meetings from API
async function loadUpcomingMeetings() {
    const meetingsList = document.getElementById('meetingsList');
    if (!meetingsList) return;

    try {
        const response = await fetch(\`\${API_BASE}/api/zoom/meetings\`, {
            headers: {
                'Authorization': \`Bearer \${localStorage.getItem('cb_auth_token')}\`
            }
        });

        if (!response.ok) throw new Error('Failed to load meetings');

        const data = await response.json();
        upcomingMeetings = data.meetings || [];

        if (upcomingMeetings.length === 0) {
            meetingsList.innerHTML = \`
                <div style="color: var(--text-muted); padding: 24px; text-align: center; background: var(--bg-surface); border-radius: 12px; border: 1px solid var(--border-subtle);">
                    No upcoming meetings scheduled
                </div>
            \`;
            return;
        }

        meetingsList.innerHTML = upcomingMeetings.map(m => \`
            <div style="display: flex; align-items: center; justify-content: space-between; padding: 16px; background: var(--bg-surface); border-radius: 12px; border: 1px solid var(--border-subtle);">
                <div>
                    <div style="font-weight: 600; color: var(--text-primary);">\${m.topic}</div>
                    <div style="font-size: 13px; color: var(--text-muted); margin-top: 4px;">
                        \${m.startTime ? new Date(m.startTime).toLocaleString() : 'Instant Meeting'} • \${m.duration} min
                    </div>
                </div>
                <button onclick="joinMeetingById('\${m.id}')"
                    style="padding: 10px 20px; background: var(--accent-blue); color: white; border: none; border-radius: 8px; font-weight: 600; cursor: pointer;">
                    Join
                </button>
            </div>
        \`).join('');

    } catch (err) {
        console.error('[Meetings] Load error:', err);
        meetingsList.innerHTML = \`
            <div style="color: var(--text-muted); padding: 24px; text-align: center; background: var(--bg-surface); border-radius: 12px;">
                No meetings available
            </div>
        \`;
    }
}

// Start an instant meeting (one click!)
async function startInstantMeeting() {
    if (isCreatingMeeting) return;
    isCreatingMeeting = true;

    const btn = document.getElementById('instantMeetingBtn');
    if (btn) {
        btn.innerHTML = \`
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20" class="spin">
                <circle cx="12" cy="12" r="10" opacity="0.3"/>
                <path d="M12 2a10 10 0 0 1 10 10" stroke-linecap="round"/>
            </svg>
            Creating Meeting...
        \`;
        btn.disabled = true;
    }

    try {
        const response = await fetch(\`\${API_BASE}/api/zoom/create-meeting\`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': \`Bearer \${localStorage.getItem('cb_auth_token')}\`
            },
            body: JSON.stringify({
                topic: \`Content Bug Meeting - \${new Date().toLocaleDateString()}\`
            })
        });

        if (!response.ok) throw new Error('Failed to create meeting');

        const data = await response.json();
        console.log('[Meetings] Created:', data.meeting);

        // Join the meeting immediately
        joinZoomMeeting(data.meeting.id, data.meeting.password);

    } catch (err) {
        console.error('[Meetings] Create error:', err);
        alert('Failed to create meeting: ' + err.message);

        if (btn) {
            btn.innerHTML = \`
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20">
                    <path d="M15 10l4.553-2.276A1 1 0 0121 8.618v6.764a1 1 0 01-1.447.894L15 14v-4z"/>
                    <rect x="3" y="6" width="12" height="12" rx="2"/>
                </svg>
                Start Instant Meeting
            \`;
            btn.disabled = false;
        }
    }

    isCreatingMeeting = false;
}

// Join meeting by ID (used for scheduled meetings)
async function joinMeetingById(meetingId) {
    try {
        // Get meeting details to get password
        const response = await fetch(\`\${API_BASE}/api/zoom/meeting/\${meetingId}\`, {
            headers: {
                'Authorization': \`Bearer \${localStorage.getItem('cb_auth_token')}\`
            }
        });

        if (response.ok) {
            const data = await response.json();
            joinZoomMeeting(meetingId, data.meeting?.password || '');
        } else {
            joinZoomMeeting(meetingId, '');
        }
    } catch (err) {
        joinZoomMeeting(meetingId, '');
    }
}

// Override the existing openMeetingModal function
const originalOpenMeetingModal = openMeetingModal;
openMeetingModal = function() {
    document.getElementById('meetingModal').classList.add('visible');
    showMeetingsDashboard();
};

// Override closeMeetingModal to also leave Zoom
const originalCloseMeetingModal = closeMeetingModal;
closeMeetingModal = function() {
    if (zoomMeetingActive) {
        if (confirm('Are you sure you want to leave the meeting?')) {
            leaveZoomMeeting();
        }
    } else {
        document.getElementById('meetingModal').classList.remove('visible');
        stopMeetingTimer();
    }
};

// Zoom control functions (connect to SDK)
const originalToggleMeetingMic = toggleMeetingMic;
toggleMeetingMic = function() {
    if (zoomMeetingActive && typeof ZoomMtg !== 'undefined') {
        ZoomMtg.mute({
            mute: !isMicMuted,
            userId: ZoomMtg.getCurrentUser()?.oderId,
            success: function() {
                originalToggleMeetingMic();
            },
            error: function(err) {
                console.error('[Zoom] Mute error:', err);
                originalToggleMeetingMic(); // Toggle UI anyway
            }
        });
    } else {
        originalToggleMeetingMic();
    }
};

const originalToggleMeetingVideo = toggleMeetingVideo;
toggleMeetingVideo = function() {
    if (zoomMeetingActive && typeof ZoomMtg !== 'undefined') {
        ZoomMtg.muteVideo({
            mute: !isVideoOff,
            success: function() {
                originalToggleMeetingVideo();
            },
            error: function(err) {
                console.error('[Zoom] Video toggle error:', err);
                originalToggleMeetingVideo(); // Toggle UI anyway
            }
        });
    } else {
        originalToggleMeetingVideo();
    }
};

toggleMeetingScreen = function() {
    if (zoomMeetingActive && typeof ZoomMtg !== 'undefined') {
        // Note: Screen sharing is handled by Zoom's built-in UI
        console.log('[Zoom] Screen share - use Zoom controls');
        alert('Use the Zoom controls above to share your screen');
    } else {
        console.log('Screen share not available - not in a meeting');
    }
};

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    // Pre-initialize Zoom SDK
    setTimeout(initZoomSDK, 2000);
});

// Expose functions
window.joinZoomMeeting = joinZoomMeeting;
window.leaveZoomMeeting = leaveZoomMeeting;
window.showMeetingsDashboard = showMeetingsDashboard;
window.startInstantMeeting = startInstantMeeting;
window.joinMeetingById = joinMeetingById;
window.loadUpcomingMeetings = loadUpcomingMeetings;
