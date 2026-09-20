/**
 * Pentest AI Platform - Main JavaScript
 * Phase 10: Enhanced with toast notifications, AJAX polling, CSRF handling
 */

(function() {
    'use strict';

    // =============================================
    // CSRF Token Helper
    // =============================================
    function getCSRFToken() {
        // Try meta tag first
        var meta = document.querySelector('meta[name="csrf-token"]');
        if (meta) return meta.getAttribute('content');
        // Try hidden input
        var input = document.querySelector('input[name="csrf_token"]');
        if (input) return input.value;
        return '';
    }

    // Expose CSRF token globally
    window.CSRF_TOKEN = getCSRFToken();

    // =============================================
    // Toast Notification System
    // =============================================
    var ToastManager = {
        container: null,

        init: function() {
            this.container = document.querySelector('.toast-container');
            if (!this.container) {
                this.container = document.createElement('div');
                this.container.className = 'toast-container';
                document.body.appendChild(this.container);
            }
        },

        show: function(type, title, message, iconHtml, duration) {
            if (!this.container) this.init();
            duration = duration || 5000;

            var icons = {
                success: '&#9989;',
                error: '&#10060;',
                warning: '&#9888;&#65039;',
                info: '&#8505;&#65039;'
            };

            var toast = document.createElement('div');
            toast.className = 'toast toast-' + type;
            toast.innerHTML =
                '<span class="toast-icon">' + (iconHtml || icons[type] || icons.info) + '</span>' +
                '<div class="toast-body">' +
                    '<div class="toast-title">' + this._escapeHtml(title) + '</div>' +
                    (message ? '<div class="toast-message">' + this._escapeHtml(message) + '</div>' : '') +
                '</div>' +
                '<button class="toast-close">&times;</button>';

            var self = this;
            toast.querySelector('.toast-close').addEventListener('click', function() {
                self._removeToast(toast);
            });

            this.container.appendChild(toast);

            // Auto-dismiss
            var timer = setTimeout(function() {
                self._removeToast(toast);
            }, duration);

            toast._autoDismissTimer = timer;

            return toast;
        },

        _removeToast: function(toast) {
            if (toast._removing) return;
            toast._removing = true;
            clearTimeout(toast._autoDismissTimer);
            toast.classList.add('removing');
            setTimeout(function() {
                if (toast.parentNode) toast.parentNode.removeChild(toast);
            }, 300);
        },

        _escapeHtml: function(str) {
            if (!str) return '';
            var div = document.createElement('div');
            div.textContent = str;
            return div.innerHTML;
        }
    };

    // =============================================
    // Notification Polling
    // =============================================
    var NotificationPoller = {
        interval: null,
        pollFrequency: 30000, // 30 seconds

        start: function() {
            var self = this;
            // Initial fetch
            self._updateBadge();
            // Start polling
            self.interval = setInterval(function() {
                self._updateBadge();
            }, self.pollFrequency);
        },

        stop: function() {
            if (this.interval) {
                clearInterval(this.interval);
                this.interval = null;
            }
        },

        _updateBadge: function() {
            fetch('/api/notifications/count', {
                headers: {'X-CSRFToken': window.CSRF_TOKEN}
            })
            .then(function(response) { return response.json(); })
            .then(function(data) {
                var badge = document.querySelector('.nav-notification .badge-count');
                if (badge) {
                    badge.textContent = data.unread_count;
                    if (data.unread_count > 0) {
                        badge.classList.remove('hidden');
                    } else {
                        badge.classList.add('hidden');
                    }
                }
            })
            .catch(function() { /* silently fail */ });
        }
    };

    // =============================================
    // Scan Status Polling
    // =============================================
    var ScanPoller = {
        intervals: {},

        start: function(scanId, options) {
            var self = this;
            if (self.intervals[scanId]) return; // already polling

            options = options || {};
            var frequency = options.frequency || 3000;
            var onUpdate = options.onUpdate || function() {};
            var onComplete = options.onComplete || function() {};

            self.intervals[scanId] = setInterval(function() {
                fetch('/api/scans/' + scanId + '/status', {
                    headers: {'X-CSRFToken': window.CSRF_TOKEN}
                })
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    onUpdate(data);
                    if (data.status === 'completed' || data.status === 'failed' || data.status === 'cancelled') {
                        self.stop(scanId);
                        var icon = data.status === 'completed' ? '&#9989;' : '&#10060;';
                        var toastType = data.status === 'completed' ? 'success' : 'error';
                        ToastManager.show(
                            toastType,
                            'Scan ' + data.status,
                            'Scan #' + scanId + ' has ' + data.status + ' (' + data.progress + '%).',
                            icon
                        );
                        onComplete(data);
                    }
                })
                .catch(function() { /* silently retry */ });
            }, frequency);
        },

        stop: function(scanId) {
            if (this.intervals[scanId]) {
                clearInterval(this.intervals[scanId]);
                delete this.intervals[scanId];
            }
        }
    };

    // =============================================
    // Public API
    // =============================================
    window.PentestAI = {
        showToast: function(type, title, message, icon, duration) {
            return ToastManager.show(type, title, message, icon, duration);
        },
        startScanPolling: function(scanId, options) {
            ScanPoller.start(scanId, options);
        },
        stopScanPolling: function(scanId) {
            ScanPoller.stop(scanId);
        },
        getCSRFToken: getCSRFToken,
        NotificationPoller: NotificationPoller,
        ToastManager: ToastManager
    };

    // =============================================
    // DOM Ready Initialization
    // =============================================
    document.addEventListener('DOMContentLoaded', function() {
        // Initialize toast container
        ToastManager.init();

        // Auto-dismiss flash messages after 5 seconds
        var flashMessages = document.querySelectorAll('.flash-message');
        flashMessages.forEach(function(msg) {
            setTimeout(function() {
                msg.style.opacity = '0';
                msg.style.transform = 'translateY(-10px)';
                setTimeout(function() { msg.remove(); }, 300);
            }, 5000);
        });

        // Confirm before dangerous actions
        var dangerForms = document.querySelectorAll('form[data-confirm]');
        dangerForms.forEach(function(form) {
            form.addEventListener('submit', function(e) {
                var message = form.getAttribute('data-confirm') || 'Are you sure?';
                if (!confirm(message)) {
                    e.preventDefault();
                }
            });
        });

        // Toggle add-target form visibility
        var toggleButtons = document.querySelectorAll('[data-toggle]');
        toggleButtons.forEach(function(btn) {
            btn.addEventListener('click', function() {
                var target = document.getElementById(btn.getAttribute('data-toggle'));
                if (target) {
                    target.style.display = target.style.display === 'none' ? 'block' : 'none';
                }
            });
        });

        // Notification dropdown toggle
        var notifBtn = document.querySelector('.nav-notification');
        var notifDropdown = document.querySelector('.notification-dropdown');
        if (notifBtn && notifDropdown) {
            notifBtn.addEventListener('click', function(e) {
                e.stopPropagation();
                notifDropdown.classList.toggle('open');
                if (notifDropdown.classList.contains('open')) {
                    loadNotifications();
                }
            });

            // Close dropdown on outside click
            document.addEventListener('click', function(e) {
                if (!notifBtn.contains(e.target) && !notifDropdown.contains(e.target)) {
                    notifDropdown.classList.remove('open');
                }
            });

            // Mark all as read
            var markAllBtn = notifDropdown.querySelector('.mark-all-read-btn');
            if (markAllBtn) {
                markAllBtn.addEventListener('click', function(e) {
                    e.preventDefault();
                    e.stopPropagation();
                    fetch('/api/notifications/read-all', {
                        method: 'POST',
                        headers: {
                            'X-CSRFToken': window.CSRF_TOKEN,
                            'Content-Type': 'application/json'
                        }
                    })
                    .then(function(response) { return response.json(); })
                    .then(function(data) {
                        if (data.success) {
                            loadNotifications();
                            NotificationPoller._updateBadge();
                        }
                    })
                    .catch(function() { /* silently fail */ });
                });
            }
        }

        // Mark single notification as read on click
        document.addEventListener('click', function(e) {
            var item = e.target.closest('.notification-item');
            if (item) {
                var notifId = item.getAttribute('data-notification-id');
                if (notifId) {
                    fetch('/api/notifications/' + notifId + '/read', {
                        method: 'POST',
                        headers: {
                            'X-CSRFToken': window.CSRF_TOKEN,
                            'Content-Type': 'application/json'
                        }
                    })
                    .then(function(response) { return response.json(); })
                    .then(function() {
                        item.classList.remove('unread');
                        NotificationPoller._updateBadge();
                    })
                    .catch(function() { /* silently fail */ });
                }
            }
        });

        // Start notification polling for logged-in users
        if (document.querySelector('.nav-notification')) {
            NotificationPoller.start();
        }

        // Live scan status polling for scan detail pages
        var scanStatusEl = document.querySelector('[data-scan-id]');
        if (scanStatusEl) {
            var scanId = scanStatusEl.getAttribute('data-scan-id');
            ScanPoller.start(scanId, {
                frequency: 5000,
                onUpdate: function(data) {
                    // Update progress bar
                    var progressFill = document.querySelector('.scan-detail-progress .progress-fill');
                    var progressText = document.querySelector('.scan-detail-progress .progress-text');
                    if (progressFill) progressFill.style.width = data.progress + '%';
                    if (progressText) progressText.textContent = data.progress + '%';

                    // Update job status dots
                    if (data.jobs) {
                        data.jobs.forEach(function(job) {
                            var jobEl = document.querySelector('.job-item[data-job-id="' + job.id + '"]');
                            if (jobEl) {
                                var dot = jobEl.querySelector('.job-status-dot');
                                if (dot) {
                                    dot.className = 'job-status-dot dot-' + job.status;
                                }
                                var badge = jobEl.querySelector('.badge');
                                if (badge) {
                                    badge.textContent = job.status;
                                    badge.className = 'badge badge-' + (
                                        job.status === 'completed' ? 'success' :
                                        job.status === 'running' ? 'warning' :
                                        job.status === 'failed' ? 'danger' : 'secondary'
                                    );
                                }
                            }
                        });
                    }

                    // Update job counts
                    var totalEl = document.querySelector('[data-scan-total]');
                    var completedEl = document.querySelector('[data-scan-completed]');
                    var failedEl = document.querySelector('[data-scan-failed]');
                    if (totalEl) totalEl.textContent = data.total_jobs;
                    if (completedEl) completedEl.textContent = data.completed_jobs;
                    if (failedEl) failedEl.textContent = data.failed_jobs;
                },
                onComplete: function(data) {
                    // Reload page after a short delay
                    setTimeout(function() { location.reload(); }, 1500);
                }
            });
        }
    });

    // =============================================
    // Notification Loading Helper
    // =============================================
    function loadNotifications() {
        var listEl = document.querySelector('.notification-list');
        if (!listEl) return;

        fetch('/api/notifications', {
            headers: {'X-CSRFToken': window.CSRF_TOKEN}
        })
        .then(function(response) { return response.json(); })
        .then(function(notifications) {
            listEl.innerHTML = '';
            if (notifications.length === 0) {
                listEl.innerHTML = '<div class="notification-empty">No new notifications</div>';
                return;
            }
            notifications.forEach(function(n) {
                var item = document.createElement('div');
                item.className = 'notification-item unread';
                item.setAttribute('data-notification-id', n.id);

                var timeAgo = formatTimeAgo(n.created_at);
                item.innerHTML =
                    '<span class="notification-dot type-' + (n.type || 'system') + '"></span>' +
                    '<div class="notification-content">' +
                        '<div class="notification-title">' + escapeHtml(n.title) + '</div>' +
                        '<div class="notification-message">' + escapeHtml(n.message) + '</div>' +
                        '<div class="notification-time">' + timeAgo + '</div>' +
                    '</div>';

                listEl.appendChild(item);
            });
        })
        .catch(function() {
            listEl.innerHTML = '<div class="notification-empty">Failed to load notifications</div>';
        });
    }

    function formatTimeAgo(isoString) {
        if (!isoString) return '';
        try {
            var date = new Date(isoString);
            var now = new Date();
            var diff = Math.floor((now - date) / 1000);
            if (diff < 60) return 'just now';
            if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
            if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
            return Math.floor(diff / 86400) + 'd ago';
        } catch (e) {
            return '';
        }
    }

    function escapeHtml(str) {
        if (!str) return '';
        var div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

})();
