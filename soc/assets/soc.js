(function () {
    var settings = {
        theme: localStorage.getItem('soc-theme') || 'light',
        refresh: localStorage.getItem('soc-refresh') !== '0',
        interval: Number(localStorage.getItem('soc-refresh-interval') || 10000),
        compact: localStorage.getItem('soc-compact') === '1'
    };

    function escapeHtml(value) {
        return String(value == null ? '' : value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    function t(key, fallback) {
        return (window.SOC_I18N && window.SOC_I18N[key]) || fallback || key;
    }

    function applySettings() {
        document.documentElement.setAttribute('data-theme', settings.theme);
        document.documentElement.classList.toggle('compact-rows', settings.compact);
    }

    function setText(selector, value) {
        document.querySelectorAll(selector).forEach(function (node) {
            node.textContent = value;
        });
    }

    function sourceRows(sources, total) {
        if (!sources || !sources.length) {
            return '<p class="empty-note">' + escapeHtml(t('empty_sources', 'Aucune source détectée.')) + '</p>';
        }
        return sources.map(function (source) {
            var count = Number(source.total || 0);
            var width = total > 0 ? Math.max(8, (count / total) * 100) : 0;
            return '<div class="source-row">' +
                '<span>' + escapeHtml(source.source_ip) + '</span>' +
                '<b>' + escapeHtml(count) + '</b>' +
                '<i><em style="width: ' + width.toFixed(2) + '%;"></em></i>' +
            '</div>';
        }).join('');
    }

    function renderTrend(trend) {
        trend = Array.isArray(trend) ? trend : [];
        var width = 640;
        var height = 250;
        var left = 48;
        var right = 22;
        var top = 24;
        var bottom = 42;
        var plotWidth = width - left - right;
        var plotHeight = height - top - bottom;
        var max = 1;
        trend.forEach(function (point) {
            max = Math.max(max, Number(point.total || 0));
        });
        var count = Math.max(1, trend.length);
        var alertPoints = [];
        trend.forEach(function (point, index) {
            var x = left + (count === 1 ? plotWidth / 2 : (index / (count - 1)) * plotWidth);
            var alertY = top + plotHeight - ((Number(point.total || 0) / max) * plotHeight);
            alertPoints.push(x.toFixed(1) + ',' + alertY.toFixed(1));
        });

        var grid = '';
        for (var i = 0; i <= 4; i++) {
            var y = top + (plotHeight / 4) * i;
            grid += '<line x1="' + left + '" y1="' + y.toFixed(1) + '" x2="' + (width - right) + '" y2="' + y.toFixed(1) + '"></line>';
        }

        var labels = trend.map(function (point, index) {
            var x = left + (count === 1 ? plotWidth / 2 : (index / (count - 1)) * plotWidth);
            var step = Math.max(1, Math.ceil(count / 6));
            if (count > 10 && index % step !== 0 && index !== count - 1) {
                return '';
            }
            return '<text x="' + x.toFixed(1) + '" y="' + (height - 14) + '" text-anchor="middle">' + escapeHtml(point.label) + '</text>';
        }).join('');

        return '<svg class="trend-svg" viewBox="0 0 ' + width + ' ' + height + '" role="img" aria-label="' + escapeHtml(t('trend_aria', 'Alert trend')) + '">' +
            '<g class="grid-lines">' + grid + '</g>' +
            '<polyline class="trend-line total" points="' + alertPoints.join(' ') + '"></polyline>' +
            labels +
        '</svg>';
    }

    function renderAlerts(alerts, selectedId) {
        if (!alerts || !alerts.length) {
            return '<tr><td colspan="7" class="empty-cell">' + escapeHtml(t('empty_alerts', 'Aucune alerte ne correspond aux filtres.')) + '</td></tr>';
        }
        return alerts.map(function (alert) {
            var selected = selectedId && Number(alert.id) === Number(selectedId) ? ' selected' : '';
            var url = updateUrlId(alert.id);
            return '<tr class="clickable-row' + selected + '" data-alert-row="' + escapeHtml(alert.id) + '" data-row-url="' + escapeHtml(url) + '">' +
                '<td>' + escapeHtml(alert.timestamp) + '</td>' +
                '<td><span class="attack-label ' + escapeHtml(alert.attack_token) + '">' + escapeHtml(alert.attack_label) + '</span></td>' +
                '<td><span class="pill severity-' + escapeHtml(String(alert.severity).toLowerCase()) + '">' + escapeHtml(alert.severity_label) + '</span></td>' +
                '<td>' + escapeHtml(alert.source_ip) + '</td>' +
                '<td class="url-cell">' + escapeHtml(alert.url) + '</td>' +
                '<td><span class="pill status-' + escapeHtml(alert.status_token) + '">' + escapeHtml(alert.status_label) + '</span></td>' +
                '<td><a class="mini-link" href="' + escapeHtml(url) + '">' + escapeHtml(t('view', 'Voir')) + '</a></td>' +
            '</tr>';
        }).join('');
    }

    function dashboardParams() {
        var params = new URLSearchParams(window.location.search);
        params.delete('q');
        params.delete('mode');
        return params;
    }

    function dashboardApiUrl() {
        var params = dashboardParams();
        var query = params.toString();
        return 'api.php' + (query ? '?' + query : '');
    }

    function updateUrlId(id) {
        var params = dashboardParams();
        params.set('id', id);
        var query = params.toString();
        return 'index.php' + (query ? '?' + query : '');
    }

    function apiUrlForId(id) {
        var params = dashboardParams();
        params.set('id', id);
        params.set('mode', 'detail');
        var query = params.toString();
        return 'api.php' + (query ? '?' + query : '');
    }

    function selectDashboardAlert(id) {
        if (!id) return;
        var scrollX = window.scrollX;
        var scrollY = window.scrollY;
        var pageUrl = updateUrlId(id);
        history.replaceState(null, '', pageUrl);
        document.querySelectorAll('[data-alert-row]').forEach(function (row) {
            row.classList.toggle('selected', Number(row.getAttribute('data-alert-row')) === Number(id));
        });
        fetch(apiUrlForId(id), { cache: 'no-store' })
            .then(function (response) { return response.ok ? response.json() : null; })
            .then(function (data) {
                if (!data) return;
                var detail = document.querySelector('[data-detail-card]');
                if (detail) {
                    detail.innerHTML = renderDetail(data.selected_alert);
                }
                if (Object.prototype.hasOwnProperty.call(data, 'unread_count')) {
                    setText('.soc-nav b', data.unread_count || 0);
                }
                requestAnimationFrame(function () {
                    window.scrollTo(scrollX, scrollY);
                });
            })
            .catch(function () {});
    }

    function detailRow(label, value, isCode, isChip) {
        var content = isCode
            ? '<code>' + escapeHtml(value) + '</code>'
            : (isChip ? '<span class="mitre-chip">' + escapeHtml(value) + '</span>' : escapeHtml(value));
        return '<div><dt>' + escapeHtml(label) + '</dt><dd>' + content + '</dd></div>';
    }

    function detailVisible(display, key) {
        return !display || display[key] !== false;
    }

    function renderDetail(alert) {
        if (!alert) {
            return '<div class="panel-head"><h2>' + escapeHtml(t('detail_title', 'Détail alerte')) + '</h2></div><p class="empty-note">' + escapeHtml(t('no_alert_selected', 'Aucune alerte sélectionnée.')) + '</p>';
        }
        var display = alert.display || {};
        var rows = [
            detailRow(t('source_ip', 'IP source'), alert.source_ip, false, false),
            detailRow(t('target_url', 'URL ciblée'), alert.url, false, false),
            detailRow(t('payload', 'Payload'), alert.payload, true, false),
            detailRow(t('triggered_rule', 'Règle déclenchée'), alert.triggered_rule, false, false)
        ];

        if (detailVisible(display, 'show_mitre_id')) {
            rows.push(detailRow(t('mitre_id', 'MITRE ID'), alert.mitre_id, false, true));
        }
        if (detailVisible(display, 'show_mitre_tactic')) {
            rows.push(detailRow(t('tactic', 'Tactique'), alert.mitre_tactic, false, false));
        }
        if (detailVisible(display, 'show_mitre_technique')) {
            rows.push(detailRow(t('technique', 'Technique'), alert.mitre_technique, false, false));
        }
        if (detailVisible(display, 'show_recommended_response')) {
            rows.push(detailRow(t('recommended_response', 'Réponse recommandée'), alert.recommended_response, false, false));
        }

        return '<div class="panel-head">' +
            '<h2>' + escapeHtml(t('detail_title', 'Détail alerte')) + '</h2>' +
            '<a class="mini-link" href="' + escapeHtml(alert.detail_url) + '">' + escapeHtml(t('detail_page', 'Page détail')) + '</a>' +
        '</div>' +
        '<div class="detail-badges">' +
            '<span class="pill severity-' + escapeHtml(String(alert.severity).toLowerCase()) + '">' + escapeHtml(alert.severity_label) + '</span>' +
            '<span class="pill status-' + escapeHtml(alert.status_token) + '">' + escapeHtml(alert.status_label) + '</span>' +
        '</div>' +
        '<dl class="detail-list">' + rows.join('') + '</dl>' +
        '<form class="status-form" method="post">' +
            '<input type="hidden" name="csrf" value="' + escapeHtml(window.SOC_CSRF || '') + '">' +
            '<input type="hidden" name="action" value="update_status">' +
            '<label>Justification / Investigation<textarea name="note" maxlength="1000" rows="3"></textarea></label>' +
            '<input type="hidden" name="id" value="' + escapeHtml(alert.id) + '">' +
            '<label for="status">' + escapeHtml(t('status', 'Statut')) + '</label>' +
            '<div><select id="status" name="status">' +
                statusOption('nouveau', t('status_new', 'Nouveau'), alert.status) +
                statusOption('en_cours', t('status_progress', 'En cours'), alert.status) +
                statusOption('resolu', t('status_resolved', 'Résolu'), alert.status) +
                statusOption('faux_positif', t('status_false_positive', 'Faux positif'), alert.status) +
            '</select><button type="submit">' + escapeHtml(t('update', 'Mettre à jour')) + '</button></div>' +
        '</form>';
    }

    function statusOption(value, label, current) {
        return '<option value="' + escapeHtml(value) + '"' + (value === current ? ' selected' : '') + '>' + escapeHtml(label) + '</option>';
    }

    function renderDashboard(data) {
        if (!data || !data.stats) return;

        setText('[data-stat="total"]', data.stats.total);
        setText('[data-stat="sqli"]', data.stats.sqli);
        setText('[data-stat="xss"]', data.stats.xss);
        setText('[data-stat="brute_force"]', data.stats.brute_force);
        setText('[data-stat="donut_total"]', data.stats.total);
        setText('[data-alert-count]', data.filtered_total);
        setText('[data-updated-at]', data.generated_at);
        setText('.soc-nav b', data.unread_count || 0);

        var severities = data.stats.severity || {};
        Object.keys(severities).forEach(function (key) {
            setText('[data-severity="' + key + '"]', severities[key]);
        });
        var severityTotal = Object.keys(severities).reduce(function (sum, key) {
            return sum + Number(severities[key] || 0);
        }, 0);
        setText('[data-severity-total]', severityTotal + ' ' + t('alerts_lower', 'alertes'));

        var donut = document.querySelector('[data-donut]');
        if (donut) {
            donut.setAttribute('style', data.donut_style || 'background: var(--empty-ring);');
        }

        var sources = document.querySelector('[data-sources]');
        if (sources) {
            sources.innerHTML = sourceRows(data.stats.sources || [], Number(data.stats.total || 0));
        }

        var trend = document.querySelector('[data-trend-chart]');
        if (trend) {
            trend.innerHTML = renderTrend(data.trend || []);
        }

        var selectedId = data.selected_alert ? data.selected_alert.id : 0;
        var table = document.querySelector('[data-alerts-table]');
        if (table) {
            table.innerHTML = renderAlerts(data.alerts || [], selectedId);
        }

        var detail = document.querySelector('[data-detail-card]');
        if (detail) {
            detail.innerHTML = renderDetail(data.selected_alert);
        }

        if (data.detection) {
            setText('[data-stat="score_global"]', data.detection.score_global);
            setText('[data-stat="score_level"]', data.detection.score_level);
            setText('[data-live-label]', data.detection.label);
            setText('[data-live-last]', data.detection.last_seen);
            setText('[data-live-score]', data.detection.score_global + ' / ' + data.detection.score_level);
            document.querySelectorAll('.live-dot').forEach(function (dot) {
                dot.className = 'live-dot ' + data.detection.state;
            });
        }
    }

    function initLiveDashboard() {
        var root = document.querySelector('[data-live-dashboard]');
        if (!root) return;
        var timer = null;

        function refresh() {
            if (!settings.refresh) return;
            fetch(dashboardApiUrl(), { cache: 'no-store' })
                .then(function (response) { return response.ok ? response.json() : null; })
                .then(renderDashboard)
                .catch(function () {});
        }

        function schedule() {
            if (timer) clearInterval(timer);
            if (settings.refresh) {
                timer = setInterval(refresh, Math.max(5000, settings.interval || 10000));
            }
        }

        schedule();
        refresh();
    }

    function initSettingsPage() {
        var themeButtons = document.querySelectorAll('[data-setting-theme] button');
        var refreshInput = document.querySelector('[data-setting-refresh]');
        var intervalInput = document.querySelector('[data-setting-interval]');
        var compactInput = document.querySelector('[data-setting-compact]');

        function syncControls() {
            themeButtons.forEach(function (button) {
                button.classList.toggle('active', button.getAttribute('data-theme-value') === settings.theme);
            });
            if (refreshInput) refreshInput.checked = settings.refresh;
            if (intervalInput) intervalInput.value = String(settings.interval);
            if (compactInput) compactInput.checked = settings.compact;
        }

        themeButtons.forEach(function (button) {
            button.addEventListener('click', function () {
                settings.theme = button.getAttribute('data-theme-value') || 'light';
                localStorage.setItem('soc-theme', settings.theme);
                applySettings();
                syncControls();
            });
        });

        if (refreshInput) {
            refreshInput.addEventListener('change', function () {
                settings.refresh = refreshInput.checked;
                localStorage.setItem('soc-refresh', settings.refresh ? '1' : '0');
            });
        }

        if (intervalInput) {
            intervalInput.addEventListener('change', function () {
                settings.interval = Number(intervalInput.value || 10000);
                localStorage.setItem('soc-refresh-interval', String(settings.interval));
            });
        }

        if (compactInput) {
            compactInput.addEventListener('change', function () {
                settings.compact = compactInput.checked;
                localStorage.setItem('soc-compact', settings.compact ? '1' : '0');
                applySettings();
            });
        }

        syncControls();
    }

    function submitStatusForm(form) {
        var submitter = form.querySelector('button[type="submit"]');
        var data = new FormData(form);
        if (!data.get('csrf') && window.SOC_CSRF) {
            data.set('csrf', window.SOC_CSRF);
        }

        if (submitter) submitter.disabled = true;
        fetch(dashboardApiUrl(), {
            method: 'POST',
            body: data,
            cache: 'no-store'
        })
            .then(function (response) { return response.ok ? response.json() : null; })
            .then(function (payload) {
                if (payload) renderDashboard(payload);
            })
            .catch(function () {})
            .finally(function () {
                if (submitter) submitter.disabled = false;
            });
    }

    function initStatusForms() {
        document.addEventListener('submit', function (event) {
            var form = event.target.closest('.status-form');
            if (!form || !document.querySelector('[data-live-dashboard]')) return;
            event.preventDefault();
            submitStatusForm(form);
        });
    }

    function initClickableRows() {
        document.addEventListener('click', function (event) {
            var detailLink = event.target.closest('[data-alerts-table] a.mini-link');
            if (detailLink) {
                var linkRow = detailLink.closest('[data-alert-row]');
                if (!linkRow) return;
                event.preventDefault();
                selectDashboardAlert(linkRow.getAttribute('data-alert-row'));
                return;
            }

            if (event.target.closest('a, button, input, select, label')) return;
            var row = event.target.closest('[data-alert-row]');
            if (!row) return;
            selectDashboardAlert(row.getAttribute('data-alert-row'));
        });
    }

    applySettings();
    initSettingsPage();
    initStatusForms();
    initClickableRows();
    initLiveDashboard();
}());
