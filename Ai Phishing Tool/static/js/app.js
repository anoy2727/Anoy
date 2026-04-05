/**
 * PhishGuard AI - Dashboard JavaScript
 * Real-time URL analysis with animated results
 */

let selectedModel = 'roberta';

function selectModel(model) {
    selectedModel = model;
    document.querySelectorAll('.model-btn').forEach(btn => {
        btn.classList.remove('model-btn-active');
    });
    const activeBtn = model === 'roberta' ? document.getElementById('btnRoberta') : document.getElementById('btnAutoencoder');
    activeBtn.classList.add('model-btn-active');
}

async function analyzeURL() {
    const urlInput = document.getElementById('urlInput');
    const url = urlInput.value.trim();

    if (!url) {
        showToast('Please enter a URL to analyze.', 'warning');
        urlInput.focus();
        return;
    }

    const analyzeBtn = document.getElementById('analyzeBtn');
    analyzeBtn.classList.add('analyzing');
    analyzeBtn.disabled = true;

    try {
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url, model: selectedModel })
        });

        if (!response.ok) {
            const errData = await response.json();
            throw new Error(errData.error || 'Analysis failed');
        }

        const result = await response.json();
        displayResult(result, url);

    } catch (err) {
        showToast(err.message || 'Something went wrong.', 'error');
    } finally {
        analyzeBtn.classList.remove('analyzing');
        analyzeBtn.disabled = false;
    }
}

function displayResult(result, url) {
    const panel = document.getElementById('resultPanel');
    const card = document.getElementById('resultCard');
    const isPhishing = result.prediction === 'Phishing';

    // Remove old state classes
    card.classList.remove('result-phishing', 'result-legitimate');
    card.classList.add(isPhishing ? 'result-phishing' : 'result-legitimate');

    // Icon & prediction
    document.getElementById('resultIcon').textContent = isPhishing ? '🚨' : '✅';
    document.getElementById('resultPrediction').textContent = result.prediction;
    document.getElementById('resultModel').textContent = `${result.model} · ${result.model_description}`;

    // URL
    document.getElementById('resultUrlValue').textContent = url;

    // Confidence ring animation
    const confidencePercent = Math.round(result.confidence * 100);
    const circumference = 2 * Math.PI * 52; // r=52
    const offset = circumference - (confidencePercent / 100) * circumference;

    const fill = document.getElementById('confidenceFill');
    fill.style.strokeDasharray = circumference;
    fill.style.strokeDashoffset = circumference;

    // Force reflow for animation
    void fill.offsetWidth;
    requestAnimationFrame(() => {
        fill.style.strokeDashoffset = offset;
    });

    // Animate confidence number
    animateCounter('confidenceNumber', 0, confidencePercent, 1200);

    // Risk score bar
    const riskPercent = Math.round((result.risk_score || 0) * 100);
    document.getElementById('riskScoreLabel').textContent = riskPercent + '%';
    const riskFill = document.getElementById('riskBarFill');
    riskFill.style.width = '0%';
    void riskFill.offsetWidth;
    requestAnimationFrame(() => {
        riskFill.style.width = riskPercent + '%';
    });

    // Feature grid
    const grid = document.getElementById('featuresGrid');
    grid.innerHTML = '';
    if (result.features) {
        for (const [key, value] of Object.entries(result.features)) {
            const item = document.createElement('div');
            item.className = 'feature-item';
            item.innerHTML = `
                <span class="feature-item-label">${escapeHtml(key)}</span>
                <span class="feature-item-value">${escapeHtml(String(value))}</span>
            `;
            grid.appendChild(item);
        }
    }

    // Show panel
    panel.style.display = 'block';
    panel.scrollIntoView({ behavior: 'smooth', block: 'start' });

    // Update stats
    updateDashStats();
}

function animateCounter(elementId, start, end, duration) {
    const el = document.getElementById(elementId);
    const range = end - start;
    const startTime = performance.now();

    function step(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3); // easeOutCubic
        const current = Math.round(start + range * eased);
        el.textContent = current;
        if (progress < 1) {
            requestAnimationFrame(step);
        }
    }

    requestAnimationFrame(step);
}

function updateDashStats() {
    fetch('/api/history')
        .then(res => res.json())
        .then(history => {
            const totalEl = document.getElementById('totalScans');
            const threatsEl = document.getElementById('threatsFound');
            if (totalEl) totalEl.textContent = history.length;
            if (threatsEl) threatsEl.textContent = history.filter(h => h.prediction === 'Phishing').length;
        })
        .catch(() => { });
}

function clearHistory() {
    if (!confirm('Clear all scan history?')) return;
    fetch('/api/history/clear', { method: 'POST' })
        .then(res => res.json())
        .then(() => {
            const historyList = document.getElementById('historyList');
            historyList.innerHTML = `
                <div class="history-empty">
                    <span class="history-empty-icon">🔍</span>
                    <p>No scans yet. Analyze your first URL above!</p>
                </div>
            `;
            updateDashStats();
            showToast('History cleared.', 'success');
        })
        .catch(() => showToast('Failed to clear history.', 'error'));
}

function analyzeFromHistory(url, model) {
    document.getElementById('urlInput').value = url;
    selectModel(model.toLowerCase().replace(' ', ''));
    analyzeURL();
}

function showToast(message, type) {
    const icons = { success: '✅', error: '❌', warning: '⚠️', info: 'ℹ️' };
    const toast = document.createElement('div');
    toast.className = `flash flash-${type}`;
    toast.innerHTML = `
        <span class="flash-icon">${icons[type] || 'ℹ️'}</span>
        ${escapeHtml(message)}
        <button class="flash-close" onclick="this.parentElement.remove()">✕</button>
    `;

    let container = document.querySelector('.flash-container');
    if (!container) {
        container = document.createElement('div');
        container.className = 'flash-container';
        document.body.appendChild(container);
    }
    container.appendChild(toast);

    setTimeout(() => toast.remove(), 5000);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Enter key to analyze
document.addEventListener('DOMContentLoaded', () => {
    const urlInput = document.getElementById('urlInput');
    if (urlInput) {
        urlInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                analyzeURL();
            }
        });
    }
});
