"""Custom CSS for the Dash security console UI."""

CUSTOM_STYLE = '''
<style>
:root {
    --bg: #f3f7fb;
    --bg-panel: #ffffff;
    --ink-900: #10233a;
    --ink-700: #2f4a68;
    --ink-500: #587290;
    --line: #d8e3ef;
    --brand: #0a84ff;
    --brand-700: #0069d9;
    --brand-soft: #e6f2ff;
    --success: #0f9d58;
    --warning: #d9822b;
    --danger: #d64550;
    --shadow-soft: 0 12px 32px rgba(16, 35, 58, 0.08);
    --shadow-hover: 0 18px 42px rgba(16, 35, 58, 0.14);
}

html,
body {
    margin: 0;
    background:
        radial-gradient(circle at 15% 5%, rgba(10, 132, 255, 0.16), transparent 34%),
        radial-gradient(circle at 85% 2%, rgba(14, 158, 104, 0.12), transparent 32%),
        linear-gradient(180deg, #f9fbfe 0%, var(--bg) 100%);
    color: var(--ink-900);
    font-family: "DM Sans", "Avenir Next", sans-serif;
}

h1,
h2,
h3,
h4,
h5,
h6,
.nav-link,
.card-title,
.hero-kicker {
    font-family: "Sora", "Trebuchet MS", sans-serif;
}

.app-shell {
    max-width: 1520px;
    padding-bottom: 32px;
}

.hero-panel {
    background:
        linear-gradient(120deg, rgba(10, 132, 255, 0.97), rgba(13, 77, 169, 0.97)),
        repeating-linear-gradient(
            -45deg,
            rgba(255, 255, 255, 0.08),
            rgba(255, 255, 255, 0.08) 12px,
            transparent 12px,
            transparent 24px
        );
    border-radius: 24px;
    border: 1px solid rgba(255, 255, 255, 0.36);
    box-shadow: var(--shadow-soft);
    color: #ffffff;
    padding: 26px 28px;
}

.hero-kicker {
    display: inline-block;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    font-size: 11px;
    font-weight: 700;
    opacity: 0.9;
    margin-bottom: 10px;
}

.hero-title {
    margin: 0;
    font-size: clamp(1.5rem, 3vw, 2.3rem);
    letter-spacing: -0.02em;
}

.hero-subtitle {
    margin: 10px 0 0;
    font-size: 0.99rem;
    max-width: 860px;
    opacity: 0.95;
}

.nav-tabs {
    border: none;
    gap: 8px;
    background: transparent;
    flex-wrap: wrap;
}

.nav-tabs .nav-link {
    border: 1px solid var(--line);
    border-radius: 999px;
    color: var(--ink-700);
    font-weight: 600;
    background: rgba(255, 255, 255, 0.7);
    padding: 10px 14px;
    transition: all 0.2s ease;
}

.nav-tabs .nav-link:hover {
    border-color: #b8cadf;
    color: var(--ink-900);
}

.nav-tabs .nav-link.active,
.nav-tabs .nav-item.show .nav-link {
    color: #ffffff;
    background: linear-gradient(120deg, var(--brand), var(--brand-700));
    border-color: transparent;
    box-shadow: 0 8px 18px rgba(10, 132, 255, 0.26);
}

.tab-content-shell {
    animation: fadeUp 260ms ease;
}

.card {
    border-radius: 18px !important;
    border: 1px solid var(--line) !important;
    background: var(--bg-panel) !important;
    box-shadow: var(--shadow-soft);
    overflow: hidden;
    transition: transform 0.2s ease, box-shadow 0.2s ease, border-color 0.2s ease;
}

.card:hover {
    transform: translateY(-3px);
    box-shadow: var(--shadow-hover);
    border-color: #b8cadf !important;
}

.card-header {
    background: linear-gradient(180deg, #f8fbff 0%, #f1f6fc 100%) !important;
    border-bottom: 1px solid var(--line) !important;
    color: var(--ink-900) !important;
    font-weight: 700;
    padding: 14px 16px !important;
}

.card-title {
    color: var(--ink-700);
    font-size: 0.9rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 8px;
}

.card h2 {
    color: var(--ink-900);
    letter-spacing: -0.03em;
    font-weight: 800;
}

.log-stream,
#raw-file-content,
#security-events-list,
#raw-data-table {
    border: 1px solid var(--line) !important;
    border-radius: 12px;
    background: linear-gradient(180deg, #0f1927 0%, #0a1220 100%) !important;
    color: #d2e6ff !important;
}

.log-stream {
    box-shadow: inset 0 0 0 1px rgba(100, 146, 194, 0.12);
}

.btn {
    border-radius: 12px;
    font-weight: 600;
    border-width: 1px;
}

.btn-primary {
    background: linear-gradient(120deg, var(--brand), var(--brand-700));
    border: none;
}

.btn-primary:hover {
    filter: brightness(1.06);
}

.btn-danger {
    background-color: var(--danger);
    border-color: var(--danger);
}

.btn-success {
    background-color: var(--success);
    border-color: var(--success);
}

.btn-warning {
    color: #10233a;
    background-color: #f7b267;
    border-color: #f7b267;
}

.form-control,
.form-select,
.Select-control,
.Select-menu-outer {
    border-radius: 12px !important;
    border-color: #c7d6e6 !important;
    background-color: #fdfefe !important;
}

.form-control:focus,
.form-select:focus {
    border-color: var(--brand) !important;
    box-shadow: 0 0 0 0.22rem rgba(10, 132, 255, 0.16) !important;
}

.table {
    border-color: var(--line);
}

.table-dark {
    --bs-table-bg: #0f1927;
    --bs-table-striped-bg: #132133;
    --bs-table-hover-bg: #1a2a3e;
    --bs-table-color: #d9ebff;
    --bs-table-border-color: #2f4865;
    border-radius: 14px;
    overflow: hidden;
}

.alert {
    border-radius: 14px;
    border-width: 1px;
}

@keyframes fadeUp {
    from {
        opacity: 0;
        transform: translateY(6px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

@media (max-width: 992px) {
    .hero-panel {
        padding: 22px 18px;
    }

    .hero-subtitle {
        font-size: 0.92rem;
    }

    .nav-tabs .nav-link {
        width: 100%;
        text-align: center;
    }
}

@media (max-width: 576px) {
    .card {
        border-radius: 14px !important;
    }

    .card-body {
        padding: 14px;
    }

    .hero-title {
        font-size: 1.45rem;
    }
}
</style>
'''
