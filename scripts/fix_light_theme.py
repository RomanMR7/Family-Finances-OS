import re

def fix_light_theme():
    with open('family_finances_os/web_server.py', 'r', encoding='utf-8') as f:
        content = f.read()

    # 1. Ensure --bg-gradient is properly defined for BOTH dark and light themes
    # In [data-theme="light"] root variables, add --bg-gradient and refine tokens
    target_light_root = """    [data-theme="light"] {
      --bg: #f5f6f8;
      --card-bg: #ffffff;"""

    repl_light_root = """    [data-theme="light"] {
      --bg: #f8fafc;
      --bg-gradient: linear-gradient(180deg, #f8fafc 0%, #f1f5f9 100%);
      --card-bg: #ffffff;"""

    if target_light_root in content:
        content = content.replace(target_light_root, repl_light_root, 1)
        print("Updated [data-theme='light'] root tokens!")
    else:
        print("target_light_root not found, checking with regex...")
        content = re.sub(
            r'(\[data-theme=["\']light["\']\]\s*\{\s*--bg:\s*[^;]+;)',
            r'\1\n      --bg-gradient: linear-gradient(180deg, #f8fafc 0%, #f1f5f9 100%);',
            content,
            count=1
        )
        print("Regex replaced --bg-gradient in [data-theme='light']!")

    # 2. Add comprehensive light-theme CSS overrides
    light_theme_comprehensive_css = """
    /* ==========================================================================
       BULLETPROOF LIGHT THEME HIGH-CONTRAST SPECIFICATION (REVOLUT / HALLMARK)
       ========================================================================== */
    [data-theme="light"] body {
      background: #f8fafc !important;
      background-image: linear-gradient(180deg, #f8fafc 0%, #f1f5f9 100%) !important;
      color: #0f172a !important;
    }

    [data-theme="light"] .header {
      background: rgba(255, 255, 255, 0.92) !important;
      backdrop-filter: blur(20px) !important;
      -webkit-backdrop-filter: blur(20px) !important;
      border-bottom: 1px solid #e2e8f0 !important;
    }

    [data-theme="light"] .brand-title {
      color: #0f172a !important;
    }

    [data-theme="light"] .brand-tag {
      color: #64748b !important;
    }

    /* Cards */
    [data-theme="light"] .card,
    [data-theme="light"] .desktop-main-column .card,
    [data-theme="light"] .desktop-widget-column .card {
      background: #ffffff !important;
      border: 1px solid #e2e8f0 !important;
      border-top: 1px solid #cbd5e1 !important;
      box-shadow: 0 4px 20px -2px rgba(15, 23, 42, 0.06) !important;
      color: #0f172a !important;
    }

    [data-theme="light"] .card:hover {
      border-color: #cbd5e1 !important;
      box-shadow: 0 8px 30px -4px rgba(15, 23, 42, 0.1) !important;
    }

    /* Card Titles & Text */
    [data-theme="light"] h1,
    [data-theme="light"] h2,
    [data-theme="light"] h3,
    [data-theme="light"] h4,
    [data-theme="light"] .card-title,
    [data-theme="light"] .text-strong {
      color: #0f172a !important;
    }

    [data-theme="light"] p,
    [data-theme="light"] .text-muted,
    [data-theme="light"] .stat-label {
      color: #64748b !important;
    }

    /* Hero Balance Card in Light Theme */
    [data-theme="light"] .revolut-hero-card,
    [data-theme="light"] .appetite-hero-card {
      background: #ffffff !important;
      background-image: linear-gradient(180deg, #ffffff 0%, #f8fafc 100%) !important;
      border: 1px solid #e2e8f0 !important;
      border-top: 3px solid #2563eb !important;
      box-shadow: 0 10px 30px -4px rgba(15, 23, 42, 0.08) !important;
      color: #0f172a !important;
    }

    [data-theme="light"] .hero-balance-val {
      color: #0f172a !important;
    }

    [data-theme="light"] .hero-balance-label {
      color: #64748b !important;
    }

    [data-theme="light"] .hero-secondary-balance-box {
      background: #f1f5f9 !important;
      border: 1px solid #e2e8f0 !important;
      color: #0f172a !important;
    }

    [data-theme="light"] .hero-secondary-val {
      color: #0f172a !important;
    }

    [data-theme="light"] .hero-secondary-label {
      color: #64748b !important;
    }

    /* 4 Revolut Action Buttons in Light Theme */
    [data-theme="light"] .revolut-action-label,
    [data-theme="light"] .hero-action-btn span {
      color: #0f172a !important;
      font-weight: 600 !important;
    }

    [data-theme="light"] .hero-action-icon,
    [data-theme="light"] .revolut-action-icon {
      background: #f8fafc !important;
      border: 1px solid #e2e8f0 !important;
      color: #0f172a !important;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.04) !important;
    }

    [data-theme="light"] .revolut-icon-expense {
      background: #fef2f2 !important;
      border-color: #fecaca !important;
      color: #dc2626 !important;
    }

    [data-theme="light"] .revolut-icon-income {
      background: #f0fdf4 !important;
      border-color: #bbf7d0 !important;
      color: #16a34a !important;
    }

    [data-theme="light"] .revolut-icon-transfer {
      background: #eff6ff !important;
      border-color: #bfdbfe !important;
      color: #2563eb !important;
    }

    [data-theme="light"] .revolut-icon-goals {
      background: #fffbeb !important;
      border-color: #fde68a !important;
      color: #d97706 !important;
    }

    /* Navigation Tabs in Light Theme */
    [data-theme="light"] .nav-tabs {
      background: #f1f5f9 !important;
      border: 1px solid #e2e8f0 !important;
      box-shadow: inset 0 1px 2px rgba(0, 0, 0, 0.04) !important;
    }

    [data-theme="light"] .tab-btn {
      color: #64748b !important;
      background: transparent !important;
    }

    [data-theme="light"] .tab-btn:hover {
      color: #0f172a !important;
      background: #e2e8f0 !important;
    }

    [data-theme="light"] .tab-btn.active {
      color: #2563eb !important;
      background: #ffffff !important;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08) !important;
      font-weight: 700 !important;
    }

    /* Inputs & Selects in Light Theme */
    [data-theme="light"] input,
    [data-theme="light"] select,
    [data-theme="light"] textarea {
      background: #ffffff !important;
      color: #0f172a !important;
      border: 1px solid #cbd5e1 !important;
    }

    [data-theme="light"] input::placeholder,
    [data-theme="light"] textarea::placeholder {
      color: #94a3b8 !important;
    }

    [data-theme="light"] input:focus,
    [data-theme="light"] select:focus,
    [data-theme="light"] textarea:focus {
      background: #ffffff !important;
      color: #0f172a !important;
      border-color: #2563eb !important;
      box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.15) !important;
    }

    [data-theme="light"] label {
      color: #334155 !important;
      font-weight: 600 !important;
    }

    /* Buttons in Light Theme */
    [data-theme="light"] .btn-secondary {
      background: #f1f5f9 !important;
      color: #0f172a !important;
      border: 1px solid #cbd5e1 !important;
    }

    [data-theme="light"] .btn-secondary:hover {
      background: #e2e8f0 !important;
      color: #0f172a !important;
    }

    /* Stat Amounts in Light Theme */
    [data-theme="light"] .stat-val {
      color: #0f172a !important;
    }

    [data-theme="light"] .stat-val.primary { color: #2563eb !important; }
    [data-theme="light"] .stat-val.success { color: #16a34a !important; }
    [data-theme="light"] .stat-val.danger { color: #dc2626 !important; }
    [data-theme="light"] .stat-val.warning { color: #d97706 !important; }
    [data-theme="light"] .stat-val.purple { color: #7c3aed !important; }

    /* Tables & Rows in Light Theme */
    [data-theme="light"] table {
      color: #0f172a !important;
    }

    [data-theme="light"] th {
      background: #f8fafc !important;
      color: #64748b !important;
      border-bottom: 1px solid #e2e8f0 !important;
      font-weight: 600 !important;
    }

    [data-theme="light"] td {
      color: #0f172a !important;
      border-bottom: 1px solid #f1f5f9 !important;
    }

    [data-theme="light"] tbody tr:hover td {
      background: #f8fafc !important;
    }

    /* Modals & Bottom Sheets in Light Theme */
    [data-theme="light"] .modal-overlay,
    [data-theme="light"] [id^="modal"] {
      background: rgba(15, 23, 42, 0.5) !important;
    }

    [data-theme="light"] .modal-overlay .card,
    [data-theme="light"] [id^="modal"] .card,
    [data-theme="light"] .bottom-sheet-card {
      background: #ffffff !important;
      color: #0f172a !important;
      border: 1px solid #e2e8f0 !important;
      box-shadow: 0 20px 48px -6px rgba(15, 23, 42, 0.2) !important;
    }

    /* Category Dropdown in Light Theme */
    [data-theme="light"] .category-dropdown-menu {
      background: #ffffff !important;
      border: 1px solid #cbd5e1 !important;
      box-shadow: 0 12px 36px -4px rgba(15, 23, 42, 0.15) !important;
    }

    [data-theme="light"] .cat-dropdown-item {
      color: #0f172a !important;
    }

    [data-theme="light"] .cat-dropdown-item:hover {
      background: #f1f5f9 !important;
      color: #0f172a !important;
    }

    [data-theme="light"] .cat-group-header {
      color: #64748b !important;
      background: #f8fafc !important;
    }

    /* Mobile Bottom Nav in Light Theme */
    [data-theme="light"] .mobile-bottom-nav {
      background: rgba(255, 255, 255, 0.95) !important;
      border: 1px solid #e2e8f0 !important;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.08) !important;
    }

    [data-theme="light"] .mobile-nav-item {
      color: #64748b !important;
    }

    [data-theme="light"] .mobile-nav-item.active {
      color: #2563eb !important;
    }

    [data-theme="light"] .mobile-nav-item.active .icon {
      color: #2563eb !important;
    }

    /* Month Selector in Light Theme */
    [data-theme="light"] #globalMonthSelect,
    [data-theme="light"] .month-nav-select {
      background: #ffffff !important;
      color: #0f172a !important;
      border: 1px solid #cbd5e1 !important;
    }

    [data-theme="light"] #prevMonthBtn,
    [data-theme="light"] #nextMonthBtn {
      background: #ffffff !important;
      color: #0f172a !important;
      border: 1px solid #cbd5e1 !important;
    }

    [data-theme="light"] #prevMonthBtn:hover,
    [data-theme="light"] #nextMonthBtn:hover {
      background: #f1f5f9 !important;
    }

    /* Badges & Chips in Light Theme */
    [data-theme="light"] .badge {
      background: #f1f5f9 !important;
      color: #475569 !important;
      border: 1px solid #e2e8f0 !important;
    }

    [data-theme="light"] .revolut-chip {
      background: #f1f5f9 !important;
      border: 1px solid #e2e8f0 !important;
      color: #0f172a !important;
    }

    [data-theme="light"] .revolut-chip:hover {
      background: #e2e8f0 !important;
    }
"""

    assert '</style>' in content, "</style> not found"
    content = content.replace('</style>', light_theme_comprehensive_css + '\n  </style>', 1)

    # Bump service worker cache name to ffos-shell-v16
    content = content.replace("ffos-shell-v15", "ffos-shell-v16")
    content = content.replace("ffos-shell-v14", "ffos-shell-v16")

    with open('family_finances_os/web_server.py', 'w', encoding='utf-8', newline='') as f:
        f.write(content)

    print("Light theme completely overhauled and saved!")

if __name__ == '__main__':
    fix_light_theme()
