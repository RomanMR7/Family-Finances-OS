import re
from pathlib import Path

def audit():
    file_path = Path("family_finances_os/web_server.py")
    text = file_path.read_text(encoding="utf-8")
    
    # 1. Collect all JS functions
    functions = re.findall(r'function\s+([a-zA-Z0-9_]+)\s*\(', text)
    async_functions = re.findall(r'async\s+function\s+([a-zA-Z0-9_]+)\s*\(', text)
    all_funcs = sorted(set(functions + async_functions))
    
    # 2. Collect all element IDs referenced in JS via getElementById
    js_ids = re.findall(r'document\.getElementById\([\'"]([^\'"]+)[\'"]\)', text)
    unique_js_ids = sorted(set(js_ids))
    
    # 3. Collect all DOM element IDs in HTML
    html_ids = re.findall(r'\bid=[\'"]([^\'"]+)[\'"]', text)
    unique_html_ids = sorted(set(html_ids))
    
    # Check if any JS ID is missing in HTML
    missing_ids = [i for i in unique_js_ids if i not in unique_html_ids]
    
    print(f"Total JS functions: {len(all_funcs)}")
    print(f"Total HTML IDs: {len(unique_html_ids)}")
    print(f"Total JS IDs accessed: {len(unique_js_ids)}")
    print(f"Missing IDs: {missing_ids}")
    
    # Key functional anchors that MUST NEVER be removed or broken:
    must_have_funcs = [
        "loadDashboard", "loadTransactions", "loadDebts", "loadObligations",
        "loadGoals", "loadEnvelopes", "loadAnalytics",
        "openNewTxModal", "submitQuickInput", "submitTransaction",
        "openNewDebtModal", "submitNewDebt", "openPayDebtModal", "submitPayDebt",
        "openNewGoalModal", "submitSaveGoal", "openContributeGoalModal",
        "openNewEnvelopeModal", "submitSaveEnvelope", "openEnvelopeTransferModal",
        "toggleCategoryDropdown", "filterCategoryDropdown", "onSelectCategory",
        "switchTab", "onGlobalMonthSelectChange", "shiftSelectedMonth"
    ]
    
    print("\nChecking core must-have functions:")
    all_ok = True
    for fn in must_have_funcs:
        present = fn in all_funcs
        if not present:
            all_ok = False
        print(f"  [{'OK' if present else 'FAIL'}] {fn}")

    if len(all_funcs) < 161 or len(unique_html_ids) < 330 or missing_ids or not all_ok:
        print("\n[FAILED] Invariant violation detected!")
        import sys
        sys.exit(1)
    else:
        print("\n[PASSED] All 161 JS functions, 330 DOM IDs, and core anchors are 100% intact!")

if __name__ == "__main__":
    audit()
