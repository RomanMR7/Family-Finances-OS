import re

def audit_light_theme():
    text = open('family_finances_os/web_server.py', 'r', encoding='utf-8').read()
    
    # 1. Check data-theme="light" block in CSS
    match = re.search(r'\[data-theme=["\']light["\']\]\s*\{([^}]+)\}', text)
    if match:
        print("=== [data-theme='light'] Root Variables ===")
        print(match.group(1).strip())
    else:
        print("NO [data-theme='light'] root block found!")

    # 2. Find hardcoded inline white colors: color: #fff, color: #ffffff, color: white
    inline_white = re.findall(r'style=["\'][^"\']*(?:color:\s*(?:#fff|#ffffff|white))[^"\']*["\']', text, re.IGNORECASE)
    print(f"\nTotal elements with hardcoded inline white text: {len(inline_white)}")
    for iw in inline_white[:15]:
        print("  ->", iw[:100])

    # 3. Find hardcoded backgrounds: background: #0c0d12, #141720, rgba(255,255,255,...)
    print("\nChecking CSS rules for light theme:")
    light_blocks = re.findall(r'(\[data-theme=["\']light["\']\][^{]*\{[^}]+\})', text)
    print(f"Total [data-theme='light'] specific CSS rules: {len(light_blocks)}")
    for lb in light_blocks[:10]:
        print("  *", lb.split('{')[0].strip())

if __name__ == '__main__':
    audit_light_theme()
