with open('family_finances_os/web_server.py', encoding='utf-8') as f:
    text = f.read()

import re
matches = re.findall(r'(\[data-theme=["\']light["\']\][^{]+)\{([^}]+)\}', text)
for sel, b in matches:
    print(sel.strip())
    for line in b.strip().splitlines()[:6]:
        print('  ', line.strip())
