with open('family_finances_os/web_server.py', encoding='utf-8') as f:
    text = f.read()

import re
light_vars = re.search(r'\[data-theme=["\']light["\']\]\s*\{([^}]+)\}', text).group(1)
print('Is --bg-gradient in [data-theme=light]?', '--bg-gradient' in light_vars)
if '--bg-gradient' not in light_vars:
    print('CRITICAL BUG FOUND: --bg-gradient is missing in light theme, so body inherits dark gradient with dark text!')
