import re
path = '.agents/skills/exploit-backend/SKILL.md'
with open(path, 'r', encoding='utf-8') as f:
    lines = f.readlines()
new_lines = []
for line in lines:
    m = re.match(r'^(\d+)\.\s', line)
    if m and int(m.group(1)) >= 6:
        n = int(m.group(1)) - 1
        line = f'{n}. {line[m.end():]}'
    new_lines.append(line)
with open(path, 'w', encoding='utf-8') as f:
    f.writelines(new_lines)
print('Renumbered exploit-backend steps 6-48 to 5-47')
