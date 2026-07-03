# Extensions

Директория для **внешних агент-проектов**, расширяющих White Rabbit специфическими
whitebox-задачами. Содержимое (кроме этого файла) **не попадает в git**.

## Как подключить расширение

```bash
ln -s /path/to/example-scanner extensions/example-scanner
```

Имя симлинка = имя расширения: `/wr example-scanner …`. Discovery автоматический —
`/wr` (status) покажет всё, что прилинковано.

## Манифест (опционально)

Расширение может описать себя файлом `wr-extension.md` в своём корне:

```markdown
---
name: example-scanner
description: Go security scanner — malware/webshell detection in web apps
commands: example-scanner
---
## Когда предлагать
…
## Как запускать (read-only)
…
```

Если манифеста нет, White Rabbit прочитает `CLAUDE.md`, затем `README.md`
проекта и разберётся сам. Приоритет: `wr-extension.md` → `CLAUDE.md` → `README.md`.

## Guard и доверие

Расширения работают под тем же read-only guard'ом. Бинарь расширения **не разрешается
автоматически** — поле `commands:` манифеста лишь декларация. Чтобы разрешить команду,
добавь её имя строкой в `policy/allowed-commands.local.txt` (gitignored, ведёшь его ты;
denylist и запрет редиректов действуют в любом случае).

Discovery-скрипт: `scripts/extensions/list.sh` (TSV: `name / path / manifest / description`).
