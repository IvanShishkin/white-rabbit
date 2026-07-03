# White Rabbit — бэклог доработок

Источник: гэп-анализ против топовых white-box инструментов (Lynis, CIS Benchmarks,
Wazuh SCA, osquery) + Definition of Done MVP из `docs/design.md` (02.07.2026).

Сознательно НЕ берём полный CIS-стиль (сотни контролей про umask/mount-опции) —
это генератор шума; дифференциатор White Rabbit — корреляции и AI-триаж.

## Приоритет 1 — persistence pack (расширение server_snapshot) `[done]`

Закрывает «кто имеет доступ» и «есть ли персистентность» — вопросы, которые боевой
прогон 01.07 поднял, а инструмент ответить не смог. Коллектор v3, seam `WR_ROOT`
для тестируемости без живого хоста; hash'и shadow и key-блобы никогда не печатаются.

- [x] `users_auth`: дубликаты UID 0, пустые пароли в shadow, аккаунты с login-шеллом
- [x] `sudoers`: NOPASSWD/ALL-правила, члены групп sudo/admin/wheel/docker/root
- [x] `authorized_keys`: инвентарь по всем пользователям + count + mtime (свежий ключ = флаг)
- [x] `scheduled`: crontab/cron.d/спул + systemd-timers (персистентность №1)
- [x] `persistence_signals`: ld.so.preload, процессы с удалённым бинарником,
      rc.local, SUID вне стандартных путей
- [x] `patching`: pending security updates, reboot-required, EOL-дистрибутив
- [x] `sysctl_hardening`: 11 ключей (ASLR, ptrace_scope, rp_filter, syncookies…)
- [x] `docker`: published-порты (реальная поверхность!), privileged/host-network,
      знание «Docker обходит ufw» закреплено в `knowledge/checks/docker.md`
- [x] каталоги проверок `knowledge/checks/{access,persistence,patching,sysctl,docker}.md`
- [x] обновить `skills/wr-server-audit/SKILL.md` (+ кросс-корреляции)
- [x] тесты: 6 новых поведенческих + read-only guard на новые команды (fixture-tree)

## Приоритет 2 — оркестратор + дельта + кросс-корреляция (DoD 4) `[done]`

- [x] `/wr all [user@host]`: все три коллектора за один прогон (скилл `wr-orchestrate`)
- [x] кросс-корреляция web↔ssh: read-only скрипт `scripts/analyze/correlate.sh` —
      детерминированное пересечение множеств IP; accepted-SSH + web = critical,
      SSH-брутфорс + web-скан/login-bf/sensitive = high. Каталог `checks/correlation.md`.
      Скрипт точечно добавлен в allowlist (не `bash` целиком).
- [x] дельта против прошлого прогона — на уровне скилла: читает предыдущий
      `reports/full-<host>-*.md`, помечает находки [NEW]/[UNCHANGED]/[RESOLVED]
- [x] единый отчёт со сквозным severity-скорингом (одна отсортированная лента находок)
- [x] тесты: 8 поведенческих на коррелятор + read-only guard + knowledge-каталог
- [ ] (позже) вынести дельту/скоринг в отдельный движок, если понадобится строгость

## Приоритет 3 — точечные фиксы детекции `[done]`

- [x] `web_pull.sh`: секция `path_payloads` — `PAYLOAD_RE` (traversal/SQLi/XSS/Log4Shell/LFI)
      по пути запроса, `<count> <ip> <status> <path>` (2xx = возможный успешный эксплойт).
      Каталог `web-log.md` обновлён (`web-path-payload`), роль `payload` добавлена в коррелятор.
- [x] `log_pull.sh`: fallback без `dig` (seam `WR_NO_DIG`) — нота + PTR-колонка `-`, без
      спавна падающих dig
- [x] (бонус) фикс merge-interaction бага: коррелятор читал IP из `accepted_logins` по
      старому полю 2, а PR #2 сменил формат на `<count> <user> <ip> <method>` (IP = поле 3) —
      ключевая foothold-корреляция была сломана на master; исправлено + фикстура обновлена

## Находки боевого прогона (боевой Ubuntu-хост, 02.07) — тул-фиксы

Первый полный прогон `/wr all` на живом Ubuntu-хосте (mawk). DoD 6 фактически выполнен —
инструмент дал осмысленный приоритизированный результат и сам себя провалидировал.

- [x] **CRITICAL:** `\.` в awk-регэкспах → mawk трактует как «любой символ», `../` матчил
      почти любой URL. `path_payloads`/`referer-payload` в ложняках, коррелятор фабриковал
      critical на IP оператора. Фикс `[.]` + регрессионные тесты. (фикстуры на gawk не ловили)
- [x] `source: none` при 1.3M запросов — потеря `SOURCE_DESC` в subshell, фикс через маркер `WR-SRC:`
- [x] **web_pull.sh масштабируемость:** потоковый cap `WR_WEB_MAX_LINES` (дефолт 200k) применён
      ко ВСЕМ источникам (был только у `docker logs`); источники эмитятся oldest-first, `tail`
      держит в памяти только N свежих строк — конец безлимитному RAW/TSV, который рвал SSH (exit 255).
      Честная `WR-NOTE` о срезе в `meta`. + ssh keepalive (`ServerAliveInterval/CountMax`) в
      скиллах `wr-web-hunt`/`wr-orchestrate`. Тест на cap+note.
- [x] `patching`: классификация по POCKET (case-insensitive, скоуп до поля перед пробелом — ловит
      `focal-security`/`Debian-Security`, не путает пакет с именем *security*) + fallback
      `apt-get -s upgrade` (read-only simulate), который вытягивает archive-origin, когда Ubuntu
      шлёт security через `-updates` pocket (та самая причина «192 upgradable, 0 security»). 2 теста.
- [x] `persistence_signals`: kernel-threads больше не дают ложный «scan incomplete». Пустой
      `/proc/PID/exe` дизамбигуируется через world-readable `/proc/PID/cmdline`: пусто = kthread
      (ожидаемо, не blind), непусто = реальный процесс с непрозрачным exe (настоящий blind spot).
      Работает независимо от привилегий. 2 теста (kthread quiet / opaque userspace blind).

## Фаза 3, слайс 1 — CVE-проверка пакетов ОС `[done]`

Сознательно БЕЗ app-зависимостей (package-lock/go.mod — Фаза 2) и без reachability.
Источник: OSV.dev batch API (zero-install на обеих сторонах, Ubuntu/Debian/RHEL-семейство
одним API); EPSS — FIRST.org, KEV — CISA. Сеть только с auditor-машины; наружу уходят
имена/версии пакетов и CVE-id (публичные, низкочувствительные) — posture-note в каталоге.

- [x] коллектор: секция `packages` в server_snapshot v4 — dpkg-query (4 колонки,
      source-пакет!) + rpm-fallback, read-only
- [x] анализатор `scripts/analyze/cve_scan.sh`: OSV-матчинг по source-пакетам,
      приоритизация KEV → EPSS → OSV-severity, только actionable (есть fixed-версия),
      VEX-подавление (`targets/vex.txt`), деградация каждого источника в WR-NOTE
- [x] guard: канонический путь `WR_CVE_SCANNER` (не basename), тест «подставной файл — deny»
- [x] каталог `knowledge/checks/cve.md`, скилл `wr-cve`, роут `/wr cve`,
      секция в оркестраторе `/wr all`
- [x] тесты: 19 на анализатор (фикстуры OSV/EPSS/KEV, без сети) + 4 на коллектор
- [ ] (позже) прогон на живом хосте + тюнинг ecosystem-маппинга по его результатам

## Приоритет 4 — обогащение и доставка (DoD 5–6)

- [ ] threat-intel обогащение топ-IP (AbuseIPDB free tier) — «817 фейлов с IP»
      против «817 фейлов с известного ботнета»
- [ ] TLS: истечение сертификатов, протоколы/шифры, security-заголовки (дизайн 5.3)
- [ ] доставка отчёта в Slack (переиспользовать существующий MCP-паттерн рассылки)
- [ ] еженедельный прогон по расписанию + финальный прогон на боевой VM (DoD 6)

## Сделано

- [x] фундамент: гвардрейлсы policy/ + enforced read-only хук (guard.sh)
- [x] `/wr server` — SSH-конфиг, порты, фаервол (боевой прогон 01.07)
- [x] `/wr logs` — SSH/auth-логи, брутфорс, корреляция success×attacker (боевой прогон 01.07)
- [x] `/wr web` — HTTP access-логи nginx/Caddy, sensitive-2xx корреляция
- [x] persistence pack — accounts/sudo/keys/cron/rootkit/patch/sysctl/docker (PR #4)
- [x] `/wr all` — оркестратор: три коллектора + кросс-корреляция web↔ssh + дельта + единый отчёт
