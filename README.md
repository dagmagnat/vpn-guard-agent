# VPN Guard Agent

**VPN Guard Agent** — это CLI-утилита для VPS/VDS с VPN или proxy-сервисами.  
Она помогает найти клиентов, из-за которых хостер может прислать abuse-жалобу: подозрительные TCP/UDP-соединения, много destination IP, обращения к blacklist-подсетям, высокий трафик.

Проект рассчитан на серверы с:

- Xray / 3x-ui / VLESS / VMess / Trojan
- WireGuard
- AmneziaWG, если доступна команда `wg show`
- OpenVPN
- Linux conntrack
- nftables или iptables

> Важно: по умолчанию проект **ничего автоматически не блокирует**. Он показывает таблицу риска и дает команды для ручного действия.

---

## Возможности

- Сканирование активных соединений через `conntrack`
- Парсинг Xray access log
- Проверка WireGuard peers через `wg show all dump`
- Парсинг OpenVPN status log
- Risk score для каждого клиентского IP
- Поиск клиентов, которые ходили в blacklist/abuse-подсети
- Блокировка и разблокировка IP через nftables или iptables
- JSON-отчет для хостера
- Интерактивное меню

---

## Быстрая установка

```bash
sudo apt update
sudo apt install -y git

git clone https://github.com/YOUR_USERNAME/vpn-guard-agent.git
cd vpn-guard-agent
sudo bash install.sh
```

Проверка:

```bash
vpn-guard scan
```

---

## Ручная установка для разработки

```bash
sudo apt install -y python3 python3-venv python3-pip conntrack nftables wireguard-tools

git clone https://github.com/YOUR_USERNAME/vpn-guard-agent.git
cd vpn-guard-agent
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

vpn-guard scan --config ./config.example.yml
```

---

## Настройка

После установки конфиг находится здесь:

```bash
/etc/vpn-guard/config.yml
```

Пример:

```yaml
paths:
  xray_access_log: /var/log/xray/access.log
  openvpn_status_log: /etc/openvpn/openvpn-status.log
  db_path: /var/lib/vpn-guard/vpn-guard.sqlite3

firewall:
  backend: nftables
  nft_table: vpn_guard
  nft_set: blocked_ips

thresholds:
  tcp_connections_high: 300
  udp_connections_high: 500
  unique_destinations_high: 200
  upload_mb_per_hour_high: 1000
  blacklist_hits_high: 1

actions:
  auto_block: false
  auto_block_score: 100
  temporary_ban_hours: 24

blocklists:
  - 178.162.203.0/24
  - 45.159.79.0/24
  - 85.17.155.0/24
```

---

## Включение логов Xray / 3x-ui

Чтобы VPN Guard мог понять, какой клиент Xray ходил к подозрительному destination, включите access log.

В Xray config должно быть примерно так:

```json
"log": {
  "access": "/var/log/xray/access.log",
  "error": "/var/log/xray/error.log",
  "loglevel": "warning"
}
```

После изменения перезапустите Xray или 3x-ui.

```bash
systemctl restart xray
```

или через панель 3x-ui.

---

## Основные команды

### Показать всех активных клиентов

```bash
vpn-guard scan
```

Пример вывода:

```text
┌──────────┬───────┬───────────────┬────────────┬─────┬─────┬──────┬────────┬────────┬──────────────────────┐
│ Risk     │ Score │ Client IP     │ Source     │ TCP │ UDP │ Dest │ RX     │ TX     │ Reason               │
├──────────┼───────┼───────────────┼────────────┼─────┼─────┼──────┼────────┼────────┼──────────────────────┤
│ HIGH     │ 95    │ 1.2.3.4       │ xray       │ 401 │ 0   │ 260  │ 0.0 B  │ 0.0 B  │ high TCP connections │
│ LOW      │ 0     │ 5.6.7.8       │ wireguard  │ 0   │ 0   │ 0    │ 2.1 GB │ 400 MB │ -                    │
└──────────┴───────┴───────────────┴────────────┴─────┴─────┴──────┴────────┴────────┴──────────────────────┘
```

### Показать только подозрительных

```bash
vpn-guard top
```

или:

```bash
vpn-guard scan --suspicious
```

### Проверить обращения к abuse/blocklist подсетям

```bash
vpn-guard abuse-check
```

Это полезно, если хостер прислал список подсетей, куда шел вредоносный трафик.

### Инициализировать firewall

Для nftables:

```bash
sudo vpn-guard init-firewall
```

### Заблокировать IP

```bash
sudo vpn-guard block 1.2.3.4
```

### Разблокировать IP

```bash
sudo vpn-guard unblock 1.2.3.4
```

### Интерактивное меню

```bash
sudo vpn-guard menu
```

### Сделать отчет для хостера

```bash
vpn-guard report --output abuse-report.json
```

---

## Как считается риск

Примерная логика:

| Событие | Баллы |
|---|---:|
| Очень много TCP-соединений | +30 |
| Очень много UDP-соединений | +25 |
| Много разных destination IP | +25 |
| Обращение к blacklist-подсети | +70 |
| Высокий upload | +20 |

Уровни:

| Score | Risk |
|---:|---|
| 0–39 | LOW |
| 40–69 | MEDIUM |
| 70–99 | HIGH |
| 100+ | CRITICAL |

---

## Типичный сценарий после письма от хостера

1. Добавьте подсети из письма в `/etc/vpn-guard/config.yml` в блок `blocklists`.
2. Запустите:

```bash
sudo vpn-guard abuse-check
```

3. Посмотрите, какой клиентский IP ходил к этим подсетям.
4. Заблокируйте клиента:

```bash
sudo vpn-guard block CLIENT_IP
```

5. Сделайте отчет:

```bash
vpn-guard report --output abuse-report.json
```

---

## Для 3x-ui / Xray

Если у вас много клиентов в одном inbound, желательно:

- включить access log;
- использовать отдельные UUID для каждого клиента;
- не раздавать один и тот же UUID всем;
- периодически проверять `vpn-guard top`;
- при abuse сначала отключать UUID клиента в 3x-ui, потом уже банить IP, если нужно.

---

## Для WireGuard / AmneziaWG

Команда:

```bash
wg show all dump
```

должна возвращать список peer-ов.  
Если команда не работает, установите:

```bash
sudo apt install wireguard-tools
```

---

## Для OpenVPN

Укажите правильный путь к status-файлу:

```yaml
paths:
  openvpn_status_log: /etc/openvpn/openvpn-status.log
```

В конфиге OpenVPN должна быть строка:

```conf
status /etc/openvpn/openvpn-status.log
```

---

## Systemd

В проекте есть пример сервиса:

```bash
sudo cp vpn-guard.service /etc/systemd/system/vpn-guard.service
sudo systemctl daemon-reload
sudo systemctl enable vpn-guard
sudo systemctl start vpn-guard
```

Пока сервис запускает `vpn-guard top`. Для постоянного мониторинга в будущих версиях будет добавлен режим `watch`.

---

## Roadmap

План на следующие версии:

- режим `watch` с периодической проверкой;
- временные баны: `--time 24h`;
- rate-limit через `tc`;
- Web UI с графиками;
- Telegram-уведомления;
- интеграция с 3x-ui API;
- отдельная статистика по UUID Xray;
- автоэкспорт отчета для хостера;
- Docker-образ.

---

## Безопасность

Этот проект предназначен для защиты собственного сервера и расследования abuse-инцидентов.  
Не используйте его для скрытого мониторинга чужих систем или перехвата содержимого трафика. Утилита анализирует метаданные соединений: IP, протоколы, счетчики, destination и системные логи VPN.

---

## Лицензия

MIT
