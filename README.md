# JamVPN — Go Edition

Полноценный VPN-клиент на Go + Wails v2 с современным UI.

## Возможности

| Функция | Описание |
|---|---|
| **Протоколы** | WireGuard, OpenVPN, L2TP/IPSec, IKEv2, SSTP, PPTP |
| **Импорт** | URL-ссылка, JSON, текст (.conf/.ovpn/URI), файл, QR-код |
| **Экспорт** | JSON, WireGuard .conf, QR-код, shareable-ссылка `jamvpn://` |
| **Миграция** | Автоматический импорт профилей из старого Python-приложения |
| **UI** | Dark theme, glassmorphism, CSS-анимации, плавные переходы |

## Требования

### Инструменты разработки
```bash
# Go 1.21+
https://go.dev/dl/

# Wails v2
go install github.com/wailsapp/wails/v2/cmd/wails@latest

# Node.js 18+ (для сборки фронтенда)
https://nodejs.org/
```

### Системные зависимости (Windows)
- **WireGuard** (для WireGuard-профилей): https://www.wireguard.com/install/
- **OpenVPN** (для OpenVPN-профилей): https://openvpn.net/community-downloads/
- L2TP/IKEv2/SSTP/PPTP — встроены в Windows, дополнительная установка не нужна

## Сборка

```bash
cd jamvpn-go

# Установить зависимости
go mod tidy

# Запустить в режиме разработки
wails dev

# Собрать production .exe
wails build

# Итоговый файл: build/bin/JamVPN.exe
```

## Структура проекта

```
jamvpn-go/
├── main.go                     # Точка входа Wails
├── app.go                      # API, экспонируемый фронтенду
├── go.mod
├── wails.json
│
├── internal/
│   ├── config/
│   │   ├── profile.go          # Модели данных (Profile, ConnectionStatus)
│   │   └── store.go            # Хранилище профилей в JSON
│   │
│   ├── vpn/
│   │   ├── manager.go          # Менеджер VPN-соединений
│   │   ├── ras_windows.go      # L2TP/IKEv2/SSTP/PPTP через PowerShell RAS
│   │   ├── wireguard_windows.go# WireGuard через wireguard.exe
│   │   └── openvpn.go          # OpenVPN subprocess
│   │
│   ├── parser/
│   │   ├── parser.go           # Универсальный парсер (URL, bytes, base64)
│   │   ├── wireguard.go        # WireGuard .conf формат
│   │   ├── openvpn.go          # OpenVPN .ovpn формат
│   │   └── uri.go              # URI-схемы (wireguard://, vmess://, ss://, ...)
│   │
│   └── qr/
│       └── qr.go               # Генерация QR, парсинг из текста
│
└── frontend/
    ├── index.html              # Single-page UI (Vanilla JS + CSS)
    └── wailsjs/                # Wails runtime + Go bindings
```

## Поддерживаемые форматы импорта

| Формат | Пример |
|---|---|
| WireGuard .conf | `[Interface]\nPrivateKey = ...` |
| OpenVPN .ovpn | `client\nremote vpn.example.com 1194` |
| JSON (профиль) | `{"name":"...", "tunnel_type":"L2TP", ...}` |
| JSON (список) | `{"version":2, "profiles":[...]}` |
| WireGuard URI | `wireguard://privatekey@host:port?publickey=...` |
| VMess URI | `vmess://BASE64` |
| VLESS URI | `vless://uuid@host:port?...#name` |
| Trojan URI | `trojan://password@host:port#name` |
| Shadowsocks URI | `ss://method:pass@host:port#name` |
| Старый формат | `vpn_profiles.json` от Python-версии |

## Данные приложения

Профили хранятся в: `%APPDATA%\JamVPN\profiles.json`
