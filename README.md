# AikenVPN

VPN-клиент для Windows с встроенными протоколами.  
**Не требует установки** — скачайте и запустите единственный `.exe` файл.

## ⬇️ Скачать

➡️ **[Releases → AikenVPN.exe](../../releases/latest)**

## Поддерживаемые протоколы

| Протокол | Реализация | Зависимости |
|---|---|---|
| WireGuard | wireguard-go + wintun | нет (встроено) |
| VMess / VLESS / Trojan / Shadowsocks | xray-core | нет (встроено) |
| OpenVPN | openvpn.exe | встроен при сборке с `-WithOpenVPN`, иначе нужен системный OpenVPN |
| L2TP / IKEv2 / SSTP / PPTP | Windows RAS API | Windows built-in |

## Требования

- Windows 10 / 11 x64
- Права администратора (WireGuard создаёт сетевой адаптер)

---

## Сборка из исходников

### Зависимости

```powershell
winget install GoLang.Go          # Go 1.26+
winget install OpenJS.NodeJS.LTS  # Node 18+ (frontend)
go install github.com/wailsapp/wails/v2/cmd/wails@latest
```

### Без OpenVPN (~45 МБ)

```powershell
git clone https://github.com/AikenIzumi/AlphazetVPN.git
cd AlphazetVPN
wails build -clean -platform windows/amd64
# → build\bin\AikenVPN.exe
```

### С встроенным OpenVPN (~55 МБ, полностью автономный)

```powershell
# Скачать GPL-бинарники OpenVPN (не хранятся в репозитории)
.\scripts\download-openvpn.ps1

# Сборка
.\build.ps1 -WithOpenVPN
```

## Структура

```
internal/vpn/
├── xray.go              # VMess/VLESS/Trojan/SS — xray-core in-process
├── wireguard_windows.go # WireGuard — wireguard-go + wintun
├── ras_windows.go       # L2TP/IKEv2/SSTP/PPTP — rasapi32.dll напрямую
├── openvpn.go           # OpenVPN — встроенный exe
├── proxy_windows.go     # системный прокси Windows (WinInet)
└── assets/
    └── wintun.dll       # MIT, встроена в бинарник
scripts/
└── download-openvpn.ps1 # загрузка OpenVPN для полной сборки
```

## Лицензия

MIT

Встроенные компоненты:
- [wireguard-go](https://github.com/WireGuard/wireguard-go) — MIT
- [wintun](https://www.wintun.net/) — MIT
- [xray-core](https://github.com/XTLS/Xray-core) — MPL-2.0
- OpenVPN — GPL-2.0 *(бинарники загружаются при сборке, не хранятся в репо)*
