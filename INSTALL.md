# WinNative-SSH インストールマニュアル

## 前提

- Windows 11 / Windows Server
- Rust toolchain（ソースからビルドする場合）
- 管理者権限の PowerShell

## 1. ソースからビルド

```powershell
cargo build --release
```

生成バイナリ:

- `target/release/vlt-sshd.exe`
- `target/release/vlt-worker.exe`
- `target/release/vlt_admin.exe`
- `target/release/vlt_admin_api.exe`

## 2. サービスとしてインストール

### 推奨（ラッパー）

```powershell
pwsh ./scripts/Install-WinNativeSSH.ps1 -Port 2222
```

### 手動（分割）

```powershell
pwsh ./scripts/Install-WinNativeSSHService.ps1 -BinaryPath .\target\release\vlt-sshd.exe -Port 2222
pwsh ./scripts/Start-WinNativeSSHService.ps1
```

## 3. 管理 API を起動

```powershell
$env:WNSSH_ADMIN_TOKEN = "change-this-token"
.\target\release\vlt_admin_api.exe
```

確認:

```powershell
curl http://127.0.0.1:9443/health
```

UI:

- [http://127.0.0.1:9443/ui](http://127.0.0.1:9443/ui)

## 4. 初期セットアップ例

```powershell
.\target\release\vlt_admin.exe add-user veltrea "YourPassword"
.\target\release\vlt_admin.exe add-key veltrea "ssh-ed25519 AAAA... comment"
```

## 5. アップグレード

```powershell
cargo build --release
pwsh ./scripts/Upgrade-WinNativeSSH.ps1
```

## 6. バックアップ/復元

バックアップ:

```powershell
pwsh ./scripts/Backup-WinNativeSSH.ps1
```

復元:

```powershell
pwsh ./scripts/Restore-WinNativeSSH.ps1 -ArchivePath .\backups\winnative-backup-<timestamp>.zip
```

## 7. アンインストール

```powershell
pwsh ./scripts/Stop-WinNativeSSHService.ps1
pwsh ./scripts/Uninstall-WinNativeSSHService.ps1
```
