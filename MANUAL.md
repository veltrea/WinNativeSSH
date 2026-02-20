# WinNative-SSH マニュアル

## 1. 概要

WinNative-SSH は、Windows での運用を意識して作った SSH サーバーです。  
サービス運用・監査・鍵管理・API 管理を一体化しているのが特徴です。

## 2. コンポーネント

- `sshd`: SSH サーバー本体（Windows Service 対応）
- `worker`: セッション処理ワーカー
- `vlt-admin`: 管理 CLI
- `vlt_admin_api`: 管理 API（`127.0.0.1:9443`）

## 3. よく使う CLI

### ユーザー管理

```powershell
vlt-admin add-user <name> <password>
vlt-admin disable-user <name>
vlt-admin enable-user <name>
vlt-admin delete-user <name>
```

### 鍵管理

```powershell
vlt-admin add-key <name> "<pubkey>" --expires-at 2026-12-31T23:59:59+09:00 --constraints-json "{\"comment\":\"dev\",\"use_case\":\"remote-debug\",\"tags\":[\"beta\"]}"
vlt-admin list-keys <name> --limit 50 --offset 0
vlt-admin disable-key <key_id>
vlt-admin rotate-key <key_id> "<new_pubkey>"
vlt-admin list-key-alerts --days 30
```

### 監査・セッション・ポリシー

```powershell
vlt-admin list-audit --limit 100 --offset 0
vlt-admin list-sessions --limit 100 --offset 0
vlt-admin list-policies --limit 100 --offset 0
vlt-admin set-policy <scope> <scope_id|-> <priority> "<policy_json>"
```

## 4. 管理 API

- Health: `GET /health`
- UI: `GET /ui`
- Users: `GET /users`
- Keys: `GET /keys?user=<name>`
- Sessions: `GET /sessions`
- Audit: `GET /audit`
- Policies: `GET /policies`
- Key alerts: `GET /key-alerts`
- ACL: `GET /acl?path=<path>&mode=simple|detailed`

`/health` と `/ui` 以外は `Authorization: Bearer <WNSSH_ADMIN_TOKEN>` が必要です。

## 5. ログ/監査

- SQLite: `winnative.db` の `audit_events`, `sessions` テーブル
- Windows Event Log: provider `WinNativeSSH`
- JSONL エクスポート:

```powershell
pwsh ./scripts/Export-AuditJsonl.ps1
```

## 6. トラブルシュート

- サービス状態:

```powershell
Get-Service WinNativeSSH
```

- API ヘルス:

```powershell
curl http://127.0.0.1:9443/health
```

- イベント確認:

```powershell
Get-WinEvent -LogName Application | ? ProviderName -eq "WinNativeSSH" | select -First 20
```

## 7. コマンド互換モード（Windows実運用向け）

Windows 環境では、サービス実行コンテキスト差分により一部標準コマンドが失敗することがあります  
（例: `0xC0000142` / DLL 初期化失敗）。

このため、WinNative-SSH は「必要コマンドを worker 内部で処理する」方針を段階導入できます。

- 方針:
  - 失敗頻度の高いコマンドを allow-list で内蔵化
  - 互換範囲は運用で必要なサブセットに限定
  - 未対応オプションは明示エラーで返す（沈黙しない）
- 想定対象（初期）:
  - `whoami`
  - `whoami /user`
  - `where`
  - `tasklist`（最小フィルタ）

注意:
- Windows 標準コマンドと完全互換は保証しません。
- 非互換は仕様として明示し、監査ログで `intercepted_command` を追跡可能にします。

設計詳細は以下を参照:
- `docs/COMMAND_INTERCEPTION_STRATEGY_2026-02-15.md`
