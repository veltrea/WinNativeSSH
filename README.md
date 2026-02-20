# WinNative-SSH (Beta)

Windows 向けに作った、Rust 製の SSH サーバー実装です。  
「Windows で SSH を運用しやすくする」ことを目的に、以下を中心に実装しています。

- SSH サーバー本体 (`vlt-sshd`)
- 管理 CLI (`vlt-admin`)
- 管理 API + 簡易 UI (`vlt_admin_api`, `/ui`)
- 監査ログ（SQLite）
- SFTP（VSS / `.snapshots` 対応）

このリポジトリは **ベータリリース** です。  
実運用に使う場合は、必ず検証環境で動作確認してからご利用ください。

## クイックスタート

1. ビルド

```powershell
cargo build --release
```

2. インストール（サービス登録）

```powershell
pwsh ./scripts/Install-WinNativeSSH.ps1
```

3. 管理 API 起動（別ターミナル）

```powershell
$env:WNSSH_ADMIN_TOKEN = "change-me"
.\target\release\vlt_admin_api.exe
```

4. 管理 UI へアクセス

- [http://127.0.0.1:9443/ui](http://127.0.0.1:9443/ui)

## システム構成

- **`vlt-sshd`**: SSH サーバー本体。Windows Service として動作 (`LocalSystem`)。
- **`vlt-worker`**: ユーザーセッションでコマンドを実行するためのエージェント。`CreateProcessAsUserW` で起動され、名前付きパイプで通信。
- **`vlt-admin`**: 管理用 CLI ツール.
- **`vlt_admin_api`**: 管理用 REST API サーバー + 簡易 UI。

## Why WinNativeSSH? - The "Escaping Hell" & "ACL Trap"

私たちは、Windows における SSH 利用の最大の障壁は、以下の2つの「見えない罠」にあると考えています。

1. **The "Escaping Hell" (シェルクォート地獄)**
    - **Human Cost**: 緊急時のシステム復旧で、オペレータが「コマンドパスの空白」や「PowerShellのエスケープ」に悩み、対応が遅れる事態が頻発しています。
    - **AI Cost**: AIエージェントにとっても、Windows特有の複雑なエスケープ規則は「Token Tax（無駄な推論コスト）」となり、実行エラーと再試行のループを引き起こします。これが世界規模での計算資源の浪費に繋がっています。

2. **The "ACL Permission Trap" (権限設定の罠)**
    - **Silent Failure**: Windows版 OpenSSH は、鍵ファイルや `authorized_keys` の ACL（アクセス権）が "Too Open" だと、警告なく認証を拒否します。
    - **AI Barrier**: この「何も言わずに失敗する」挙動は、AIエージェントにとってデバッグの悪夢です。セットアップに膨大な時間を要し、環境変化（権限継承の復活など）で突然繋がらなくなる原因を特定できません。

WinNativeSSH は、単なるSSHサーバーではなく、**「引数安全な実行モード (Argument-Safe Execution)」** と **「明確な診断・管理機構」** を実装することで、人間とAIの双方にとって「直感通りに動き、失敗理由がわかる」インフラを提供することを目指しています。
詳細は以下のドキュメントを参照してください。
- [Problem Analysis: Shell Quoting & Escaping](docs/technical/PROBLEM_ANALYSIS_SHELL_QUOTING_AND_ESCAPING.md)

### Milestone 0: The "ACL Permission Trap"
Before we even get to running commands (M4), verify that we can **connect** securely.
Windows OpenSSH has a "Permission Trap" where `authorized_keys` are silently ignored if ACLs are "too open" (inherited permissions) or if the user is an Administrator (Split Split Configuration).
-   **Problem**: Silent failure ("Permission denied") with no clear cause.
-   **Solution**: WinNativeSSH treats this as **Milestone 0 (Foundation)**. We provide built-in diagnostics and automated repair (`vlt-admin fix-permissions`) to ensure the foundation is solid before layering features on top.
-   [Detailed Analysis](docs/technical/PROBLEM_ANALYSIS_ACL_PERMISSION_TRAP.md)


## 実装済み機能 (Implemented Features)

### 1. コア / 認証
- **Windows Service 対応**: SCM (Service Control Manager) 完全対応。
- **認証**: 
    - Password (Local Windows Accounts)
    - Public Key (`authorized_keys` / DB管理)
- **セッション記録**: 接続開始・終了、ユーザー、クライアントIP等を SQLite に記録。

### 2. コマンド実行 / Worker (Windows Native)
- **Session-Correct Spawn**: 接続ユーザーのセッション (Session 1+) でプロセスを起動。
    - `WTSQueryUserToken` + SID check により、誤ったセッションでの実行を防止。
- **Headless Recovery Shims**: ユーザーログオンが無い (Session 0) 状態でも動作する内蔵管理者コマンド。
    - `sysinfo`, `netinfo` (IP/DNS), `fs stat`, `svc` (Service Control), `eventlog tail`
    - 外部プロセス (`cmd`, `powershell`) が `0xC0000142` で死ぬ環境下での救済措置。
- **Internal Commands**: `whoami`, `tasklist`, `wsl-status` 等の軽量実装。

### 3. ネットワーク / ポリシー
- **Port Forwarding**: 
    - Local (`-L`), Remote (`-R`), Dynamic (`-D`)
    - DBポリシーによる許可/拒否制御。
- **監査**: 転送イベントのログ記録。

### 4. 管理プレーン (CLI / API)
- **ユーザー/鍵管理**: 追加、無効化、有効期限 (`expires_at`) 設定。
- **API**: `/health`, `/metrics`, `/audit`, `/policies` 等の管理エンドポイント。
- **監査ログ**: JSONL エクスポート (`scripts/Export-AuditJsonl.ps1`) 対応。

### 5. SFTP / VSS
- **Basic SFTP**: ファイル転送サブシステム (基本実装)。
- **VSS Support**: `.snapshots` 仮想ディレクトリ経由でのシャドウコピーアクセス (Experimental)。

## 今後のロードマップ (Roadmap)

### P1: 安定性・運用性の向上
- [x] **Structured Binary Protocol (SBP)**: 旧称 "M4"。JSON/バイナリハイブリッドプロトコルによる、クォート地獄を回避した安全なコマンド実行 (`vlt-exec`)。
- [x] **Ephemeral Worker Architecture**: セッションごとに使い捨てのワーカープロセスを起動し、クリーンな環境を保証。
- [x] **Binary Naming Consistency**: `vlt-sshd.exe` / `vlt-worker.exe` / `vlt-admin.exe` / `vlt-exec.exe` を正式採用。
- [ ] **E2E Matrix Completion**: SFTP クライアントやポートフォワードの組み合わせテストの網羅。
- [ ] **Client-side Implementation**: `vlt-exec` の独立クレート化 (`clients/vlt-exec`) とマルチプラットフォーム対応。
- [ ] **Client-side Implementation**: `vlt-exec` の独立クレート化 (`clients/vlt-exec`) とマルチプラットフォーム対応。

### P2: 機能拡張
- [ ] **Advanced UI**: 管理 API 上の UI をよりリッチな管理コンソールへ昇華。
- [ ] **Real-time Logging**: ETW (Event Tracing for Windows) への構造化ログ出力。
- [ ] **Full Headless Support**: Session 0 環境下での外部コマンド実行保証（技術的ハードル高）。

## コマンドラインツール

- `vlt-admin`: サーバー管理（ユーザー追加、権限修復、サービス制御）
- `vlt-exec`: SBP プロトコルを使用したクライアントツール（Windows/Linux/Mac対応）。標準の SSH 接続上で、構造化されたコマンド実行を行います。

## ドキュメント

- 基本マニュアル: `MANUAL.md`
- インストール手順: `INSTALL.md`
- 運用ランブック: `docs/OPERATIONS_RUNBOOK.md` (現在非公開 / Private)
- 相互運用テスト表: `docs/INTEROP_E2E_MATRIX.md` (現在非公開 / Private)
- 拡張ロードマップ: `docs/LOW_PRIORITY_ROADMAP.md` (現在非公開 / Private)

## 開発インシデント履歴 (Development History)

### 2026-02-19: AIエージェントによる仕様乖離と復旧
- **事象**: AIエージェントの暴走により、仕様と乖離した別物への改変が行われました。
- **影響**: 公開リポジトリへのプッシュが正常に行われず、リバートを試みた結果、ローカル環境でもビルドが通らない状況に陥りました。
- **対応**: 最終的に、安定していたかなり古いバージョンまで遡って復旧を行いました。

## 免責

本ソフトウェアはベータ版です。  
データ保全・可用性・セキュリティ要件が厳しい本番環境では、十分な評価とバックアップ運用を前提にご利用ください。
