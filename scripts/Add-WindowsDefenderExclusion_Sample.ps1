# ==================================================================================
# [警告 / WARNING]
# ==================================================================================
# 本スクリプトは、アンチウイルスソフト（Windows Defender）による誤検知を回避するために
# 特定のフォルダをスキャン対象から除外するためのサンプルです。
#
# !! 注意 !!
# 1. このスクリプトを使用すると、指定したフォルダ内のファイルはウイルスチェックされなくなります。
# 2. マルウェアが混入した場合、検知できなくなるリスクがあります。
# 3. 本ソフトウェアおよび本スクリプトの使用により発生したいかなる損害についても、
#    作者は一切の責任を負いません。
# 4. ご自身の責任において、セキュリティリスクを十分に理解した上で使用してください。
# ==================================================================================

# ユーザー設定: 除外したいフォルダパスに変更してください
# 例: $TargetFolder = "C:\Tools\WinNativeSSH"
$TargetFolder = "C:\Path\To\WinNativeSSH_Directory"

# パスの存在確認
if (-not (Test-Path $TargetFolder)) {
    Write-Host "[エラー] 指定されたフォルダが見つかりません: $TargetFolder" -ForegroundColor Red
    Write-Host "スクリプト内の `$TargetFolder` を正しいパスに書き換えてください。" -ForegroundColor Yellow
    exit 1
}

# 実行確認
Write-Host "以下のフォルダをWindows Defenderの除外リストに追加します:" -ForegroundColor Cyan
Write-Host "パス: $TargetFolder"
Write-Host ""
Write-Host "※この操作には管理者権限が必要です。" -ForegroundColor Yellow
$confirm = Read-Host "本当によろしいですか？ (y/n)"

if ($confirm -ne 'y') {
    Write-Host "中止しました。"
    exit
}

try {
    # Windows Defenderの除外リストに追加 (管理者権限が必要)
    Add-MpPreference -ExclusionPath $TargetFolder -ErrorAction Stop
    Write-Host "[成功] 除外リストに追加しました。" -ForegroundColor Green
}
catch {
    Write-Host "[エラー] 追加に失敗しました。" -ForegroundColor Red
    Write-Host "エラー詳細: $_"
    Write-Host ""
    Write-Host "ヒント: このスクリプトを「管理者として実行」していますか？" -ForegroundColor Yellow
}

Pause
