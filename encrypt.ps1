# ============================================================
# 資料夾 PGP 加密與簽署工具（tar 封裝 xz/zstd/不壓縮 + GPG 公鑰加密）
#
# 用法一：雙擊「加密工具.bat」，把資料夾拖進視窗清單
# 用法二：直接把資料夾拖曳到「加密工具.bat」圖示上
# 命令列：powershell -File encrypt.ps1 -cli <資料夾> <收件人KeyID或Email> [xz|zstd|store]
#
# 產出：資料夾依壓縮模式輸出 <名稱>.tar.xz.gpg（xz）、<名稱>.tar.zst.gpg（zstd）或
#       <名稱>.tar.gpg（store，僅打包不壓縮），與來源同一層；單一檔案輸出 <名稱>.gpg
# 流程：tar 串流壓縮(xz/zstd)或僅打包 → 管線直接送入 gpg 加密與簽署，明文暫存不落地
# 注意：本檔必須以「UTF-8 with BOM」編碼儲存，
#       否則 Windows PowerShell 5.1 會將中文解析為亂碼。
# ============================================================

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ---------- 外部工具定位 ----------

function Find-GpgExe {
    # 優先採用 GnuPG 標準安裝位置，避免 PATH 中混入 MSYS／其他發行版的 gpg
    # （例如 Git-Bash 環境的 gpg 會找不到自帶的 keyboxd 而失敗）
    foreach ($p in @(
        'C:\Program Files (x86)\GnuPG\bin\gpg.exe',
        'C:\Program Files\GnuPG\bin\gpg.exe',
        'C:\opt\GnuPG\bin\gpg.exe')) {
        if (Test-Path -LiteralPath $p) { return $p }
    }
    $c = Get-Command gpg.exe -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    return ''
}

$script:GpgExe = Find-GpgExe
$script:TarExe = Join-Path $env:SystemRoot 'System32\tar.exe'
if (-not (Test-Path -LiteralPath $script:TarExe)) { $script:TarExe = 'tar.exe' }

# ---------- 通用輔助 ----------

function Q { param([string]$s) '"' + $s + '"' }

function Normalize-FolderPath {
    # 轉為絕對路徑並移除結尾反斜線（磁碟根目錄除外）
    param([string]$p)
    $full = [System.IO.Path]::GetFullPath($p)
    while ($full.Length -gt 3 -and $full.EndsWith('\')) { $full = $full.Substring(0, $full.Length - 1) }
    return $full
}

function Write-Log {
    # kind：0 一般、1 成功、2 錯誤；GUI 寫入紀錄面板；CLI 模式緩衝到處理結束後一次輸出。
    # 重要：實測 PowerShell 5.1 在 tar→gpg 管線傳輸期間輸出主控台，
    #       gpg 收到的串流開頭會被插入 UTF-8 BOM 導致解壓失敗，故 CLI 不得即時輸出。
    param([string]$msg, [int]$kind = 0)
    $line = '[{0:HH:mm:ss}] {1}' -f (Get-Date), $msg
    if ($script:txtLog) {
        $color = [System.Drawing.Color]::Black
        if ($kind -eq 1) { $color = [System.Drawing.Color]::Green }
        if ($kind -eq 2) { $color = [System.Drawing.Color]::Firebrick }
        $script:txtLog.SelectionStart = $script:txtLog.Text.Length
        $script:txtLog.SelectionColor = $color
        $script:txtLog.AppendText($line + [Environment]::NewLine)
        $script:txtLog.ScrollToCaret()
        $script:txtLog.SelectionColor = $script:txtLog.ForeColor
    } elseif ($script:CliLog) {
        [void]$script:CliLog.Add($line)
    } else {
        Write-Host $line
    }
}

function Flush-LogBuffer {
    # CLI 模式結束時輸出緩衝的紀錄
    if ($script:CliLog) {
        foreach ($l in $script:CliLog) { Write-Host $l }
        $script:CliLog = $null
    }
}

function Get-OutputPath {
    # 資料夾依壓縮模式輸出對應副檔名，檔案輸出 gpg；同名檔案已存在時附加序號，避免覆蓋舊備份
    param(
        [string]$Source,
        [string]$CompMode = 'xz'
    )
    $full = Normalize-FolderPath -p $Source
    $dir  = Split-Path -Parent $full
    $name = Split-Path -Leaf   $full
    $suffix = if (Test-Path -LiteralPath $full -PathType Container) { $script:CompSuffix[$CompMode] } else { '.gpg' }
    $base = Join-Path $dir ($name + $suffix)
    if (-not (Test-Path -LiteralPath $base)) { return $base }
    $i = 1
    while ($true) {
        $cand = Join-Path $dir ($name + '_' + ('{0:D2}' -f $i) + $suffix)
        if (-not (Test-Path -LiteralPath $cand)) { return $cand }
        $i++
    }
}

function Get-CombinedOutputPath {
    # 確保合併輸出使用與壓縮模式對應的副檔名，並保留既有檔案的自動序號保護
    param(
        [string]$RequestedPath,
        [string]$CompMode = 'xz'
    )
    $suffix = $script:CompSuffix[$CompMode]
    $full = [System.IO.Path]::GetFullPath($RequestedPath)
    if (-not $full.EndsWith($suffix, [System.StringComparison]::OrdinalIgnoreCase)) { $full += $suffix }
    if (-not (Test-Path -LiteralPath $full)) { return $full }
    $base = $full.Substring(0, $full.Length - $suffix.Length)
    $i = 1
    while ($true) {
        $cand = $base + '_' + ('{0:D2}' -f $i) + $suffix
        if (-not (Test-Path -LiteralPath $cand)) { return $cand }
        $i++
    }
}

function Invoke-TarEncrypt {
    # 以 cmd 原生管線串接 tar 與 gpg，明文封裝檔不落地。
    # 不以 .NET 重新導向管線搬運串流：實測 PowerShell 5.1 環境下該方式偶發使
    # gpg 收到的串流開頭被插入 UTF-8 BOM，導致解密端 tar 無法解壓。
    # 左側以暫存批次檔包裝 tar：@echo off 防止命令回顯進入管線，
    # %errorlevel% 於批次內執行期展開（哨兵檔記錄 tar 結束碼）。
    # 所有路徑參數經環境變數傳入，批次檔保持純 ASCII，展開為單次、不受
    # 命令列特殊字元（&、% 等）影響。
    param(
        [string]$TarArguments,
        [string]$Recipient,
        [string]$OutputFile
    )
    $ecFile = [System.IO.Path]::GetTempFileName()
    $tarErr = [System.IO.Path]::GetTempFileName()
    $leftCmd = [System.IO.Path]::GetTempFileName()
    Remove-Item -LiteralPath $leftCmd -Force -ErrorAction SilentlyContinue
    $leftCmd += '.cmd'
    # gpg 內層停止重複壓縮（tar 串流已壓縮或選擇不壓縮）
    $gpgArgs = '--quiet --batch --yes --no-tty --trust-model always --compress-level 0 --output ' + (Q $OutputFile) + ' --sign --encrypt --recipient ' + (Q $Recipient)
    $batch = @"
@echo off
"$script:TarExe" %PGPTAR% 2> "$tarErr"
> "$ecFile" echo %errorlevel%
"@
    [System.IO.File]::WriteAllText($leftCmd, $batch, [System.Text.Encoding]::ASCII)

    $line = '"' + $leftCmd + '" | "' + $script:GpgExe + '" %PGPGPG%'
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $env:ComSpec
    $psi.Arguments = '/d /s /c "' + $line + '"'
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow  = $true
    $psi.RedirectStandardError = $true
    $psi.EnvironmentVariables['TAREXE']  = $script:TarExe
    $psi.EnvironmentVariables['PGPTAR']  = $TarArguments
    $psi.EnvironmentVariables['PGPGPG']  = $gpgArgs

    $cmd = [System.Diagnostics.Process]::Start($psi)
    try { $cmd.WaitForExit() } catch {}
    $errText = ''
    try { $errText = $cmd.StandardError.ReadToEnd() } catch {}
    $gpgExit = $cmd.ExitCode
    $cmd.Dispose()

    $tarExit = 1
    try { $tarExit = [int](Get-Content -LiteralPath $ecFile -TotalCount 1) } catch {}
    $tarMsg = ''
    try { $tarMsg = (Get-Content -LiteralPath $tarErr -Raw) } catch {}
    Remove-Item -LiteralPath $leftCmd -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $ecFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $tarErr -Force -ErrorAction SilentlyContinue

    if ($gpgExit -ne 0) {
        if (Test-Path -LiteralPath $OutputFile) { Remove-Item -LiteralPath $OutputFile -Force -ErrorAction SilentlyContinue }
        throw ('GPG 加密或簽署失敗（結束碼 ' + $gpgExit + '）：' + $errText.Trim())
    }
    if ($tarExit -ne 0) {
        if (Test-Path -LiteralPath $OutputFile) { Remove-Item -LiteralPath $OutputFile -Force -ErrorAction SilentlyContinue }
        $detail = ''
        if ($tarMsg) { $detail = '：' + ($tarMsg.Trim()) }
        throw "tar 壓縮失敗（結束碼 $tarExit）$detail"
    }
}

function Invoke-CompressEncrypt {
    # 單一資料夾依壓縮模式封裝後加密與簽署
    param(
        [string]$SourcePath,
        [string]$Recipient,
        [string]$OutputFile,
        [string]$CompMode = 'xz'
    )
    $full = Normalize-FolderPath -p $SourcePath
    if ($full -match '^[A-Za-z]:\\?$') { throw '無法加密磁碟根目錄，請選擇其下的子資料夾。' }
    if (-not (Test-Path -LiteralPath $full -PathType Container)) { throw "來源不是有效資料夾：$full" }
    $parent = Split-Path -Parent $full
    $name   = Split-Path -Leaf   $full
    if (-not $parent) { throw "無法取得上層資料夾：$full" }

    Write-Log "壓縮、加密並簽署中：$name"
    Invoke-TarEncrypt -TarArguments ((Get-TarCompressArgs -Mode $CompMode) + ' -C ' + (Q $parent) + ' ' + (Q $name)) -Recipient $Recipient -OutputFile $OutputFile
}

function Invoke-CombinedCompressEncrypt {
    # 使用每個來源的上層路徑封裝，避免把絕對路徑與磁碟代號寫入封裝檔
    param(
        [string[]]$SourcePaths,
        [string]$Recipient,
        [string]$OutputFile,
        [string]$CompMode = 'xz'
    )
    $tarParts = New-Object System.Collections.Generic.List[string]
    [void]$tarParts.Add((Get-TarCompressArgs -Mode $CompMode))
    $entryNames = New-Object System.Collections.Generic.List[string]
    foreach ($source in $SourcePaths) {
        $full = Normalize-FolderPath -p $source
        if ($full -match '^[A-Za-z]:\\?$') { throw '無法合併磁碟根目錄，請選擇其下的資料夾或檔案。' }
        if (-not ((Test-Path -LiteralPath $full -PathType Container) -or (Test-Path -LiteralPath $full -PathType Leaf))) {
            throw "來源不是有效資料夾或檔案：$full"
        }
        $parent = Split-Path -Parent $full
        $name = Split-Path -Leaf $full
        if ($entryNames -contains $name) { throw "合併項目有重複名稱：$name。請重新命名後再合併。" }
        $entryNames.Add($name)
        $tarParts.Add('-C ' + (Q $parent) + ' ' + (Q $name))
    }
    Write-Log ('合併 ' + $SourcePaths.Count + ' 個項目並加密簽署中…')
    Invoke-TarEncrypt -TarArguments ($tarParts -join ' ') -Recipient $Recipient -OutputFile $OutputFile
}

function Invoke-FileEncrypt {
    # 單一檔案直接加密與簽署，避免為檔案額外建立 tar 封裝
    param(
        [string]$SourcePath,
        [string]$Recipient,
        [string]$OutputFile,
        [string]$CompMode = 'xz'
    )
    $full = Normalize-FolderPath -p $SourcePath
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw "來源不是有效檔案：$full" }

    Write-Log "加密並簽署檔案中：$(Split-Path -Leaf $full)"
    $gpgPsi = New-Object System.Diagnostics.ProcessStartInfo
    $gpgPsi.FileName  = $script:GpgExe
    # store（不壓縮）模式：連 gpg 內層壓縮也停用，避免對已壓縮內容白費時間
    $compArgs = if ($CompMode -eq 'store') { ' --compress-level 0' } else { '' }
    $gpgPsi.Arguments = '--quiet --batch --yes --no-tty --trust-model always --output ' + (Q $OutputFile) + ' --sign --encrypt --recipient ' + (Q $Recipient) + $compArgs + ' -- ' + (Q $full)
    $gpgPsi.UseShellExecute = $false
    $gpgPsi.CreateNoWindow  = $true
    $gpgPsi.RedirectStandardError = $true

    $gpg = [System.Diagnostics.Process]::Start($gpgPsi)
    $gpg.WaitForExit()
    $errText = $gpg.StandardError.ReadToEnd()
    $gpgExit = $gpg.ExitCode
    $gpg.Dispose()
    if ($gpgExit -ne 0) {
        if (Test-Path -LiteralPath $OutputFile) { Remove-Item -LiteralPath $OutputFile -Force -ErrorAction SilentlyContinue }
        throw ('GPG 加密或簽署失敗（結束碼 ' + $gpgExit + '）：' + $errText.Trim())
    }
}

function Invoke-EncryptInput {
    # 依來源類型選擇封裝方式，讓 GUI 與命令列保持相同輸出規則
    param(
        [string]$SourcePath,
        [string]$Recipient,
        [string]$OutputFile,
        [string]$CompMode = 'xz'
    )
    if (Test-Path -LiteralPath $SourcePath -PathType Container) {
        Invoke-CompressEncrypt -SourcePath $SourcePath -Recipient $Recipient -OutputFile $OutputFile -CompMode $CompMode
    } elseif (Test-Path -LiteralPath $SourcePath -PathType Leaf) {
        Invoke-FileEncrypt -SourcePath $SourcePath -Recipient $Recipient -OutputFile $OutputFile -CompMode $CompMode
    } else {
        throw "來源不是有效資料夾或檔案：$SourcePath"
    }
}

function Get-RecipientKeys {
    # 解析 gpg 金鑰清單，回傳可用於加密的公鑰（略過停用／過期金鑰）
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $lines = & $script:GpgExe --list-keys --with-colons 2>$null
    $ErrorActionPreference = $prev
    $keys = @()
    $cur = $null
    foreach ($ln in $lines) {
        if ([string]::IsNullOrEmpty($ln)) { continue }
        $f = $ln -split ':'
        if ($f[0] -eq 'pub') {
            if ($null -ne $cur) { $keys += $cur; $cur = $null }
            if ($f.Count -gt 4 -and $f[1] -notmatch '[dei]') {
                $cur = @{ Id = $f[4]; Uid = $f[4] }
            }
        }
        elseif ($f[0] -eq 'uid' -and $null -ne $cur -and $cur.Uid -eq $cur.Id -and $f.Count -gt 5) {
            if ($f[5]) { $cur.Uid = $f[5] }
        }
    }
    if ($null -ne $cur) { $keys += $cur }
    return ,$keys
}

# ---------- 壓縮模式 ----------
# xz：高壓縮率（預設）；zstd：速度優先；store：僅打包不壓縮（適合影片等已壓縮內容）
$script:CompArgs   = @{ xz = '-cJf -'; zstd = '--zstd -cf -'; store = '-cf -' }
$script:CompSuffix = @{ xz = '.tar.xz.gpg'; zstd = '.tar.zst.gpg'; store = '.tar.gpg' }

function Get-TarCompressArgs {
    # 依壓縮模式回傳 tar 的建立與壓縮參數
    param([string]$Mode)
    $a = $script:CompArgs[$Mode]
    if (-not $a) { throw "未知壓縮模式：$Mode（可選 xz、zstd、store）" }
    return $a
}

function Test-TarZstdSupport {
    # 以與主流程相同的方式（stdout 管線串流）實測 tar 的 zstd：寫出後必須能被 tar 讀回。
    # 部分 bsdtar 版本對 stdout 輸出會補零至 10240 位元組，導致 zstd 串流無法解壓。
    $tmp = Join-Path $env:TEMP ('tarzstd_' + [Guid]::NewGuid().ToString('N'))
    try {
        [void](New-Item -ItemType Directory -Path $tmp -Force)
        Set-Content -LiteralPath (Join-Path $tmp 'probe.txt') -Value 'probe'

        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $script:TarExe
        $psi.Arguments = '--zstd -cf - -C ' + (Q $tmp) + ' probe.txt'
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $tar = [System.Diagnostics.Process]::Start($psi)
        $ms = New-Object System.IO.MemoryStream
        try { $tar.StandardOutput.BaseStream.CopyTo($ms) } catch {}
        try { [void]$tar.StandardError.ReadToEnd() } catch {}
        try { $tar.WaitForExit() } catch {}
        $code = $tar.ExitCode
        $tar.Dispose()
        if ($code -ne 0 -or $ms.Length -eq 0) { return $false }

        $zst = Join-Path $tmp 'probe.tar.zst'
        [System.IO.File]::WriteAllBytes($zst, $ms.ToArray())
        $prev = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        & $script:TarExe -tf $zst 2>$null | Out-Null
        $readOk = ($LASTEXITCODE -eq 0)
        $ErrorActionPreference = $prev
        return $readOk
    } catch {
        return $false
    } finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$script:ZstdOk = Test-TarZstdSupport

# ---------- 命令列模式：encrypt.ps1 -cli <資料夾或檔案> <收件人> [xz|zstd|store] ----------

if ($args.Count -ge 1 -and $args[0] -eq '-cli') {
    if (-not $script:GpgExe) { Write-Host '找不到 gpg.exe，請先安裝 GnuPG（Gpg4win）。'; exit 2 }
    if ($args.Count -lt 3)  { Write-Host '用法：encrypt.ps1 -cli <資料夾或檔案> <收件人KeyID或Email> [xz|zstd|store]'; exit 2 }
    $compMode = 'xz'
    if ($args.Count -ge 4) {
        $compMode = ([string]$args[3]).ToLowerInvariant()
        if ($compMode -eq 'tar' -or $compMode -eq 'none') { $compMode = 'store' }
        if (-not $script:CompSuffix.ContainsKey($compMode)) {
            Write-Host ('未知壓縮模式：{0}（可選 xz、zstd、store）' -f $args[3]); exit 2
        }
        if ($compMode -eq 'zstd' -and -not $script:ZstdOk) {
            Write-Host '本機 tar.exe 的 zstd 串流寫出後無法讀回（bsdtar 已知問題），請使用 xz 或 store（僅打包）。'; exit 2
        }
    }
    $out = Get-OutputPath -Source $args[1] -CompMode $compMode
    $script:CliLog = New-Object System.Collections.Generic.List[string]
    try {
        Invoke-EncryptInput -SourcePath $args[1] -Recipient $args[2] -OutputFile $out -CompMode $compMode
        Write-Log "完成：$out" 1
        Flush-LogBuffer
        exit 0
    } catch {
        Write-Log ("失敗：" + $_.Exception.Message) 2
        Flush-LogBuffer
        exit 1
    }
}

# ---------- 圖形介面 ----------

if (-not $script:GpgExe) {
    [void][System.Windows.Forms.MessageBox]::Show('找不到 gpg.exe，請先安裝 GnuPG（Gpg4win）後再執行。', '缺少必要元件')
    exit 2
}

[System.Windows.Forms.Application]::EnableVisualStyles()

$script:txtLog  = $null
$script:Busy    = $false
$script:KeyMap  = @{}
$script:Inputs  = New-Object System.Collections.Generic.List[string]

$form = New-Object System.Windows.Forms.Form
$form.Text = '資料夾與檔案 PGP 加密與簽署工具（tar + GPG）'
$form.ClientSize = New-Object System.Drawing.Size(694, 521)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.Font = New-Object System.Drawing.Font('Microsoft JhengHei UI', 9)

$lblHint = New-Object System.Windows.Forms.Label
$lblHint.Text = '1. 將要加密的資料夾或檔案拖曳到下方清單（可多個）'
$lblHint.Location = New-Object System.Drawing.Point(12, 12)
$lblHint.Size = New-Object System.Drawing.Size(460, 20)
$form.Controls.Add($lblHint)

$lblCount = New-Object System.Windows.Forms.Label
$lblCount.Text = '已加入 0 個項目'
$lblCount.Location = New-Object System.Drawing.Point(480, 12)
$lblCount.Size = New-Object System.Drawing.Size(202, 20)
$lblCount.TextAlign = 'MiddleRight'
$form.Controls.Add($lblCount)

$lstFolders = New-Object System.Windows.Forms.ListBox
$lstFolders.Location = New-Object System.Drawing.Point(12, 36)
$lstFolders.Size = New-Object System.Drawing.Size(560, 160)
$lstFolders.SelectionMode = 'MultiExtended'
$lstFolders.AllowDrop = $true
$lstFolders.HorizontalScrollbar = $true
$form.Controls.Add($lstFolders)

$btnAdd = New-Object System.Windows.Forms.Button
$btnAdd.Text = '加入資料夾…'
$btnAdd.Location = New-Object System.Drawing.Point(582, 36)
$btnAdd.Size = New-Object System.Drawing.Size(100, 28)
$form.Controls.Add($btnAdd)

$btnAddFile = New-Object System.Windows.Forms.Button
$btnAddFile.Text = '加入檔案…'
$btnAddFile.Location = New-Object System.Drawing.Point(582, 70)
$btnAddFile.Size = New-Object System.Drawing.Size(100, 28)
$form.Controls.Add($btnAddFile)

$btnRemove = New-Object System.Windows.Forms.Button
$btnRemove.Text = '移除所選'
$btnRemove.Location = New-Object System.Drawing.Point(582, 104)
$btnRemove.Size = New-Object System.Drawing.Size(100, 28)
$form.Controls.Add($btnRemove)

$btnClear = New-Object System.Windows.Forms.Button
$btnClear.Text = '清空'
$btnClear.Location = New-Object System.Drawing.Point(582, 138)
$btnClear.Size = New-Object System.Drawing.Size(100, 28)
$form.Controls.Add($btnClear)

$chkCombine = New-Object System.Windows.Forms.CheckBox
$chkCombine.Text = '將清單中的所有項目合併為單一壓縮檔'
$chkCombine.Location = New-Object System.Drawing.Point(12, 202)
$chkCombine.Size = New-Object System.Drawing.Size(360, 24)
$form.Controls.Add($chkCombine)

$lblComp = New-Object System.Windows.Forms.Label
$lblComp.Text = '壓縮格式：'
$lblComp.Location = New-Object System.Drawing.Point(384, 202)
$lblComp.Size = New-Object System.Drawing.Size(78, 24)
$form.Controls.Add($lblComp)

$cboComp = New-Object System.Windows.Forms.ComboBox
$cboComp.Location = New-Object System.Drawing.Point(466, 202)
$cboComp.Size = New-Object System.Drawing.Size(216, 26)
$cboComp.DropDownStyle = 'DropDownList'
$form.Controls.Add($cboComp)

$lblKey = New-Object System.Windows.Forms.Label
$lblKey.Text = '2. 選擇加密對象（公鑰）'
$lblKey.Location = New-Object System.Drawing.Point(12, 236)
$lblKey.Size = New-Object System.Drawing.Size(670, 20)
$form.Controls.Add($lblKey)

$cboKey = New-Object System.Windows.Forms.ComboBox
$cboKey.Location = New-Object System.Drawing.Point(12, 260)
$cboKey.Size = New-Object System.Drawing.Size(670, 26)
$cboKey.DropDownStyle = 'DropDownList'
$form.Controls.Add($cboKey)

$btnGo = New-Object System.Windows.Forms.Button
$btnGo.Text = '開始加密並簽署'
$btnGo.Location = New-Object System.Drawing.Point(12, 296)
$btnGo.Size = New-Object System.Drawing.Size(670, 42)
$form.Controls.Add($btnGo)

$lblLog = New-Object System.Windows.Forms.Label
$lblLog.Text = '處理紀錄：'
$lblLog.Location = New-Object System.Drawing.Point(12, 346)
$lblLog.Size = New-Object System.Drawing.Size(670, 20)
$form.Controls.Add($lblLog)

$rtbLog = New-Object System.Windows.Forms.RichTextBox
$rtbLog.Location = New-Object System.Drawing.Point(12, 368)
$rtbLog.Size = New-Object System.Drawing.Size(670, 140)
$rtbLog.ReadOnly = $true
$rtbLog.BackColor = [System.Drawing.Color]::White
$form.Controls.Add($rtbLog)
$script:txtLog = $rtbLog

function Update-Count {
    $lblCount.Text = '已加入 ' + $script:Inputs.Count + ' 個項目'
}

function Add-Inputs {
    # 加入資料夾或檔案，並以完整路徑去重
    param([string[]]$Paths)
    foreach ($p in $Paths) {
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        try { $full = Normalize-FolderPath -p $p } catch { Write-Log "略過無效路徑：$p" 2; continue }
        if ((Test-Path -LiteralPath $full -PathType Container) -or (Test-Path -LiteralPath $full -PathType Leaf)) {
            if (-not $script:Inputs.Contains($full)) {
                $script:Inputs.Add($full)
                [void]$lstFolders.Items.Add($full)
                Write-Log "已加入：$full"
            } else {
                Write-Log "重複，略過：$full"
            }
        } else {
            Write-Log "略過（找不到資料夾或檔案）：$full" 2
        }
    }
    Update-Count
}

$dragHandler = {
    param($s, $e)
    if ($e.Data.GetDataPresent([System.Windows.Forms.DataFormats]::FileDrop)) {
        $e.Effect = [System.Windows.Forms.DragDropEffects]::Copy
    }
}
$dropHandler = {
    param($s, $e)
    if ($script:Busy) { Write-Log '正在處理中，請稍候。' 2; return }
    $paths = $e.Data.GetData([System.Windows.Forms.DataFormats]::FileDrop)
    if ($paths) { Add-Inputs -Paths $paths }
}
$lstFolders.add_DragEnter($dragHandler)
$lstFolders.add_DragDrop($dropHandler)
$form.AllowDrop = $true
$form.add_DragEnter($dragHandler)
$form.add_DragDrop($dropHandler)

$btnAdd.add_Click({
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description = '選擇要加密的資料夾'
    if ($dlg.ShowDialog($form) -eq [System.Windows.Forms.DialogResult]::OK) {
        Add-Inputs -Paths @($dlg.SelectedPath)
    }
})

$btnAddFile.add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Title = '選擇要加密的檔案'
    $dlg.Multiselect = $true
    if ($dlg.ShowDialog($form) -eq [System.Windows.Forms.DialogResult]::OK) {
        Add-Inputs -Paths $dlg.FileNames
    }
})

$btnRemove.add_Click({
    if ($script:Busy) { return }
    $sel = @($lstFolders.SelectedIndices)
    for ($i = $sel.Count - 1; $i -ge 0; $i--) {
        $script:Inputs.RemoveAt($sel[$i])
        $lstFolders.Items.RemoveAt($sel[$i])
    }
    Update-Count
})

$btnClear.add_Click({
    if ($script:Busy) { return }
    $script:Inputs.Clear()
    $lstFolders.Items.Clear()
    Update-Count
})

$btnGo.add_Click({
    if ($script:Busy) { return }
    if ($script:Inputs.Count -eq 0) {
        [void][System.Windows.Forms.MessageBox]::Show($form, '請先將要加密的資料夾或檔案加入清單。', '提示')
        return
    }
    $disp = $cboKey.SelectedItem
    if ($null -eq $disp -or -not $script:KeyMap.ContainsKey($disp)) {
        [void][System.Windows.Forms.MessageBox]::Show($form, '請先選擇加密對象（公鑰）。', '提示')
        return
    }
    $rid = $script:KeyMap[$disp]
    $compMode = $script:CompMap[[string]$cboComp.SelectedItem]
    if (-not $compMode) { $compMode = 'xz' }
    $compSuffix = $script:CompSuffix[$compMode]
    $combinedOutput = ''
    if ($chkCombine.Checked) {
        $saveDlg = New-Object System.Windows.Forms.SaveFileDialog
        $saveDlg.Title = '選擇合併壓縮檔的輸出位置'
        $saveDlg.InitialDirectory = Split-Path -Parent $script:Inputs[0]
        $saveDlg.FileName = '合併加密' + $compSuffix
        $saveDlg.Filter = '加密壓縮檔 (*' + $compSuffix + ')|*' + $compSuffix
        $saveDlg.AddExtension = $false
        if ($saveDlg.ShowDialog($form) -ne [System.Windows.Forms.DialogResult]::OK) { return }
        $combinedOutput = Get-CombinedOutputPath -RequestedPath $saveDlg.FileName -CompMode $compMode
    }
    $script:Busy = $true
    $btnGo.Enabled = $false; $btnAdd.Enabled = $false; $btnAddFile.Enabled = $false; $btnRemove.Enabled = $false; $btnClear.Enabled = $false; $chkCombine.Enabled = $false; $cboComp.Enabled = $false
    $form.UseWaitCursor = $true
    try {
        if ($chkCombine.Checked) {
            try {
                Invoke-CombinedCompressEncrypt -SourcePaths $script:Inputs.ToArray() -Recipient $rid -OutputFile $combinedOutput -CompMode $compMode
                Write-Log "完成：$combinedOutput" 1
            } catch {
                Write-Log ("失敗：" + $_.Exception.Message) 2
            }
        } else {
            foreach ($p in $script:Inputs.ToArray()) {
                try {
                    $out = Get-OutputPath -Source $p -CompMode $compMode
                    Invoke-EncryptInput -SourcePath $p -Recipient $rid -OutputFile $out -CompMode $compMode
                    Write-Log "完成：$out" 1
                } catch {
                    Write-Log ("失敗：" + $_.Exception.Message) 2
                }
            }
        }
        Write-Log '全部處理完畢。' 1
    } finally {
        $script:Busy = $false
        $form.UseWaitCursor = $false
        $btnGo.Enabled = $true; $btnAdd.Enabled = $true; $btnAddFile.Enabled = $true; $btnRemove.Enabled = $true; $btnClear.Enabled = $true; $chkCombine.Enabled = $true; $cboComp.Enabled = $true
    }
})
$form.AcceptButton = $btnGo

# 壓縮格式選單：zstd 僅在本機 tar 實測可寫入並讀回時列出
$script:CompMap = @{}
$compChoices = @(@{ Text = 'xz（高壓縮率，較慢）'; Mode = 'xz' })
if ($script:ZstdOk) {
    $compChoices += @{ Text = 'zstd（速度快，壓縮率中等）'; Mode = 'zstd' }
}
$compChoices += @{ Text = '不壓縮（僅打包 tar）'; Mode = 'store' }
foreach ($c in $compChoices) {
    $script:CompMap[$c.Text] = $c.Mode
    [void]$cboComp.Items.Add($c.Text)
}
$cboComp.SelectedIndex = 0
if (-not $script:ZstdOk) {
    Write-Log '本機 tar.exe 的 zstd 串流寫出後無法讀回（bsdtar 已知問題），已隱藏 zstd 選項。' 2
}

# 載入金鑰圈中的公鑰
$keys = Get-RecipientKeys
foreach ($k in $keys) {
    $disp = $k.Uid + '  [' + $k.Id + ']'
    $script:KeyMap[$disp] = $k.Id
    [void]$cboKey.Items.Add($disp)
}
if ($cboKey.Items.Count -gt 0) {
    $cboKey.SelectedIndex = 0
} else {
    Write-Log '金鑰圈中找不到可用公鑰。請先建立（gpg --full-generate-key）或匯入（gpg --import 公鑰檔）。' 2
}

# 預先填入拖曳到 .bat 上的資料夾或檔案
if ($args.Count -ge 1) { Add-Inputs -Paths $args }

Write-Log '請拖入資料夾或檔案後按「開始加密並簽署」。'
[void]$form.ShowDialog()
