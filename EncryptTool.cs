// ============================================================
// 資料夾／檔案 PGP 加密與簽署工具（tar + GPG）— C# 版
//
// 以 Windows 內建 .NET Framework csc.exe 編譯為單一 exe（見 build.bat），
// Win10/11 無需安裝任何執行環境即可執行。
//
// 用法一：雙擊 PGPEncrypt.exe（或 加密工具.bat），把資料夾／檔案拖進清單
// 用法二：直接把資料夾／檔案拖曳到 PGPEncrypt.exe 圖示上（原生參數，無 cmd 限制）
// 命令列：PGPEncrypt.exe <資料夾或檔案> <收件人KeyID或Email> [xz|zstd|store]
//         （相容舊寫法：第一個參數為 -cli 時予以略過）
// 合併：  PGPEncrypt.exe -combine <輸出檔> <收件人> [xz|zstd|store] <項目...>
// 密碼：  PGPEncrypt.exe -pw [-len 位數] [-mx 等級] [-toname] [-out <輸出檔>] <項目...>
//
// 產出：資料夾依壓縮模式輸出 <名稱>.tar.xz.gpg（xz）、<名稱>.tar.zst.gpg（zstd）或
//       <名稱>.tar.gpg（store，僅打包不壓縮），與來源同一層；單一檔案輸出 <名稱>.gpg
//       -pw 模式輸出 <名稱>.7z（與來源同一層），以隨機密碼做 7z AES-256 對稱加密
// 流程：tar 串流壓縮(xz/zstd)或僅打包 → cmd 原生管線直送 gpg 加密與簽署，明文暫存不落地
//       -pw 模式不經 tar 與 GPG：7z 自行讀取來源打包並加密，明文同樣不落地
// 注意：tar→gpg 不用 .NET 重新導向管線搬運串流——實測該方式偶發使 gpg 收到的
//       串流開頭被插入 UTF-8 BOM 導致解壓失敗，故以 cmd 原生管線 + 批次檔哨兵實作。
// ============================================================

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;

namespace PGPEncrypt
{
    internal class GpgKey
    {
        public string Id;
        public string Uid;
    }

    internal static class Program
    {
        internal const string GpgArgsCommon = "--quiet --batch --yes --no-tty --trust-model always";

        internal static readonly Dictionary<string, string> CompArgs = new Dictionary<string, string>
        {
            { "xz", "-cJf -" },
            { "zstd", "--zstd -cf -" },
            { "store", "-cf -" }
        };

        internal static readonly Dictionary<string, string> CompSuffix = new Dictionary<string, string>
        {
            { "xz", ".tar.xz.gpg" },
            { "zstd", ".tar.zst.gpg" },
            { "store", ".tar.gpg" }
        };

        internal static string GpgExe = "";
        internal static string TarExe = "";
        internal static string SevenZipExe = "";
        internal static bool ZstdOk = false;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AttachConsole(uint dwProcessId);
        [DllImport("kernel32.dll")]
        private static extern bool AllocConsole();
        [DllImport("kernel32.dll")]
        private static extern bool FreeConsole();
        private const uint ATTACH_PARENT_PROCESS = 0xFFFFFFFF;

        [STAThread]
        private static int Main(string[] args)
        {
            GpgExe = FindGpgExe();
            TarExe = FindTarExe();
            SevenZipExe = Find7ZipExe();
            ZstdOk = ProbeTarZstd();

            List<string> a = new List<string>(args);
            bool hadCliPrefix = a.Count > 0 && a[0] == "-cli";
            if (hadCliPrefix) a.RemoveAt(0);

            // -combine <輸出檔> <收件人> [xz|zstd|store] <項目...>
            if (a.Count >= 1 && a[0] == "-combine")
            {
                AttachCliConsole();
                if (GpgExe.Length == 0) { Console.WriteLine("找不到 gpg.exe，請先安裝 GnuPG（Gpg4win）。"); return 2; }
                if (a.Count < 3) { Console.WriteLine(Usage()); return 2; }
                string mode = "xz";
                int idx = 3;
                if (a.Count >= 4)
                {
                    string m = a[3].ToLowerInvariant();
                    if (m == "tar" || m == "none") m = "store";
                    if (CompSuffix.ContainsKey(m)) { mode = m; idx = 4; }
                }
                if (mode == "zstd" && !ZstdOk)
                {
                    Console.WriteLine("本機 tar.exe 的 zstd 串流寫出後無法讀回（bsdtar 已知問題），請使用 xz 或 store（僅打包）。");
                    return 2;
                }
                if (a.Count - idx < 1) { Console.WriteLine("至少需要一個要合併的項目。"); return 2; }
                string[] items = a.GetRange(idx, a.Count - idx).ToArray();
                string outp = GetCombinedOutputPath(a[1], mode);
                try
                {
                    CombinedCompressEncrypt(items, a[2], outp, mode, ConsoleLog, MakeCliProgress());
                    ConsoleLog("完成：" + outp, 1);
                    return 0;
                }
                catch (Exception ex)
                {
                    ConsoleLog("失敗：" + ex.Message, 2);
                    return 1;
                }
            }

            // -pw [-len 位數] [-mx 等級] [-toname] [-out <輸出檔>] <項目...>
            if (a.Count >= 1 && a[0] == "-pw")
            {
                AttachCliConsole();
                int len = 27, level = 0;
                bool toName = false;
                string outOverride = null;
                List<string> items = new List<string>();
                for (int i = 1; i < a.Count; i++)
                {
                    string t = a[i];
                    if (t == "-len" && i + 1 < a.Count)
                    {
                        if (!int.TryParse(a[++i], out len) || len < 1 || len > 128) { Console.WriteLine("密碼位數必須是 1 到 128 的整數。"); return 2; }
                    }
                    else if (t == "-mx" && i + 1 < a.Count)
                    {
                        if (!int.TryParse(a[++i], out level) || level < 0 || level > 9) { Console.WriteLine("壓縮等級必須是 0 到 9 的整數。"); return 2; }
                    }
                    else if (t == "-toname") toName = true;
                    else if (t == "-out" && i + 1 < a.Count) outOverride = a[++i];
                    else if (t.StartsWith("-")) { Console.WriteLine("未知選項：" + t); return 2; }
                    else items.Add(t);
                }
                if (SevenZipExe.Length == 0) { Console.WriteLine("找不到 7z.exe。請安裝 7-Zip，或改用 PGP 模式。"); return 2; }
                if (items.Count < 1) { Console.WriteLine("至少需要一個要加密的項目。"); return 2; }
                try
                {
                    string outp;
                    string pw = SevenZipEncrypt(items.ToArray(), level, len, toName, outOverride, ConsoleLog, MakeCliProgress(), out outp);
                    ConsoleLog("密碼：" + pw, 1);
                    ConsoleLog("完成：" + outp, 1);
                    return 0;
                }
                catch (Exception ex)
                {
                    ConsoleLog("失敗：" + ex.Message, 2);
                    return 1;
                }
            }

            // CLI：<路徑> <收件人> [xz|zstd|store]
            // 收件人判定：第二個參數不是既有路徑，且含 @ 或為十六進位 KeyID
            bool looksCli = false;
            if (a.Count >= 2 && !Directory.Exists(a[1]) && !File.Exists(a[1])
                && (a[1].IndexOf('@') >= 0 || Regex.IsMatch(a[1], "^[0-9A-Fa-f]{8,40}$")))
            {
                looksCli = true;
            }
            if (looksCli || (hadCliPrefix && a.Count > 0))
            {
                AttachCliConsole();
                if (GpgExe.Length == 0) { Console.WriteLine("找不到 gpg.exe，請先安裝 GnuPG（Gpg4win）。"); return 2; }
                if (a.Count < 2) { Console.WriteLine(Usage()); return 2; }
                string mode = "xz";
                if (a.Count >= 3)
                {
                    mode = a[2].ToLowerInvariant();
                    if (mode == "tar" || mode == "none") mode = "store";
                    if (!CompSuffix.ContainsKey(mode))
                    {
                        Console.WriteLine("未知壓縮模式：" + a[2] + "（可選 xz、zstd、store）");
                        return 2;
                    }
                    if (mode == "zstd" && !ZstdOk)
                    {
                        Console.WriteLine("本機 tar.exe 的 zstd 串流寫出後無法讀回（bsdtar 已知問題），請使用 xz 或 store（僅打包）。");
                        return 2;
                    }
                }
                string outp = GetOutputPath(a[0], mode);
                try
                {
                    EncryptInput(a[0], a[1], outp, mode, ConsoleLog, MakeCliProgress());
                    ConsoleLog("完成：" + outp, 1);
                    return 0;
                }
                catch (Exception ex)
                {
                    ConsoleLog("失敗：" + ex.Message, 2);
                    return 1;
                }
            }

            // 圖形介面（無參數或拖放項目）
            FreeConsole();
            Application.EnableVisualStyles();
            Application.Run(new MainForm(a));
            return 0;
        }

        private static string Usage()
        {
            return "用法：PGPEncrypt.exe <資料夾或檔案> <收件人KeyID或Email> [xz|zstd|store]\r\n" +
                   "      PGPEncrypt.exe -combine <輸出檔> <收件人> [xz|zstd|store] <項目...>\r\n" +
                   "      PGPEncrypt.exe -pw [-len 位數] [-mx 等級] [-toname] [-out <輸出檔>] <項目...>\r\n" +
                   "      （不帶參數或拖放檔案時開啟圖形介面）";
        }

        private static void AttachCliConsole()
        {
            if (!AttachConsole(ATTACH_PARENT_PROCESS)) AllocConsole();
        }

        internal static void ConsoleLog(string msg, int kind)
        {
            // \r：覆寫命令列模式原地更新的進度百分比
            Console.WriteLine("\r[{0:HH:mm:ss}] {1}", DateTime.Now, msg);
        }

        // 命令列進度：每 0.3 秒原地更新百分比
        private static Action<int> MakeCliProgress()
        {
            DateTime last = DateTime.MinValue;
            int lastPct = -1;
            return delegate(int pct)
            {
                DateTime now = DateTime.Now;
                if (pct != lastPct && (now - last).TotalMilliseconds >= 300)
                {
                    last = now;
                    lastPct = pct;
                    Console.Write("\r{0,3}%", pct);
                }
            };
        }

        // ---------- 外部工具定位 ----------

        private static string FindGpgExe()
        {
            // 優先採用 GnuPG 標準安裝位置，避免 PATH 中混入 MSYS／其他發行版的 gpg
            foreach (string p in new string[]
            {
                @"C:\Program Files (x86)\GnuPG\bin\gpg.exe",
                @"C:\Program Files\GnuPG\bin\gpg.exe",
                @"C:\opt\GnuPG\bin\gpg.exe"
            })
            {
                if (File.Exists(p)) return p;
            }
            string pathEnv = Environment.GetEnvironmentVariable("PATH") ?? "";
            foreach (string dir in pathEnv.Split(';'))
            {
                string d = dir.Trim().Trim('"');
                if (d.Length == 0) continue;
                string c;
                try { c = Path.Combine(d, "gpg.exe"); } catch { continue; }
                if (File.Exists(c)) return c;
            }
            return "";
        }

        private static string FindTarExe()
        {
            string p = Path.Combine(Environment.SystemDirectory, "tar.exe");
            if (File.Exists(p)) return p;
            return "tar.exe";
        }

        // 7z.exe 定位：優先標準安裝位置，其次 Win11 內建（System32），最後掃 PATH
        private static string Find7ZipExe()
        {
            foreach (string p in new string[]
            {
                @"C:\Program Files\7-Zip\7z.exe",
                @"C:\Program Files (x86)\7-Zip\7z.exe",
                Path.Combine(Environment.SystemDirectory, "7z.exe")
            })
            {
                if (File.Exists(p)) return p;
            }
            string pathEnv = Environment.GetEnvironmentVariable("PATH") ?? "";
            foreach (string dir in pathEnv.Split(';'))
            {
                string d = dir.Trim().Trim('"');
                if (d.Length == 0) continue;
                string c;
                try { c = Path.Combine(d, "7z.exe"); } catch { continue; }
                if (File.Exists(c)) return c;
            }
            return "";
        }

        // ---------- 壓縮模式 ----------

        internal static string GetTarCompressArgs(string mode, bool verbose)
        {
            string a;
            if (!CompArgs.TryGetValue(mode, out a))
                throw new ApplicationException("未知壓縮模式：" + mode + "（可選 xz、zstd、store）");
            if (verbose)
            {
                // -v：tar 於 stderr 逐項列出已完成項目（每行「a <相對路徑>」），供進度估算
                a = a.Replace("-cJf -", "-cJvf -").Replace("-cf -", "-cvf -");
            }
            return a;
        }

        // 進度追蹤：tar 模式輪詢 -v 清單（tar 的 stderr 檔）比對預先走訪的項目大小；
        // 單一檔案模式以 gpg 輸出檔長度對輸入大小估算。
        internal class ProgressTracker
        {
            public Action<int> OnProgress;
            public long TotalBytes;
            public Dictionary<string, long> Entries;   // tar 模式：正規化路徑 -> 檔案大小
            public string TarErrFile;
            public string OutputFile;
            public string PercentLogFile;              // 7z 模式：進度輸出檔（輪詢檔尾百分比）
            private System.Threading.Timer timer;
            private HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            private long doneBytes;
            private long lastPos;
            private string pending = "";

            public void Start()
            {
                if (timer == null) timer = new System.Threading.Timer(Tick, null, 250, 250);
            }

            public void Stop()
            {
                if (timer != null) { timer.Dispose(); timer = null; }
                Report(100);
            }

            private void Tick(object state)
            {
                Report(Compute());
            }

            private void Report(int pct)
            {
                Action<int> cb = OnProgress;
                if (cb != null) { try { cb(pct); } catch { } }
            }

            private int Compute()
            {
                if (PercentLogFile != null) return ReadLastPercent();
                if (Entries != null && TarErrFile != null)
                {
                    ReadNewLines();
                    if (TotalBytes <= 0) return 0;
                    int pct = (int)(doneBytes * 100L / TotalBytes);
                    if (pct < 0) pct = 0;
                    if (pct > 99) pct = 99;
                    return pct;
                }
                if (OutputFile != null && TotalBytes > 0)
                {
                    try
                    {
                        FileInfo fi = new FileInfo(OutputFile);
                        if (!fi.Exists) return 0;
                        int pct = (int)(fi.Length * 100L / TotalBytes);
                        if (pct < 0) pct = 0;
                        if (pct > 95) pct = 95;
                        return pct;
                    }
                    catch { return 0; }
                }
                return 0;
            }

            // 7z -bsp1 的進度以 CR 原地覆寫（「  0%」…「100%」），只讀檔尾 4KB 找最後一個百分比
            private int ReadLastPercent()
            {
                try
                {
                    if (!File.Exists(PercentLogFile)) return 0;
                    using (FileStream fs = new FileStream(PercentLogFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                    {
                        long len = fs.Length;
                        if (len == 0) return 0;
                        int take = (int)Math.Min(len, 4096);
                        fs.Seek(len - take, SeekOrigin.Begin);
                        byte[] buf = new byte[take];
                        int n = fs.Read(buf, 0, take);
                        // 取尾段中最後一個百分比；7z 以 CR 原地覆寫進度，前面的數值是舊值
                        Match last = null;
                        for (Match m = Regex.Match(Encoding.Default.GetString(buf, 0, n), @"(\d{1,3})%"); m.Success; m = m.NextMatch()) last = m;
                        if (last == null) return 0;
                        int pct = int.Parse(last.Groups[1].Value);
                        if (pct < 0) pct = 0;
                        if (pct > 99) pct = 99;
                        return pct;
                    }
                }
                catch { return 0; }
            }

            // 增量讀取 tar 的 stderr（-v 清單），比對已完成的項目並累計位元組
            private void ReadNewLines()
            {
                try
                {
                    if (!File.Exists(TarErrFile)) return;
                    using (FileStream fs = new FileStream(TarErrFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                    {
                        if (fs.Length <= lastPos) return;
                        fs.Seek(lastPos, SeekOrigin.Begin);
                        byte[] buf = new byte[fs.Length - lastPos];
                        int n = fs.Read(buf, 0, buf.Length);
                        lastPos += n;
                        pending += Encoding.Default.GetString(buf, 0, n);
                    }
                    int idx = pending.LastIndexOf('\n');
                    if (idx < 0) return;
                    string chunk = pending.Substring(0, idx);
                    pending = pending.Substring(idx + 1);
                    foreach (string ln in chunk.Split('\n'))
                    {
                        string key = NormalizeEntry(ln);
                        if (key.Length == 0) continue;
                        long sz;
                        if (Entries.TryGetValue(key, out sz) && seen.Add(key)) doneBytes += sz;
                    }
                }
                catch { }
            }

            // bsdtar -v 每行為「a <相對路徑>」；統一斜線與大小寫供比對
            internal static string NormalizeEntry(string s)
            {
                s = s.Trim();
                if (s.StartsWith("a ")) s = s.Substring(2);
                s = s.Replace('\\', '/');
                while (s.EndsWith("/")) s = s.Substring(0, s.Length - 1);
                return s.ToLowerInvariant();
            }
        }

        // 預先走訪來源樹，建立 tar -v 項目比對索引（正規化相對路徑 -> 大小）
        internal static ProgressTracker BuildTarProgress(string[] sourcePaths)
        {
            ProgressTracker pt = new ProgressTracker();
            pt.Entries = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
            long total = 0;
            foreach (string source in sourcePaths)
            {
                string full = NormalizePath(source);
                string root = Path.GetFileName(full);
                if (File.Exists(full))
                {
                    long sz = new FileInfo(full).Length;
                    pt.Entries[ProgressTracker.NormalizeEntry(root)] = sz;
                    total += sz;
                }
                else if (Directory.Exists(full))
                {
                    total += WalkDirForProgress(full, root, pt.Entries);
                }
            }
            pt.TotalBytes = total;
            return pt;
        }

        private static long WalkDirForProgress(string dir, string relPrefix, Dictionary<string, long> entries)
        {
            long total = 0;
            entries[ProgressTracker.NormalizeEntry(relPrefix)] = 0;
            foreach (string f in Directory.GetFiles(dir))
            {
                long sz;
                try { sz = new FileInfo(f).Length; } catch { sz = 0; }
                entries[ProgressTracker.NormalizeEntry(relPrefix + "/" + Path.GetFileName(f))] = sz;
                total += sz;
            }
            foreach (string d in Directory.GetDirectories(dir))
            {
                total += WalkDirForProgress(d, relPrefix + "/" + Path.GetFileName(d), entries);
            }
            return total;
        }

        // 以與主流程相同的方式（cmd 重定向 stdout）實測 tar 的 zstd：寫出後必須能被 tar 讀回。
        // 部分 bsdtar 版本對 stdout 輸出會補零至 10240 位元組，導致 zstd 串流無法解壓。
        private static bool ProbeTarZstd()
        {
            string tmp = Path.Combine(Path.GetTempPath(), "tarzstd_" + Guid.NewGuid().ToString("N"));
            try
            {
                Directory.CreateDirectory(tmp);
                File.WriteAllText(Path.Combine(tmp, "probe.txt"), "probe");
                string zst = Path.Combine(tmp, "probe.tar.zst");
                string line = Q(TarExe) + " --zstd -cf - -C " + Q(tmp) + " probe.txt > " + Q(zst) + " 2> nul";
                RunCmdCapture(line);
                if (!File.Exists(zst) || new FileInfo(zst).Length == 0) return false;
                ProcessStartInfo psi = new ProcessStartInfo(TarExe, "-tf " + Q(zst));
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                using (Process p = Process.Start(psi))
                {
                    p.StandardOutput.ReadToEnd();
                    p.StandardError.ReadToEnd();
                    p.WaitForExit();
                    return p.ExitCode == 0;
                }
            }
            catch { return false; }
            finally { try { Directory.Delete(tmp, true); } catch { } }
        }

        // ---------- 通用輔助 ----------

        internal static string Q(string s) { return "\"" + s + "\""; }

        // 供 tar 的 -C 目錄參數使用：一般路徑直接加引號。
        // 若路徑以單一反斜線結尾（磁碟根目錄，如 E:\），引號內會出現 \"，
        // 該反斜線會被命令列解析規則視為跳脫字元，使這個引號不結束字串，
        // 於是 -C 的目錄參數會把後續的項目名稱一起吃掉，
        // tar 收不到任何封裝項目而報 "no files or directories specified"。
        // 結尾改成雙反斜線（E:\\）即可：解析結果仍是單一反斜線，語意不變。
        internal static string QDir(string d)
        {
            return "\"" + (d.EndsWith("\\") ? d + "\\" : d) + "\"";
        }

        internal static string NormalizePath(string p)
        {
            // 轉為絕對路徑並移除結尾反斜線（磁碟根目錄除外）
            string full = Path.GetFullPath(p);
            while (full.Length > 3 && full.EndsWith("\\")) full = full.Substring(0, full.Length - 1);
            return full;
        }

        internal static bool PathExists(string p)
        {
            return File.Exists(p) || Directory.Exists(p);
        }

        private static void TryDelete(string p)
        {
            try { if (File.Exists(p)) File.Delete(p); } catch { }
        }

        // 資料夾依壓縮模式輸出對應副檔名，檔案輸出 gpg；同名檔案已存在時附加序號，避免覆蓋舊備份
        internal static string GetOutputPath(string source, string mode)
        {
            string full = NormalizePath(source);
            string dir = Path.GetDirectoryName(full);
            string name = Path.GetFileName(full);
            string suffix = Directory.Exists(full) ? CompSuffix[mode] : ".gpg";
            return UniquePath(dir, name, suffix);
        }

        // 確保合併輸出使用與壓縮模式對應的副檔名，並保留既有檔案的自動序號保護
        internal static string GetCombinedOutputPath(string requested, string mode)
        {
            string suffix = CompSuffix[mode];
            string full = Path.GetFullPath(requested);
            if (!full.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)) full += suffix;
            if (!PathExists(full)) return full;
            return UniquePath(Path.GetDirectoryName(full),
                              Path.GetFileName(full).Substring(0, Path.GetFileName(full).Length - suffix.Length),
                              suffix);
        }

        // 同名檔案已存在時於主檔名後附加 _01、_02…，避免覆蓋舊備份
        private static string UniquePath(string dir, string name, string suffix)
        {
            string basePath = Path.Combine(dir, name + suffix);
            if (!PathExists(basePath)) return basePath;
            int i = 1;
            while (true)
            {
                string cand = Path.Combine(dir, name + "_" + i.ToString("D2") + suffix);
                if (!PathExists(cand)) return cand;
                i++;
            }
        }

        private static void RunCmdCapture(string line)
        {
            ProcessStartInfo psi = new ProcessStartInfo(
                Environment.GetEnvironmentVariable("ComSpec") ?? "cmd.exe",
                "/d /s /c \"" + line + "\"");
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            using (Process p = Process.Start(psi))
            {
                p.StandardOutput.ReadToEnd();
                p.StandardError.ReadToEnd();
                p.WaitForExit();
            }
        }

        // ---------- 加密核心 ----------

        // 以 cmd 原生管線串接 tar 與 gpg，明文封裝檔不落地。
        // 不以 .NET 重新導向管線搬運串流：實測該方式偶發使 gpg 收到的串流開頭
        // 被插入 UTF-8 BOM，導致解密端 tar 無法解壓。
        // 左側以暫存批次檔包裝 tar：@echo off 防止命令回顯進入管線，
        // %errorlevel% 於批次內執行期展開（哨兵檔記錄 tar 結束碼）。
        // 所有路徑參數經環境變數傳入，批次檔保持純 ASCII。
        internal static void TarEncrypt(string tarArguments, string recipient, string outputFile, ProgressTracker progress)
        {
            string ecFile = Path.GetTempFileName();
            string tarErr = Path.GetTempFileName();
            string leftCmd = Path.GetTempFileName();
            File.Delete(leftCmd);
            leftCmd += ".cmd";
            // gpg 內層停止重複壓縮（tar 串流已壓縮或選擇不壓縮）
            string gpgArgs = GpgArgsCommon + " --compress-level 0 --output " + Q(outputFile) +
                             " --sign --encrypt --recipient " + Q(recipient);
            StringBuilder b = new StringBuilder();
            b.AppendLine("@echo off");
            b.AppendLine(Q(TarExe) + " %PGPTAR% 2> " + Q(tarErr));
            b.AppendLine("> " + Q(ecFile) + " echo %errorlevel%");
            File.WriteAllText(leftCmd, b.ToString(), Encoding.ASCII);

            if (progress != null)
            {
                progress.TarErrFile = tarErr;
                progress.OutputFile = outputFile;
                progress.Start();
            }

            string line = Q(leftCmd) + " | " + Q(GpgExe) + " %PGPGPG%";
            ProcessStartInfo psi = new ProcessStartInfo(
                Environment.GetEnvironmentVariable("ComSpec") ?? "cmd.exe",
                "/d /s /c \"" + line + "\"");
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardError = true;
            psi.EnvironmentVariables["PGPTAR"] = tarArguments;
            psi.EnvironmentVariables["PGPGPG"] = gpgArgs;

            int gpgExit = -1;
            string errText = "";
            using (Process cmd = Process.Start(psi))
            {
                cmd.WaitForExit();
                try { errText = cmd.StandardError.ReadToEnd(); } catch { }
                gpgExit = cmd.ExitCode;
            }
            if (progress != null) progress.Stop();

            int tarExit = 1;
            try { tarExit = int.Parse(File.ReadAllText(ecFile).Trim()); }
            catch { }
            string tarMsg = "";
            try { tarMsg = File.ReadAllText(tarErr); } catch { }
            if (tarMsg.Length > 2000) tarMsg = tarMsg.Substring(tarMsg.Length - 2000);
            TryDelete(leftCmd);
            TryDelete(ecFile);
            TryDelete(tarErr);

            if (gpgExit != 0)
            {
                TryDelete(outputFile);
                throw new ApplicationException("GPG 加密或簽署失敗（結束碼 " + gpgExit + "）：" + errText.Trim());
            }
            if (tarExit != 0)
            {
                TryDelete(outputFile);
                string detail = tarMsg.Trim().Length > 0 ? "：" + tarMsg.Trim() : "";
                throw new ApplicationException("tar 壓縮失敗（結束碼 " + tarExit + "）" + detail);
            }
        }

        // 單一資料夾依壓縮模式封裝後加密與簽署
        internal static void CompressEncrypt(string sourcePath, string recipient, string outputFile, string mode, Action<string, int> log, Action<int> onProgress)
        {
            string full = NormalizePath(sourcePath);
            if (Regex.IsMatch(full, "^[A-Za-z]:\\\\?$"))
                throw new ApplicationException("無法加密磁碟根目錄，請選擇其下的子資料夾。");
            if (!Directory.Exists(full))
                throw new ApplicationException("來源不是有效資料夾：" + full);
            string parent = Path.GetDirectoryName(full);
            string name = Path.GetFileName(full);
            if (string.IsNullOrEmpty(parent))
                throw new ApplicationException("無法取得上層資料夾：" + full);
            log("壓縮、加密並簽署中：" + name, 0);
            ProgressTracker pt = null;
            if (onProgress != null)
            {
                pt = BuildTarProgress(new string[] { full });
                pt.OnProgress = onProgress;
            }
            TarEncrypt(GetTarCompressArgs(mode, true) + " -C " + QDir(parent) + " " + Q(name), recipient, outputFile, pt);
        }

        // 使用每個來源的上層路徑封裝，避免把絕對路徑與磁碟代號寫入封裝檔
        internal static void CombinedCompressEncrypt(string[] sourcePaths, string recipient, string outputFile, string mode, Action<string, int> log, Action<int> onProgress)
        {
            List<string> tarParts = new List<string>();
            tarParts.Add(GetTarCompressArgs(mode, true));
            List<string> entryNames = new List<string>();
            foreach (string source in sourcePaths)
            {
                string full = NormalizePath(source);
                if (Regex.IsMatch(full, "^[A-Za-z]:\\\\?$"))
                    throw new ApplicationException("無法合併磁碟根目錄，請選擇其下的資料夾或檔案。");
                if (!Directory.Exists(full) && !File.Exists(full))
                    throw new ApplicationException("來源不是有效資料夾或檔案：" + full);
                string parent = Path.GetDirectoryName(full);
                string name = Path.GetFileName(full);
                if (entryNames.Contains(name))
                    throw new ApplicationException("合併項目有重複名稱：" + name + "。請重新命名後再合併。");
                entryNames.Add(name);
                tarParts.Add("-C " + QDir(parent) + " " + Q(name));
            }
            log("合併 " + sourcePaths.Length + " 個項目並加密簽署中…", 0);
            ProgressTracker pt = null;
            if (onProgress != null)
            {
                pt = BuildTarProgress(sourcePaths);
                pt.OnProgress = onProgress;
            }
            TarEncrypt(string.Join(" ", tarParts.ToArray()), recipient, outputFile, pt);
        }

        // 單一檔案直接加密與簽署，避免為檔案額外建立 tar 封裝
        internal static void FileEncrypt(string sourcePath, string recipient, string outputFile, string mode, Action<string, int> log, Action<int> onProgress)
        {
            string full = NormalizePath(sourcePath);
            if (!File.Exists(full))
                throw new ApplicationException("來源不是有效檔案：" + full);
            log("加密並簽署檔案中：" + Path.GetFileName(full), 0);
            // store（不壓縮）模式：連 gpg 內層壓縮也停用，避免對已壓縮內容白費時間
            string compArgs = (mode == "store") ? " --compress-level 0" : "";
            string args = GpgArgsCommon + " --output " + Q(outputFile) +
                          " --sign --encrypt --recipient " + Q(recipient) + compArgs + " -- " + Q(full);
            // 檔案模式進度：以 gpg 輸出檔長度對輸入大小估算
            ProgressTracker pt = null;
            if (onProgress != null)
            {
                pt = new ProgressTracker();
                pt.OutputFile = outputFile;
                try { pt.TotalBytes = new FileInfo(full).Length; } catch { pt.TotalBytes = 0; }
                pt.OnProgress = onProgress;
                pt.Start();
            }
            ProcessStartInfo psi = new ProcessStartInfo(GpgExe, args);
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardError = true;
            int exit;
            string err;
            using (Process p = Process.Start(psi))
            {
                p.WaitForExit();
                err = p.StandardError.ReadToEnd();
                exit = p.ExitCode;
            }
            if (pt != null) pt.Stop();
            if (exit != 0)
            {
                TryDelete(outputFile);
                throw new ApplicationException("GPG 加密或簽署失敗（結束碼 " + exit + "）：" + err.Trim());
            }
        }

        // 依來源類型選擇封裝方式，讓 GUI 與命令列保持相同輸出規則
        internal static void EncryptInput(string sourcePath, string recipient, string outputFile, string mode, Action<string, int> log, Action<int> onProgress)
        {
            if (Directory.Exists(sourcePath))
                CompressEncrypt(sourcePath, recipient, outputFile, mode, log, onProgress);
            else if (File.Exists(sourcePath))
                FileEncrypt(sourcePath, recipient, outputFile, mode, log, onProgress);
            else
                throw new ApplicationException("來源不是有效資料夾或檔案：" + sourcePath);
        }

        // ---------- 密碼模式（7z AES-256） ----------

        internal const string PasswordChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        // 密碼一律以密碼學亂數產生，不用時間或 Random 之類可預測的種子。
        // 位元組大於等於 248（62 的最大完整倍數）時丟棄，避免取模造成的分布偏差。
        internal static string GeneratePassword(int length)
        {
            char[] c = new char[length];
            byte[] buf = new byte[256];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                int got = 0;
                while (got < length)
                {
                    rng.GetBytes(buf);
                    for (int i = 0; i < buf.Length && got < length; i++)
                    {
                        if (buf[i] >= 248) continue;
                        c[got++] = PasswordChars[buf[i] % PasswordChars.Length];
                    }
                }
            }
            return new string(c);
        }

        // -pw 模式輸出 <名稱>.7z（多項目時為「合併加密.7z」），與來源同一層；
        // 將密碼寫入檔名時改為 <名稱>（密碼：xxx）.7z
        internal static string GetPwOutputPath(string[] sourcePaths, string password, bool passwordInName)
        {
            string first = NormalizePath(sourcePaths[0]);
            string name = sourcePaths.Length == 1 ? Path.GetFileName(first) : "合併加密";
            if (passwordInName) name = name + "（密碼：" + password + "）";
            return GetPwOutputPath(Path.Combine(Path.GetDirectoryName(first), name));
        }

        // 補上 .7z 副檔名並套用不覆蓋序號；自訂輸出位置（-out）與預設命名共用此規則
        internal static string GetPwOutputPath(string requested)
        {
            string full = Path.GetFullPath(requested);
            string name = Path.GetFileName(full);
            if (name.EndsWith(".7z", StringComparison.OrdinalIgnoreCase)) name = name.Substring(0, name.Length - 3);
            return UniquePath(Path.GetDirectoryName(full), name, ".7z");
        }

        // 7z 密碼模式：由 7z 自行讀取來源、打包並以 AES-256 加密，不經 tar 與 GPG。
        // 多個項目以各自的完整路徑傳入，7z 會把每個項目的葉名稱放在壓縮檔根目錄，
        // 與合併模式相同，不會把磁碟代號與絕對路徑寫入壓縮檔。
        // -mhe=on 一併加密標頭，檔名清單也受密碼保護；-bsp2 讓進度走 stderr 供輪詢，
        // -bso0 關閉一般輸出，使重定向檔內只有進度與錯誤訊息。
        internal static string SevenZipEncrypt(string[] sourcePaths, int level, int passwordLength, bool passwordInName, string outputOverride, Action<string, int> log, Action<int> onProgress, out string outputFile)
        {
            if (SevenZipExe.Length == 0)
                throw new ApplicationException("找不到 7z.exe。請安裝 7-Zip，或改用 PGP 模式。");
            if (sourcePaths.Length == 0)
                throw new ApplicationException("至少需要一個要加密的項目。");
            if (level < 0) level = 0;
            if (level > 9) level = 9;
            if (passwordLength < 1) passwordLength = 1;
            if (passwordLength > 128) passwordLength = 128;

            List<string> resolved = new List<string>();
            List<string> entryNames = new List<string>();
            foreach (string s in sourcePaths)
            {
                string full = NormalizePath(s);
                if (Regex.IsMatch(full, "^[A-Za-z]:\\\\?$"))
                    throw new ApplicationException("無法加密磁碟根目錄，請選擇其下的子資料夾。");
                if (!Directory.Exists(full) && !File.Exists(full))
                    throw new ApplicationException("來源不是有效資料夾或檔案：" + full);
                string leaf = Path.GetFileName(full);
                if (entryNames.Contains(leaf))
                    throw new ApplicationException("項目有重複名稱：" + leaf + "。請重新命名後再處理。");
                entryNames.Add(leaf);
                resolved.Add(full);
            }

            string password = GeneratePassword(passwordLength);
            outputFile = outputOverride == null
                ? GetPwOutputPath(sourcePaths, password, passwordInName)
                : GetPwOutputPath(outputOverride);
            log("以 7z 加密中（" + resolved.Count + " 個項目）…", 0);

            string logFile = Path.GetTempFileName();
            ProgressTracker pt = null;
            if (onProgress != null)
            {
                pt = new ProgressTracker();
                pt.PercentLogFile = logFile;
                pt.OnProgress = onProgress;
                pt.Start();
            }

            StringBuilder b = new StringBuilder();
            b.Append("a -t7z -mhe=on -y -bso0 -bsp1 -mx").Append(level);
            // 密碼僅含 [A-Za-z0-9]，不需引號跳脫；7z 不支援自 stdin 讀取密碼，只能置於命令列
            b.Append(" -p").Append(password);
            b.Append(" \"").Append(outputFile).Append("\"");
            foreach (string p in resolved) b.Append(" \"").Append(p).Append("\"");
            // -bsp1 進度走 stdout，故以 cmd 重定向收集；7z 的錯誤訊息也一併進入同一檔
            string line = Q(SevenZipExe) + " " + b.ToString() + " > " + Q(logFile) + " 2>&1";

            int exit;
            ProcessStartInfo psi = new ProcessStartInfo(
                Environment.GetEnvironmentVariable("ComSpec") ?? "cmd.exe",
                "/d /s /c \"" + line + "\"");
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            using (Process p = Process.Start(psi))
            {
                p.WaitForExit();
                exit = p.ExitCode;
            }
            if (pt != null) pt.Stop();

            string errText = "";
            try { errText = File.ReadAllText(logFile, Encoding.Default); } catch { }

            // 失敗時刪除半成品；輸出路徑由 GetPwOutputPath 保證為不存在的新檔
            if (exit != 0) TryDelete(outputFile);
            TryDelete(logFile);

            if (exit != 0)
            {
                // 7z 的進度百分比沒有換行，訊息會黏在同一行；移除行內的百分比片段讓錯誤可讀
                errText = Regex.Replace(errText, @"\r[^\n]*?\d{1,3}%[^\n]*", "").Trim();
                string detail = errText.Trim();
                if (detail.Length > 2000) detail = detail.Substring(detail.Length - 2000);
                throw new ApplicationException("7z 加密失敗（結束碼 " + exit + "）" + (detail.Length > 0 ? "：" + detail : ""));
            }
            return password;
        }

        // 解析 gpg 金鑰清單，回傳可用於加密的公鑰（略過停用／過期金鑰）
        internal static List<GpgKey> GetRecipientKeys()
        {
            List<GpgKey> keys = new List<GpgKey>();
            if (GpgExe.Length == 0) return keys;
            ProcessStartInfo psi = new ProcessStartInfo(GpgExe, "--list-keys --with-colons");
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            using (Process p = Process.Start(psi))
            {
                string stdout = p.StandardOutput.ReadToEnd();
                p.StandardError.ReadToEnd();
                p.WaitForExit();
                GpgKey cur = null;
                foreach (string ln in stdout.Split('\n'))
                {
                    string line = ln.TrimEnd('\r');
                    if (line.Length == 0) continue;
                    string[] f = line.Split(':');
                    if (f[0] == "pub")
                    {
                        cur = null;
                        if (f.Length > 4 && !Regex.IsMatch(f[1], "[dei]"))
                        {
                            cur = new GpgKey();
                            cur.Id = f[4];
                            cur.Uid = f[4];
                            keys.Add(cur);
                        }
                    }
                    else if (f[0] == "uid" && cur != null && cur.Uid == cur.Id && f.Length > 5)
                    {
                        if (f[5].Length > 0) cur.Uid = f[5];
                    }
                }
            }
            return keys;
        }
    }

    internal class MainForm : Form
    {
        private ListBox lstFolders;
        private ComboBox cboKey;
        private ComboBox cboComp;
        private ComboBox cboMode;
        private ComboBox cboMx;
        private CheckBox chkCombine;
        private CheckBox chkPwName;
        private NumericUpDown numPwLen;
        private Label lblComp;
        private Label lblMx;
        private Label lblKey;
        private Label lblPwLen;
        private Button btnAdd;
        private Button btnAddFile;
        private Button btnRemove;
        private Button btnClear;
        private Button btnGo;
        private Label lblCount;
        private RichTextBox rtbLog;
        private ProgressBar progressBar;
        private readonly List<string> inputs = new List<string>();
        private readonly Dictionary<string, string> keyMap = new Dictionary<string, string>();
        private readonly Dictionary<string, string> compMap = new Dictionary<string, string>();
        private readonly Dictionary<string, int> mxMap = new Dictionary<string, int>();
        private bool busy;

        public MainForm(List<string> prefill)
        {
            Text = "資料夾與檔案 PGP 加密與簽署工具（tar + GPG）";
            ClientSize = new Size(694, 553);
            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            Font = new Font("Microsoft JhengHei UI", 9f);

            Label lblHint = new Label();
            lblHint.Text = "1. 將要加密的資料夾或檔案拖曳到下方清單（可多個）";
            Place(lblHint, 12, 12, 460, 20);

            lblCount = new Label();
            lblCount.Text = "已加入 0 個項目";
            lblCount.TextAlign = ContentAlignment.MiddleRight;
            Place(lblCount, 480, 12, 202, 20);

            lstFolders = new ListBox();
            lstFolders.SelectionMode = SelectionMode.MultiExtended;
            lstFolders.AllowDrop = true;
            lstFolders.HorizontalScrollbar = true;
            Place(lstFolders, 12, 36, 560, 160);
            lstFolders.DragEnter += DragEnterHandler;
            lstFolders.DragDrop += DragDropHandler;
            AllowDrop = true;
            DragEnter += DragEnterHandler;
            DragDrop += DragDropHandler;

            btnAdd = new Button();
            btnAdd.Text = "加入資料夾…";
            Place(btnAdd, 582, 36, 100, 28);
            btnAdd.Click += delegate
            {
                using (FolderBrowserDialog dlg = new FolderBrowserDialog())
                {
                    dlg.Description = "選擇要加密的資料夾";
                    if (dlg.ShowDialog(this) == DialogResult.OK) AddInputs(new string[] { dlg.SelectedPath });
                }
            };

            btnAddFile = new Button();
            btnAddFile.Text = "加入檔案…";
            Place(btnAddFile, 582, 70, 100, 28);
            btnAddFile.Click += delegate
            {
                using (OpenFileDialog dlg = new OpenFileDialog())
                {
                    dlg.Title = "選擇要加密的檔案";
                    dlg.Multiselect = true;
                    if (dlg.ShowDialog(this) == DialogResult.OK) AddInputs(dlg.FileNames);
                }
            };

            btnRemove = new Button();
            btnRemove.Text = "移除所選";
            Place(btnRemove, 582, 104, 100, 28);
            btnRemove.Click += delegate
            {
                if (busy) return;
                for (int i = lstFolders.SelectedIndices.Count - 1; i >= 0; i--)
                {
                    int idx = lstFolders.SelectedIndices[i];
                    inputs.RemoveAt(idx);
                    lstFolders.Items.RemoveAt(idx);
                }
                UpdateCount();
            };

            btnClear = new Button();
            btnClear.Text = "清空";
            Place(btnClear, 582, 138, 100, 28);
            btnClear.Click += delegate
            {
                if (busy) return;
                inputs.Clear();
                lstFolders.Items.Clear();
                UpdateCount();
            };

            chkCombine = new CheckBox();
            chkCombine.Text = "將清單中的所有項目合併為單一壓縮檔";
            Place(chkCombine, 12, 202, 360, 24);

            lblComp = new Label();
            lblComp.Text = "壓縮格式：";
            Place(lblComp, 384, 202, 78, 24);

            cboComp = new ComboBox();
            cboComp.DropDownStyle = ComboBoxStyle.DropDownList;
            Place(cboComp, 466, 202, 216, 26);

            // 加密方式切換：PGP 金鑰加密與 7z 密碼加密共用同一份清單與進度介面
            Label lblMode = new Label();
            lblMode.Text = "加密方式：";
            Place(lblMode, 12, 236, 78, 24);

            cboMode = new ComboBox();
            cboMode.DropDownStyle = ComboBoxStyle.DropDownList;
            Place(cboMode, 90, 236, 180, 26);
            cboMode.Items.Add("PGP 公鑰加密與簽署");
            cboMode.Items.Add("密碼加密（7z AES-256）");
            cboMode.SelectedIndex = 0;

            lblMx = new Label();
            lblMx.Text = "壓縮等級：";
            Place(lblMx, 278, 236, 66, 24);

            cboMx = new ComboBox();
            cboMx.DropDownStyle = ComboBoxStyle.DropDownList;
            Place(cboMx, 346, 236, 92, 26);
            mxMap["不壓縮（最快）"] = 0;
            mxMap["快速"] = 1;
            mxMap["標準"] = 5;
            mxMap["最大壓縮"] = 9;
            foreach (string k in new string[] { "不壓縮（最快）", "快速", "標準", "最大壓縮" }) cboMx.Items.Add(k);
            cboMx.SelectedIndex = 0;

            lblPwLen = new Label();
            lblPwLen.Text = "密碼位數：";
            Place(lblPwLen, 446, 236, 66, 24);

            numPwLen = new NumericUpDown();
            numPwLen.Minimum = 1;
            numPwLen.Maximum = 128;
            numPwLen.Value = 27;
            Place(numPwLen, 514, 236, 44, 26);

            chkPwName = new CheckBox();
            chkPwName.Text = "密碼寫入檔名";
            Place(chkPwName, 566, 236, 116, 24);

            lblKey = new Label();
            lblKey.Text = "2. 選擇加密對象（公鑰）";
            Place(lblKey, 12, 268, 670, 20);

            cboKey = new ComboBox();
            cboKey.DropDownStyle = ComboBoxStyle.DropDownList;
            Place(cboKey, 12, 292, 670, 26);

            btnGo = new Button();
            btnGo.Text = "開始加密並簽署";
            Place(btnGo, 12, 328, 670, 42);
            btnGo.Click += BtnGo_Click;
            AcceptButton = btnGo;

            progressBar = new ProgressBar();
            progressBar.Minimum = 0;
            progressBar.Maximum = 100;
            Place(progressBar, 12, 376, 670, 18);

            Label lblLog = new Label();
            lblLog.Text = "處理紀錄：";
            Place(lblLog, 12, 400, 670, 20);

            rtbLog = new RichTextBox();
            rtbLog.ReadOnly = true;
            rtbLog.BackColor = Color.White;
            Place(rtbLog, 12, 420, 670, 120);

            // 處理期間阻擋關閉（加密在背景執行緒進行，強制關閉會留下未完成的管線）
            FormClosing += delegate(object s, FormClosingEventArgs ev)
            {
                if (busy && ev.CloseReason == CloseReason.UserClosing)
                {
                    MessageBox.Show(this, "正在處理中，請等待完成後再關閉視窗。", "提示");
                    ev.Cancel = true;
                }
            };

            cboMode.SelectedIndexChanged += delegate { UpdateModeUi(); };

            LoadCompChoices();
            LoadKeys();
            UpdateModeUi();
            foreach (string p in prefill) AddInputs(new string[] { p });
            Log("請拖入資料夾或檔案後按「開始加密並簽署」。", 0);
        }

        // PGP 模式：壓縮格式與公鑰可選；密碼模式：壓縮等級、密碼位數與寫入檔名可選。
        // 合併勾選在兩種模式都適用：勾選時清單全部併為一個輸出檔，未勾選則逐項輸出。
        private void UpdateModeUi()
        {
            bool pw = cboMode.SelectedIndex == 1;
            bool has7z = Program.SevenZipExe.Length > 0;
            lblComp.Visible = !pw;
            cboComp.Visible = !pw;
            lblKey.Visible = !pw;
            cboKey.Visible = !pw;
            lblMx.Visible = pw;
            cboMx.Visible = pw;
            lblPwLen.Visible = pw;
            numPwLen.Visible = pw;
            chkPwName.Visible = pw;
            btnGo.Text = pw ? "開始加密（7z 密碼）" : "開始加密並簽署";
            if (pw && !has7z)
                Log("找不到 7z.exe。請安裝 7-Zip（或確認 Windows 內建版本存在），否則無法使用密碼模式。", 2);
        }

        private void Place(Control c, int x, int y, int w, int h)
        {
            c.Location = new Point(x, y);
            c.Size = new Size(w, h);
            Controls.Add(c);
        }

        // 壓縮格式選單：zstd 僅在本機 tar 實測可寫入並讀回時列出
        private void LoadCompChoices()
        {
            compMap["xz（高壓縮率，較慢）"] = "xz";
            cboComp.Items.Add("xz（高壓縮率，較慢）");
            if (Program.ZstdOk)
            {
                compMap["zstd（速度快，壓縮率中等）"] = "zstd";
                cboComp.Items.Add("zstd（速度快，壓縮率中等）");
            }
            compMap["不壓縮（僅打包 tar）"] = "store";
            cboComp.Items.Add("不壓縮（僅打包 tar）");
            cboComp.SelectedIndex = 0;
            if (!Program.ZstdOk)
                Log("本機 tar.exe 的 zstd 串流寫出後無法讀回（bsdtar 已知問題），已隱藏 zstd 選項。", 2);
        }

        // 載入金鑰圈中的公鑰
        private void LoadKeys()
        {
            foreach (GpgKey k in Program.GetRecipientKeys())
            {
                string disp = k.Uid + "  [" + k.Id + "]";
                keyMap[disp] = k.Id;
                cboKey.Items.Add(disp);
            }
            if (cboKey.Items.Count > 0)
            {
                cboKey.SelectedIndex = 0;
            }
            else
            {
                Log("金鑰圈中找不到可用公鑰。請先建立（gpg --full-generate-key）或匯入（gpg --import 公鑰檔）。", 2);
            }
        }

        private void Log(string msg, int kind)
        {
            string line = string.Format("[{0:HH:mm:ss}] {1}", DateTime.Now, msg);
            Color c = Color.Black;
            if (kind == 1) c = Color.Green;
            if (kind == 2) c = Color.Firebrick;
            rtbLog.SelectionStart = rtbLog.Text.Length;
            rtbLog.SelectionColor = c;
            rtbLog.AppendText(line + Environment.NewLine);
            rtbLog.ScrollToCaret();
            rtbLog.SelectionColor = rtbLog.ForeColor;
        }

        private void UpdateCount()
        {
            lblCount.Text = "已加入 " + inputs.Count + " 個項目";
        }

        private void LogThreadSafe(string msg, int kind)
        {
            try { BeginInvoke((Action)delegate { Log(msg, kind); }); } catch { }
        }

        private void SetProgress(int pct)
        {
            try
            {
                BeginInvoke((Action)delegate
                {
                    if (pct < progressBar.Minimum) pct = progressBar.Minimum;
                    if (pct > progressBar.Maximum) pct = progressBar.Maximum;
                    progressBar.Value = pct;
                });
            }
            catch { }
        }

        // 加入資料夾或檔案，並以完整路徑去重
        private void AddInputs(string[] paths)
        {
            foreach (string p0 in paths)
            {
                if (string.IsNullOrWhiteSpace(p0)) continue;
                string full;
                try { full = Program.NormalizePath(p0); }
                catch { Log("略過無效路徑：" + p0, 2); continue; }
                if (Directory.Exists(full) || File.Exists(full))
                {
                    if (!inputs.Contains(full))
                    {
                        inputs.Add(full);
                        lstFolders.Items.Add(full);
                        Log("已加入：" + full, 0);
                    }
                    else
                    {
                        Log("重複，略過：" + full, 0);
                    }
                }
                else
                {
                    Log("略過（找不到資料夾或檔案）：" + full, 2);
                }
            }
            UpdateCount();
        }

        private void DragEnterHandler(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop)) e.Effect = DragDropEffects.Copy;
        }

        private void DragDropHandler(object sender, DragEventArgs e)
        {
            if (busy) { Log("正在處理中，請稍候。", 2); return; }
            string[] paths = e.Data.GetData(DataFormats.FileDrop) as string[];
            if (paths != null && paths.Length > 0) AddInputs(paths);
        }

        private void BtnGo_Click(object sender, EventArgs e)
        {
            if (busy) return;
            if (inputs.Count == 0)
            {
                MessageBox.Show(this, "請先將要加密的資料夾或檔案加入清單。", "提示");
                return;
            }
            if (cboMode.SelectedIndex == 1) { BtnGoPw(); return; }
            string disp = cboKey.SelectedItem as string;
            string rid;
            if (disp == null || !keyMap.TryGetValue(disp, out rid))
            {
                MessageBox.Show(this, "請先選擇加密對象（公鑰）。", "提示");
                return;
            }
            string compMode;
            if (!compMap.TryGetValue(cboComp.SelectedItem as string ?? "", out compMode)) compMode = "xz";
            string compSuffix = Program.CompSuffix[compMode];
            string combinedOutput = null;
            if (chkCombine.Checked)
            {
                using (SaveFileDialog dlg = new SaveFileDialog())
                {
                    dlg.Title = "選擇合併壓縮檔的輸出位置";
                    dlg.InitialDirectory = Path.GetDirectoryName(inputs[0]);
                    dlg.FileName = "合併加密" + compSuffix;
                    dlg.Filter = "加密壓縮檔 (*" + compSuffix + ")|*" + compSuffix;
                    dlg.AddExtension = false;
                    if (dlg.ShowDialog(this) != DialogResult.OK) return;
                    combinedOutput = Program.GetCombinedOutputPath(dlg.FileName, compMode);
                }
            }
            busy = true;
            btnGo.Enabled = btnAdd.Enabled = btnAddFile.Enabled = btnRemove.Enabled = btnClear.Enabled = chkCombine.Enabled = cboComp.Enabled = cboMode.Enabled = false;
            progressBar.Value = 0;
            UseWaitCursor = true;
            bool doCombine = chkCombine.Checked;
            string[] items = inputs.ToArray();
            // 加密改在背景執行緒進行，UI 保持回應並即時更新進度條
            System.Threading.Thread worker = new System.Threading.Thread(delegate()
            {
                try
                {
                    if (doCombine)
                    {
                        try
                        {
                            Program.CombinedCompressEncrypt(items, rid, combinedOutput, compMode, LogThreadSafe, SetProgress);
                            LogThreadSafe("完成：" + combinedOutput, 1);
                        }
                        catch (Exception ex)
                        {
                            LogThreadSafe("失敗：" + ex.Message, 2);
                        }
                    }
                    else
                    {
                        foreach (string p in items)
                        {
                            try
                            {
                                string outp = Program.GetOutputPath(p, compMode);
                                Program.EncryptInput(p, rid, outp, compMode, LogThreadSafe, SetProgress);
                                LogThreadSafe("完成：" + outp, 1);
                            }
                            catch (Exception ex)
                            {
                                LogThreadSafe("失敗：" + ex.Message, 2);
                            }
                        }
                    }
                    LogThreadSafe("全部處理完畢。", 1);
                }
                finally
                {
                    SetProgress(100);
                    try
                    {
                        BeginInvoke((Action)delegate
                        {
                            busy = false;
                            UseWaitCursor = false;
                            btnGo.Enabled = btnAdd.Enabled = btnAddFile.Enabled = btnRemove.Enabled = btnClear.Enabled = chkCombine.Enabled = cboComp.Enabled = cboMode.Enabled = true;
                        });
                    }
                    catch { }
                }
            });
            worker.IsBackground = true;
            worker.Start();
        }

        // 密碼模式：以密碼學亂數產生密碼，交給 7z 做 AES-256 對稱加密（不經 GPG，無簽署）
        private void BtnGoPw()
        {
            if (Program.SevenZipExe.Length == 0)
            {
                MessageBox.Show(this, "找不到 7z.exe。請安裝 7-Zip 後再使用密碼模式。", "缺少必要元件");
                return;
            }
            int level = mxMap[cboMx.SelectedItem as string ?? ""];
            int pwLen = (int)numPwLen.Value;
            bool toName = chkPwName.Checked;
            bool doCombine = chkCombine.Checked;
            busy = true;
            btnGo.Enabled = btnAdd.Enabled = btnAddFile.Enabled = btnRemove.Enabled = btnClear.Enabled = chkCombine.Enabled = cboMode.Enabled = cboMx.Enabled = numPwLen.Enabled = chkPwName.Enabled = false;
            progressBar.Value = 0;
            UseWaitCursor = true;
            string[] items = inputs.ToArray();
            System.Threading.Thread worker = new System.Threading.Thread(delegate()
            {
                try
                {
                    if (doCombine)
                    {
                        string outp;
                        string pw = Program.SevenZipEncrypt(items, level, pwLen, toName, null, LogThreadSafe, SetProgress, out outp);
                        LogThreadSafe("完成：" + outp, 1);
                        // 密碼只顯示在紀錄面板；關閉視窗後無法找回
                        LogThreadSafe("密碼：" + pw, 1);
                    }
                    else
                    {
                        foreach (string p in items)
                        {
                            try
                            {
                                string outp;
                                string pw = Program.SevenZipEncrypt(new string[] { p }, level, pwLen, toName, null, LogThreadSafe, SetProgress, out outp);
                                LogThreadSafe("完成：" + outp, 1);
                                LogThreadSafe("密碼：" + pw, 1);
                            }
                            catch (Exception ex)
                            {
                                LogThreadSafe("失敗：" + ex.Message, 2);
                            }
                        }
                    }
                    LogThreadSafe("全部處理完畢。", 1);
                }
                catch (Exception ex)
                {
                    LogThreadSafe("失敗：" + ex.Message, 2);
                }
                finally
                {
                    SetProgress(100);
                    try
                    {
                        BeginInvoke((Action)delegate
                        {
                            busy = false;
                            UseWaitCursor = false;
                            btnGo.Enabled = btnAdd.Enabled = btnAddFile.Enabled = btnRemove.Enabled = btnClear.Enabled = chkCombine.Enabled = cboMode.Enabled = cboMx.Enabled = numPwLen.Enabled = chkPwName.Enabled = true;
                        });
                    }
                    catch { }
                }
            });
            worker.IsBackground = true;
            worker.Start();
        }
    }
}
