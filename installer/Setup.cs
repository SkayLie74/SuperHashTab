using System;
using System.IO;
using System.Drawing;
using System.Diagnostics;
using System.Windows.Forms;
using System.Security.Principal;
using System.ComponentModel;
using System.Threading.Tasks;
using System.Reflection;
using System.Runtime.InteropServices;
using Microsoft.Win32;

// Assembly metadata for Setup.exe
[assembly: AssemblyTitle("SuperHashTab Setup")]
[assembly: AssemblyDescription("SuperHashTab Shell Extension Installation & Deployment Wizard")]
[assembly: AssemblyConfiguration("")]
[assembly: AssemblyCompany("SkayLie74")]
[assembly: AssemblyProduct("SuperHashTab")]
[assembly: AssemblyCopyright("Copyright © 2026 SkayLie74")]
[assembly: AssemblyTrademark("")]
[assembly: AssemblyCulture("")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]

namespace SuperHashTab.Installer
{
    public class SetupForm : Form
    {
        private Button btnInstall;
        private Button btnUninstall;
        private ProgressBar progressBar;
        private TextBox txtLog;
        private Label lblTitle;
        private Label lblSubtitle;
        private Panel pnlHeader;
        
        private string appDir = @"C:\Program Files\SuperHashTab";
        private string dllName = "SuperHashTab.dll";
        private string icoName = "SuperHashTab.ico";
        private string settingsName = "settings.ini";
        
        private bool isUninstallMode = false;
        private bool isSilentMode = false;
        private string lang = "en";
        
        public SetupForm(bool uninstallMode, bool silentMode)
        {
            this.isUninstallMode = uninstallMode;
            this.isSilentMode = silentMode;
            
            try
            {
                this.lang = System.Globalization.CultureInfo.CurrentUICulture.TwoLetterISOLanguageName.ToLower();
            }
            catch
            {
                this.lang = "en";
            }
            
            InitializeComponent();
            LoadFormIcon();
            
            if (isUninstallMode && !isSilentMode)
            {
                this.Load += (s, e) => RunAutoUninstall();
            }
        }
        
        private string T(string key)
        {
            if (lang == "tr")
            {
                switch (key)
                {
                    case "Title": return "SuperHashTab Kurulum Sihirbazı";
                    case "Subtitle": return "Kabuk Eklentisi Kurulum ve Dağıtımı";
                    case "Install": return "Kur / Güncelle";
                    case "Uninstall": return "Eklentiyi Kaldır";
                    case "Ready": return "Hazır. Kuruluma başlamak için 'Kur / Güncelle' butonuna tıklayın.";
                    case "ConfirmUninstall": return "SuperHashTab uygulamasını sisteminizden tamamen kaldırmak istediğinize emin misiniz?";
                    case "ConfirmTitle": return "Kaldırmayı Onayla";
                    case "AdminRequired": return "SuperHashTab kurulumu için yönetici hakları gereklidir.";
                    case "AdminTitle": return "Yönetici Yetkisi Gerekli";
                    case "StartInstall": return "SuperHashTab Kurulumu Başlatılıyor...";
                    case "ExplorerStopped": return "Windows Gezgini durduruldu (dosya kilitleri kaldırıldı).";
                    case "UnregisterLegacy": return "Eski COM bileşeni kaydı siliniyor...";
                    case "CopyFiles": return "Dosyalar hedef dizine kopyalanıyor: ";
                    case "Copied": return "Kopyalandı: ";
                    case "CopiedLocales": return "Çeviri dosyaları başarıyla kopyalandı.";
                    case "CopiedUninstaller": return "Kaldırıcı program başarıyla kopyalandı.";
                    case "RegisteringCom": return "DLL dosyası COM kayıt defterine kaydediliyor...";
                    case "RegisteringComSuccess": return "COM kaydı başarıyla tamamlandı!";
                    case "RegisteringComWarning": return "UYARI: COM kaydı uyarılarla tamamlandı.";
                    case "RegisteringAddRemove": return "Uygulama Windows Program Ekle/Kaldır listesine ekleniyor...";
                    case "RestartingExplorer": return "Windows Gezgini yeniden başlatılıyor...";
                    case "SuccessInstallMsg": return "SuperHashTab başarıyla kuruldu ve sisteme entegre edildi!";
                    case "SuccessInstallTitle": return "Kurulum Başarılı";
                    case "FailInstall": return "Kurulum başarısız oldu:\n";
                    case "FatalError": return "KRİTİK HATA: ";
                    case "StartUninstall": return "SuperHashTab Sistemden Kaldırılıyor...";
                    case "RemoveFiles": return "Kurulum dosyaları temizleniyor...";
                    case "CleanRegistry": return "Kayıt Defteri kullanıcı ayarları temizlendi.";
                    case "SuccessUninstallMsg": return "SuperHashTab sisteminizden başarıyla kaldırıldı.";
                    case "SuccessUninstallTitle": return "Kaldırma Tamamlandı";
                    case "FailUninstall": return "Kaldırma işlemi başarısız oldu:\n";
                    case "ErrDllNotFound": return "HATA: SuperHashTab.dll dosyası bulunamadı: ";
                    case "ErrBuildFirst": return "Lütfen önce projeyi derleyin!";
                    case "ErrNoKey": return "Hata";
                }
            }
            
            switch (key)
            {
                case "Title": return "SuperHashTab Setup Wizard";
                case "Subtitle": return "Shell Extension Installation & Deployment";
                case "Install": return "Install / Update";
                case "Uninstall": return "Uninstall Extension";
                case "Ready": return "Ready. Click 'Install / Update' to begin installation.";
                case "ConfirmUninstall": return "Are you sure you want to completely uninstall SuperHashTab?";
                case "ConfirmTitle": return "Confirm Uninstall";
                case "AdminRequired": return "Administrator rights are required to install SuperHashTab.";
                case "AdminTitle": return "Admin Access Required";
                case "StartInstall": return "Starting SuperHashTab Installation...";
                case "ExplorerStopped": return "Windows Explorer stopped (file locks released).";
                case "UnregisterLegacy": return "Unregistering legacy COM component...";
                case "CopyFiles": return "Copying files to target directory: ";
                case "Copied": return "Copied: ";
                case "CopiedLocales": return "Copied locales translation directory.";
                case "CopiedUninstaller": return "Deployed uninstaller program.";
                case "RegisteringCom": return "Registering DLL with COM registry...";
                case "RegisteringComSuccess": return "COM registration successful!";
                case "RegisteringComWarning": return "WARNING: COM registration completed with potential warnings.";
                case "RegisteringAddRemove": return "Registering in Windows Add/Remove programs list...";
                case "RestartingExplorer": return "Restarting Windows Explorer shell...";
                case "SuccessInstallMsg": return "SuperHashTab has been successfully installed and registered!";
                case "SuccessInstallTitle": return "Installation Successful";
                case "FailInstall": return "Installation failed:\n";
                case "FatalError": return "FATAL ERROR: ";
                case "StartUninstall": return "Starting SuperHashTab Uninstallation...";
                case "RemoveFiles": return "Removing installation files...";
                case "CleanRegistry": return "Cleaned Registry user settings.";
                case "SuccessUninstallMsg": return "SuperHashTab has been successfully removed from your system.";
                case "SuccessUninstallTitle": return "Uninstall Complete";
                case "FailUninstall": return "Uninstallation failed:\n";
                case "ErrDllNotFound": return "ERROR: SuperHashTab.dll not found in: ";
                case "ErrBuildFirst": return "Please build the project first!";
                case "ErrNoKey": return "Error";
            }
            return key;
        }

        private void LoadFormIcon()
        {
            try
            {
                using (Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("SuperHashTab.ico"))
                {
                    if (stream != null)
                    {
                        this.Icon = new Icon(stream);
                    }
                }
            }
            catch { }
        }
        
        private void InitializeComponent()
        {
            this.Size = new Size(450, 480);
            this.Text = T("Title");
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.StartPosition = FormStartPosition.CenterScreen;
            this.BackColor = Color.White;
            this.Font = new Font("Segoe UI", 9f);
            
            // Header Panel
            pnlHeader = new Panel();
            pnlHeader.Location = new Point(0, 0);
            pnlHeader.Size = new Size(450, 75);
            pnlHeader.BackColor = Color.FromArgb(31, 41, 55);
            
            lblTitle = new Label();
            lblTitle.Text = "SuperHashTab";
            lblTitle.Font = new Font("Segoe UI", 16f, FontStyle.Bold);
            lblTitle.ForeColor = Color.White;
            lblTitle.Location = new Point(15, 12);
            lblTitle.Size = new Size(300, 30);
            
            lblSubtitle = new Label();
            lblSubtitle.Text = T("Subtitle");
            lblSubtitle.Font = new Font("Segoe UI", 9f, FontStyle.Italic);
            lblSubtitle.ForeColor = Color.FromArgb(156, 163, 175);
            lblSubtitle.Location = new Point(16, 42);
            lblSubtitle.Size = new Size(350, 20);
            
            pnlHeader.Controls.Add(lblTitle);
            pnlHeader.Controls.Add(lblSubtitle);
            this.Controls.Add(pnlHeader);
            
            // Install Button
            btnInstall = new Button();
            btnInstall.Text = T("Install");
            btnInstall.Location = new Point(20, 95);
            btnInstall.Size = new Size(190, 40);
            btnInstall.Font = new Font("Segoe UI", 10f, FontStyle.Bold);
            btnInstall.BackColor = Color.FromArgb(5, 150, 105);
            btnInstall.ForeColor = Color.White;
            btnInstall.FlatStyle = FlatStyle.Flat;
            btnInstall.FlatAppearance.BorderSize = 0;
            btnInstall.Cursor = Cursors.Hand;
            btnInstall.Click += BtnInstall_Click;
            this.Controls.Add(btnInstall);
            
            // Uninstall Button
            btnUninstall = new Button();
            btnUninstall.Text = T("Uninstall");
            btnUninstall.Location = new Point(225, 95);
            btnUninstall.Size = new Size(190, 40);
            btnUninstall.Font = new Font("Segoe UI", 10f, FontStyle.Bold);
            btnUninstall.BackColor = Color.FromArgb(220, 38, 38);
            btnUninstall.ForeColor = Color.White;
            btnUninstall.FlatStyle = FlatStyle.Flat;
            btnUninstall.FlatAppearance.BorderSize = 0;
            btnUninstall.Cursor = Cursors.Hand;
            btnUninstall.Click += BtnUninstall_Click;
            this.Controls.Add(btnUninstall);
            
            // Progress Bar
            progressBar = new ProgressBar();
            progressBar.Location = new Point(20, 155);
            progressBar.Size = new Size(395, 18);
            progressBar.Style = ProgressBarStyle.Continuous;
            this.Controls.Add(progressBar);
            
            // Logs TextBox
            txtLog = new TextBox();
            txtLog.Multiline = true;
            txtLog.ReadOnly = true;
            txtLog.ScrollBars = ScrollBars.Vertical;
            txtLog.Location = new Point(20, 190);
            txtLog.Size = new Size(395, 230);
            txtLog.BackColor = Color.FromArgb(249, 250, 251);
            txtLog.ForeColor = Color.FromArgb(55, 65, 81);
            txtLog.Font = new Font("Consolas", 9f);
            txtLog.BorderStyle = BorderStyle.FixedSingle;
            this.Controls.Add(txtLog);
            
            Log(T("Ready"));
        }
        
        private void Log(string message)
        {
            if (isSilentMode) return;
            txtLog.AppendText("[" + DateTime.Now.ToString("HH:mm:ss") + "] " + message + Environment.NewLine);
        }
        
        private void SetControlsEnabled(bool enabled)
        {
            btnInstall.Enabled = enabled;
            btnUninstall.Enabled = enabled;
        }

        private string GetRegAsmPath()
        {
            string path64 = @"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe";
            string path32 = @"C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe";
            return File.Exists(path64) ? path64 : path32;
        }

        private long ExtractEmbeddedFiles()
        {
            long totalBytesWritten = 0;
            Assembly assembly = Assembly.GetExecutingAssembly();
            
            // Extract SuperHashTab.dll
            string targetDll = Path.Combine(appDir, dllName);
            totalBytesWritten += ExtractResource(assembly, "SuperHashTab.dll", targetDll);
            Log(T("Copied") + dllName);
            
            // Extract SuperHashTab.ico
            string targetIco = Path.Combine(appDir, icoName);
            totalBytesWritten += ExtractResource(assembly, "SuperHashTab.ico", targetIco);
            Log(T("Copied") + icoName);
            
            // Extract settings.ini (if not exists)
            string targetSettings = Path.Combine(appDir, settingsName);
            if (!File.Exists(targetSettings))
            {
                totalBytesWritten += ExtractResource(assembly, "settings.ini", targetSettings);
                Log(T("Copied") + settingsName);
            }
            
            // Create locales directory
            string localesDir = Path.Combine(appDir, "locales");
            if (!Directory.Exists(localesDir))
            {
                Directory.CreateDirectory(localesDir);
            }
            
            // Extract locale json files
            string[] locales = new string[] { "de", "en", "es", "fr", "it", "ja", "ko", "pt", "ru", "tr", "zh" };
            foreach (var langCode in locales)
            {
                string resName = "locales." + langCode + ".json";
                string destPath = Path.Combine(localesDir, langCode + ".json");
                totalBytesWritten += ExtractResource(assembly, resName, destPath);
            }
            Log(T("CopiedLocales"));
            
            // Copy ourselves (SuperHashTab_Setup.exe) to target folder
            string currentExePath = assembly.Location;
            string targetExePath = Path.Combine(appDir, "SuperHashTab_Setup.exe");
            File.Copy(currentExePath, targetExePath, true);
            totalBytesWritten += new FileInfo(targetExePath).Length;
            Log(T("CopiedUninstaller"));
            
            return totalBytesWritten;
        }

        private long ExtractResource(Assembly assembly, string resourceName, string destPath)
        {
            using (Stream stream = assembly.GetManifestResourceStream(resourceName))
            {
                if (stream == null)
                {
                    throw new Exception("Embedded resource not found: " + resourceName);
                }
                using (FileStream fs = new FileStream(destPath, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    stream.CopyTo(fs);
                    return fs.Length;
                }
            }
        }

        private void RegisterInAddRemovePrograms(long totalSizeBytes)
        {
            try
            {
                string uninstallKeyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SuperHashTab";
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(uninstallKeyPath))
                {
                    if (key != null)
                    {
                        key.SetValue("DisplayName", "SuperHashTab", RegistryValueKind.String);
                        key.SetValue("DisplayVersion", "1.0.0", RegistryValueKind.String);
                        key.SetValue("Publisher", "SkayLie74", RegistryValueKind.String);
                        key.SetValue("DisplayIcon", Path.Combine(appDir, icoName), RegistryValueKind.String);
                        key.SetValue("UninstallString", "\"" + Path.Combine(appDir, "SuperHashTab_Setup.exe") + "\" /uninstall", RegistryValueKind.String);
                        key.SetValue("QuietUninstallString", "\"" + Path.Combine(appDir, "SuperHashTab_Setup.exe") + "\" /uninstall /silent", RegistryValueKind.String);
                        key.SetValue("InstallLocation", appDir, RegistryValueKind.String);
                        
                        int sizeInKB = (int)(totalSizeBytes / 1024);
                        key.SetValue("EstimatedSize", sizeInKB, RegistryValueKind.DWord);
                    }
                }
            }
            catch (Exception ex)
            {
                Log("Warning: Could not register in Add/Remove programs: " + ex.Message);
            }
        }

        private void UnregisterFromAddRemovePrograms()
        {
            try
            {
                string uninstallKeyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(uninstallKeyPath, true))
                {
                    if (key != null)
                    {
                        key.DeleteSubKeyTree("SuperHashTab", false);
                    }
                }
            }
            catch (Exception ex)
            {
                Log("Warning: Could not unregister from Add/Remove programs: " + ex.Message);
            }
        }

        private void SelfDestructAndCleanup()
        {
            try
            {
                string cmd = "cmd.exe";
                string args = "/C timeout /T 2 /NOBREAK & rmdir /S /Q \"" + appDir + "\"";
                ProcessStartInfo psi = new ProcessStartInfo(cmd, args)
                {
                    CreateNoWindow = true,
                    UseShellExecute = false
                };
                Process.Start(psi);
            }
            catch { }
        }
        
        private async void BtnInstall_Click(object sender, EventArgs e)
        {
            SetControlsEnabled(false);
            progressBar.Value = 0;
            txtLog.Clear();
            
            try
            {
                Log(T("StartInstall"));
                progressBar.Value = 10;
                
                progressBar.Value = 20;
                await Task.Run(() => KillExplorer());
                Log(T("ExplorerStopped"));
                
                progressBar.Value = 35;
                string targetDll = Path.Combine(appDir, dllName);
                if (File.Exists(targetDll))
                {
                    Log(T("UnregisterLegacy"));
                    await Task.Run(() => RunRegAsm(targetDll, false));
                }
                
                progressBar.Value = 50;
                Log(T("CopyFiles") + appDir);
                if (!Directory.Exists(appDir))
                {
                    Directory.CreateDirectory(appDir);
                }
                
                long totalBytesWritten = await Task.Run(() => ExtractEmbeddedFiles());
                
                progressBar.Value = 75;
                Log(T("RegisteringCom"));
                bool regResult = await Task.Run(() => RunRegAsm(targetDll, true));
                if (regResult)
                {
                    Log(T("RegisteringComSuccess"));
                }
                else
                {
                    Log(T("RegisteringComWarning"));
                }

                Log(T("RegisteringAddRemove"));
                RegisterInAddRemovePrograms(totalBytesWritten);
                
                progressBar.Value = 90;
                Log(T("RestartingExplorer"));
                await Task.Run(() => Process.Start("explorer.exe"));
                
                progressBar.Value = 100;
                Log(T("SuccessInstallTitle").ToUpper() + "!");
                MessageBox.Show(T("SuccessInstallMsg"), T("SuccessInstallTitle"), MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                Log(T("FatalError") + ex.Message);
                MessageBox.Show(T("FailInstall") + ex.Message, T("ErrNoKey"), MessageBoxButtons.OK, MessageBoxIcon.Error);
                try { Process.Start("explorer.exe"); } catch {}
            }
            finally
            {
                SetControlsEnabled(true);
            }
        }

        private async void RunAutoUninstall()
        {
            SetControlsEnabled(false);
            progressBar.Value = 0;
            txtLog.Clear();
            
            try
            {
                Log(T("StartUninstall"));
                progressBar.Value = 20;
                
                await Task.Run(() => KillExplorer());
                Log(T("ExplorerStopped"));
                
                progressBar.Value = 40;
                string targetDll = Path.Combine(appDir, dllName);
                if (File.Exists(targetDll))
                {
                    Log(T("UnregisterLegacy"));
                    await Task.Run(() => RunRegAsm(targetDll, false));
                }
                
                progressBar.Value = 70;
                Log(T("RemoveFiles"));
                if (Directory.Exists(appDir))
                {
                    foreach (string file in Directory.GetFiles(appDir))
                    {
                        if (!Path.GetFileName(file).Equals("SuperHashTab_Setup.exe", StringComparison.OrdinalIgnoreCase))
                        {
                            try { File.Delete(file); } catch { }
                        }
                    }
                    string localesDir = Path.Combine(appDir, "locales");
                    if (Directory.Exists(localesDir))
                    {
                        try { Directory.Delete(localesDir, true); } catch { }
                    }
                }
                
                try { Registry.CurrentUser.DeleteSubKeyTree(@"Software\SuperHashTab", false); } catch { }
                UnregisterFromAddRemovePrograms();
                Log(T("CleanRegistry"));
                
                progressBar.Value = 90;
                Log(T("RestartingExplorer"));
                await Task.Run(() => Process.Start("explorer.exe"));
                
                progressBar.Value = 100;
                Log(T("SuccessUninstallTitle").ToUpper() + "!");
                MessageBox.Show(T("SuccessUninstallMsg"), T("SuccessUninstallTitle"), MessageBoxButtons.OK, MessageBoxIcon.Information);
                
                SelfDestructAndCleanup();
                Application.Exit();
            }
            catch (Exception ex)
            {
                Log(T("FatalError") + ex.Message);
                MessageBox.Show(T("FailUninstall") + ex.Message, T("ErrNoKey"), MessageBoxButtons.OK, MessageBoxIcon.Error);
                try { Process.Start("explorer.exe"); } catch {}
                SetControlsEnabled(true);
            }
        }
        
        private async void BtnUninstall_Click(object sender, EventArgs e)
        {
            var confirm = MessageBox.Show(T("ConfirmUninstall"), T("ConfirmTitle"), MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (confirm == DialogResult.Yes)
            {
                RunAutoUninstall();
            }
        }

        public void RunSilentMode()
        {
            if (isUninstallMode)
            {
                try
                {
                    KillExplorer();
                    string targetDll = Path.Combine(appDir, dllName);
                    if (File.Exists(targetDll))
                    {
                        RunRegAsm(targetDll, false);
                    }
                    if (Directory.Exists(appDir))
                    {
                        foreach (string file in Directory.GetFiles(appDir))
                        {
                            if (!Path.GetFileName(file).Equals("SuperHashTab_Setup.exe", StringComparison.OrdinalIgnoreCase))
                            {
                                try { File.Delete(file); } catch { }
                            }
                        }
                        string localesDir = Path.Combine(appDir, "locales");
                        if (Directory.Exists(localesDir))
                        {
                            try { Directory.Delete(localesDir, true); } catch { }
                        }
                    }
                    try { Registry.CurrentUser.DeleteSubKeyTree(@"Software\SuperHashTab", false); } catch { }
                    UnregisterFromAddRemovePrograms();
                    Process.Start("explorer.exe");
                    SelfDestructAndCleanup();
                }
                catch { }
            }
        }
        
        private void KillExplorer()
        {
            foreach (var process in Process.GetProcessesByName("explorer"))
            {
                try
                {
                    process.Kill();
                    process.WaitForExit(3000);
                }
                catch { }
            }
        }
        
        private bool RunRegAsm(string dllPath, bool register)
        {
            string regasm = GetRegAsmPath();
            if (!File.Exists(regasm))
            {
                throw new FileNotFoundException("RegAsm.exe not found at: " + regasm);
            }
            
            string args = (register ? "/codebase " : "/unregister /silent ") + "\"" + dllPath + "\"";
            ProcessStartInfo psi = new ProcessStartInfo(regasm, args)
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            
            using (var proc = Process.Start(psi))
            {
                proc.WaitForExit();
                return proc.ExitCode == 0;
            }
        }
    }
    
    public static class Program
    {
        [STAThread]
        public static void Main(string[] args)
        {
            bool isUninstall = false;
            bool isSilent = false;
            
            foreach (string arg in args)
            {
                if (arg.Equals("/uninstall", StringComparison.OrdinalIgnoreCase) || 
                    arg.Equals("-uninstall", StringComparison.OrdinalIgnoreCase))
                {
                    isUninstall = true;
                }
                if (arg.Equals("/silent", StringComparison.OrdinalIgnoreCase) || 
                    arg.Equals("/quiet", StringComparison.OrdinalIgnoreCase) ||
                    arg.Equals("-silent", StringComparison.OrdinalIgnoreCase))
                {
                    isSilent = true;
                }
            }
            
            if (!IsAdministrator())
            {
                RestartAsAdmin(args);
                return;
            }
            
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            
            SetupForm form = new SetupForm(isUninstall, isSilent);
            if (isSilent)
            {
                form.RunSilentMode();
            }
            else
            {
                Application.Run(form);
            }
        }
        
        private static bool IsAdministrator()
        {
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        
        private static void RestartAsAdmin(string[] args)
        {
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = Process.GetCurrentProcess().MainModule.FileName;
            psi.Arguments = string.Join(" ", args);
            psi.Verb = "runas";
            psi.UseShellExecute = true;
            try
            {
                Process.Start(psi);
            }
            catch (Win32Exception)
            {
                string msg = "Administrator rights are required to install SuperHashTab.";
                string title = "Admin Access Required";
                try
                {
                    string systemLang = System.Globalization.CultureInfo.CurrentUICulture.TwoLetterISOLanguageName.ToLower();
                    if (systemLang == "tr")
                    {
                        msg = "SuperHashTab kurulumu için yönetici hakları gereklidir.";
                        title = "Yönetici Yetkisi Gerekli";
                    }
                }
                catch { }
                MessageBox.Show(msg, title, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }
    }
}
