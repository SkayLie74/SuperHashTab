using System;
using System.IO;
using System.Text;
using System.Drawing;
using System.Diagnostics;
using System.Threading;
using System.Windows.Forms;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Net;
using Microsoft.Win32;

namespace SuperHashTab
{
    public class HashTabControl : UserControl
    {
        private string sourceFilePath;
        private ListView listView;
        private GroupBox grpCompare;
        private TextBox txtCompare;
        private Label lblMatch;
        private Button btnCompareFile;
        private LinkLabel lnkSettings;
        private ProgressBar progressBar;
        private Label lblProgress;
        private Label lblSignature;
        private LinkLabel lblVirusTotal;

        private TableLayoutPanel pnlInfoGrid;
        private FlowLayoutPanel pnlForensic;
        private Label lblArch;
        private Label lblEntropy;

        private Thread calcThread;
        private CancellationTokenSource cts;
        private volatile bool isCalculating = false;

        // Shared ToolTip instances — created once, reused, disposed in Dispose()
        private ToolTip toolTipForensic = new ToolTip();
        private ToolTip toolTipSignature = new ToolTip();

        // Context menu items that should be disabled during hash calculation
        private MenuItem mnuSaveReport;
        private MenuItem mnuSaveHashFiles;

        // Active preferences
        private bool optLowercase = false;
        private string vtApiKey = "";
        private Dictionary<string, bool> enabledAlgos = new Dictionary<string, bool>();
        private Dictionary<string, string> calculatedHashes = new Dictionary<string, string>();

        public HashTabControl(string filePath)
        {
            this.sourceFilePath = filePath;
            LoadSettings();
            InitializeUI();
            
            this.Load += (s, e) => {
                StartCalculations();
                TryPasteFromClipboardOnLoad();
            };
        }

        private void LoadSettings()
        {
            try
            {
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\SuperHashTab"))
                {
                    optLowercase = (key != null && (int)key.GetValue("Lowercase", 0) == 1);
                    vtApiKey = key != null ? (string)key.GetValue("VirusTotalApiKey", "") : "";
                    
                    // Defaults: SHA-256 and MD5 enabled, others disabled
                    enabledAlgos["SHA-256"] = key == null || (int)key.GetValue("ShowSHA256", 1) == 1;
                    enabledAlgos["SHA-512"] = key != null && (int)key.GetValue("ShowSHA512", 0) == 1;
                    enabledAlgos["SHA-384"] = key != null && (int)key.GetValue("ShowSHA384", 0) == 1;
                    enabledAlgos["SHA3-256"] = key != null && (int)key.GetValue("ShowSHA3_256", 0) == 1;
                    enabledAlgos["SHA3-512"] = key != null && (int)key.GetValue("ShowSHA3_512", 0) == 1;
                    enabledAlgos["BLAKE2b"] = key != null && (int)key.GetValue("ShowBLAKE2b", 0) == 1;
                    enabledAlgos["BLAKE2s"] = key != null && (int)key.GetValue("ShowBLAKE2s", 0) == 1;
                    enabledAlgos["BLAKE3"] = key != null && (int)key.GetValue("ShowBLAKE3", 0) == 1;
                    enabledAlgos["MD5"] = key == null || (int)key.GetValue("ShowMD5", 1) == 1;
                    enabledAlgos["SHA-1"] = key != null && (int)key.GetValue("ShowSHA1", 0) == 1;
                    enabledAlgos["CRC32"] = key != null && (int)key.GetValue("ShowCRC32", 0) == 1;
                    enabledAlgos["SSDEEP"] = key != null && (int)key.GetValue("ShowSSDEEP", 0) == 1;
                    enabledAlgos["TLSH"] = key != null && (int)key.GetValue("ShowTLSH", 0) == 1;
                    enabledAlgos["ImpHash"] = key != null && (int)key.GetValue("ShowImpHash", 0) == 1;
                    enabledAlgos["Authentihash"] = key != null && (int)key.GetValue("ShowAuthentihash", 0) == 1;
                    enabledAlgos["RichPE Hash"] = key != null && (int)key.GetValue("ShowRichPEHash", 0) == 1;
                    enabledAlgos["Import Hash"] = key != null && (int)key.GetValue("ShowImportHash", 0) == 1;
                    enabledAlgos["PE256 (PE Header Hash)"] = key != null && (int)key.GetValue("ShowPE256", 0) == 1;
                    enabledAlgos["Icon MD5"] = key != null && (int)key.GetValue("ShowIconMD5", 0) == 1;
                    enabledAlgos["Section Hash (PE Section Hash)"] = key != null && (int)key.GetValue("ShowSectionHash", 0) == 1;
                }
            }
            catch
            {
                enabledAlgos["SHA-256"] = true;
                enabledAlgos["MD5"] = true;
            }
        }

        private void InitializeUI()
        {
            this.Size = new Size(360, 500);
            this.Font = new Font("Segoe UI", 9f);
            this.BackColor = Color.White;

            listView = new ListView();
            listView.Location = new Point(15, 10);
            listView.Size = new Size(330, 215);
            listView.View = View.Details;
            listView.FullRowSelect = true;
            listView.GridLines = false;
            listView.HeaderStyle = ColumnHeaderStyle.Nonclickable;
            listView.BorderStyle = BorderStyle.None;
            listView.OwnerDraw = true;

            listView.DrawColumnHeader += (s, e) => {
                using (var brush = new SolidBrush(Color.FromArgb(243, 244, 246))) {
                    e.Graphics.FillRectangle(brush, e.Bounds);
                }
                using (var pen = new Pen(Color.FromArgb(229, 231, 235))) {
                    e.Graphics.DrawLine(pen, e.Bounds.Left, e.Bounds.Bottom - 1, e.Bounds.Right, e.Bounds.Bottom - 1);
                }
                TextRenderer.DrawText(e.Graphics, e.Header.Text, new Font("Segoe UI", 9f, FontStyle.Bold), e.Bounds, Color.FromArgb(75, 85, 99), TextFormatFlags.VerticalCenter | TextFormatFlags.Left);
            };

            listView.DrawItem += (s, e) => { e.DrawDefault = false; };
            listView.DrawSubItem += (s, e) => {
                bool isSelected = e.Item.Selected;
                
                if (isSelected)
                {
                    using (var brush = new SolidBrush(Color.FromArgb(239, 246, 255))) {
                        e.Graphics.FillRectangle(brush, e.Bounds);
                    }
                    using (var pen = new Pen(Color.FromArgb(191, 219, 254))) {
                        e.Graphics.DrawRectangle(pen, e.Bounds.X, e.Bounds.Y, e.Bounds.Width - 1, e.Bounds.Height - 1);
                    }
                }
                else
                {
                    using (var brush = new SolidBrush(Color.White)) {
                        e.Graphics.FillRectangle(brush, e.Bounds);
                    }
                }

                if (e.ColumnIndex == 0)
                {
                    TextRenderer.DrawText(e.Graphics, e.SubItem.Text, new Font("Segoe UI", 9f, FontStyle.Bold), e.Bounds, Color.FromArgb(31, 41, 55), TextFormatFlags.VerticalCenter | TextFormatFlags.Left);
                }
                else
                {
                    TextRenderer.DrawText(e.Graphics, e.SubItem.Text, new Font("Consolas", 9f), e.Bounds, Color.FromArgb(55, 65, 81), TextFormatFlags.VerticalCenter | TextFormatFlags.Left);
                }
            };

            listView.Columns.Add(Locale.T("ColName"), 140);
            listView.Columns.Add(Locale.T("ColHash"), -2);

            // Populate initial ListView items dynamically based on settings
            AddEnabledListViewItems();

            // Handle Context Menu (Right-Click)
            ContextMenu listMenu = new ContextMenu();
            MenuItem mnuCopyValue = new MenuItem(Locale.T("MenuCopyValue"), (s, e) => {
                if (listView.SelectedItems.Count > 0)
                {
                    string val = listView.SelectedItems[0].SubItems[1].Text.Trim();
                    if (!string.IsNullOrEmpty(val) && !val.Contains("."))
                        Clipboard.SetText(val);
                }
            });
            MenuItem mnuCopyAll = new MenuItem(Locale.T("MenuCopyAll"), (s, e) => {
                StringBuilder sb = new StringBuilder();
                foreach (ListViewItem item in listView.Items)
                {
                    sb.AppendLine(item.Text + ": " + item.SubItems[1].Text);
                }
                Clipboard.SetText(sb.ToString());
            });
            mnuSaveReport = new MenuItem(Locale.T("MenuSaveReport"), (s, e) => SaveHashesToFile());
            mnuSaveHashFiles = new MenuItem(Locale.T("MenuSaveHashFiles"), (s, e) => SaveAsHashFiles());
            MenuItem mnuCopyMagnet = new MenuItem(Locale.T("MenuCopyMagnet"), (s, e) => CopyAsMagnetLink());
            MenuItem mnuSep = new MenuItem("-");
            MenuItem mnuSettings = new MenuItem(Locale.T("MenuSettings"), (s, e) => OpenSettingsDialog());
            MenuItem mnuSep2 = new MenuItem("-");
            MenuItem mnuThreatIntel = new MenuItem(Locale.T("MenuQueryOnline"));
            
            MenuItem mnuQueryVT = new MenuItem(Locale.T("MenuQueryVT", "VirusTotal ile Sorgula"), (s, e) => QueryThreatIntel("VT"));
            MenuItem mnuQueryHA = new MenuItem(Locale.T("MenuQueryHA", "Hybrid-Analysis ile Sorgula"), (s, e) => QueryThreatIntel("HA"));
            MenuItem mnuQueryOTX = new MenuItem(Locale.T("MenuQueryOTX", "AlienVault OTX Tehdit Raporu"), (s, e) => QueryThreatIntel("OTX"));
            MenuItem mnuQueryAnyRun = new MenuItem(Locale.T("MenuQueryAnyRun", "Any.Run Sandbox Analizi"), (s, e) => QueryThreatIntel("ANYRUN"));
            
            mnuThreatIntel.MenuItems.Add(mnuQueryVT);
            mnuThreatIntel.MenuItems.Add(mnuQueryHA);
            mnuThreatIntel.MenuItems.Add(mnuQueryOTX);
            mnuThreatIntel.MenuItems.Add(mnuQueryAnyRun);

            listMenu.MenuItems.Add(mnuCopyValue);
            listMenu.MenuItems.Add(mnuCopyAll);
            listMenu.MenuItems.Add(mnuSaveReport);
            listMenu.MenuItems.Add(mnuSaveHashFiles);
            listMenu.MenuItems.Add(mnuCopyMagnet);
            listMenu.MenuItems.Add(mnuSep2);
            listMenu.MenuItems.Add(mnuThreatIntel);
            listMenu.MenuItems.Add(mnuSep);
            listMenu.MenuItems.Add(mnuSettings);
            listView.ContextMenu = listMenu;

            this.Controls.Add(listView);

            progressBar = new ProgressBar();
            progressBar.Location = new Point(15, 230);
            progressBar.Size = new Size(330, 13);
            progressBar.Style = ProgressBarStyle.Continuous;
            this.Controls.Add(progressBar);
 
            lblProgress = new Label();
            lblProgress.Location = new Point(15, 247);
            lblProgress.Size = new Size(330, 18);
            lblProgress.Text = Locale.T("ProgressReady");
            lblProgress.ForeColor = Color.FromArgb(107, 114, 128);
            this.Controls.Add(lblProgress);
 
            // Hash Comparison UI GroupBox (starts at Y=255)
            grpCompare = new GroupBox();
            grpCompare.Text = Locale.T("CompareGroup");
            grpCompare.Location = new Point(15, 265);
            grpCompare.Size = new Size(330, 115);
            grpCompare.FlatStyle = FlatStyle.System;

            txtCompare = new TextBox();
            txtCompare.Location = new Point(15, 24);
            txtCompare.Size = new Size(300, 23);
            txtCompare.ForeColor = Color.FromArgb(156, 163, 175);
            txtCompare.Text = Locale.T("ComparePlaceholder");
            txtCompare.AllowDrop = true;

            txtCompare.Enter += (s, e) => {
                if (txtCompare.Text == Locale.T("ComparePlaceholder"))
                {
                    txtCompare.Text = "";
                    txtCompare.ForeColor = Color.FromArgb(31, 41, 55);
                }
            };
            txtCompare.Leave += (s, e) => {
                if (string.IsNullOrEmpty(txtCompare.Text))
                {
                    txtCompare.ForeColor = Color.FromArgb(156, 163, 175);
                    txtCompare.Text = Locale.T("ComparePlaceholder");
                }
            };
            txtCompare.TextChanged += (s, e) => PerformHashComparison();

            txtCompare.DragEnter += (s, e) => {
                if (e.Data.GetDataPresent(DataFormats.FileDrop)) e.Effect = DragDropEffects.Copy;
            };
            txtCompare.DragDrop += (s, e) => {
                string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
                if (files != null && files.Length > 0)
                {
                    CompareWithFile(files[0]);
                }
            };

            grpCompare.Controls.Add(txtCompare);

            lblMatch = new Label();
            lblMatch.Location = new Point(15, 54);
            lblMatch.Size = new Size(300, 20);
            lblMatch.Font = new Font("Segoe UI", 10f, FontStyle.Bold);
            lblMatch.TextAlign = ContentAlignment.MiddleCenter;
            grpCompare.Controls.Add(lblMatch);

            btnCompareFile = new Button();
            btnCompareFile.Text = Locale.T("CompareButton");
            btnCompareFile.Location = new Point(15, 78);
            btnCompareFile.Size = new Size(300, 26);
            btnCompareFile.FlatStyle = FlatStyle.System;
            btnCompareFile.Click += (s, e) => SelectAndCompareFile();
            grpCompare.Controls.Add(btnCompareFile);

            this.Controls.Add(grpCompare);

            // Forensic & Security Information Grid (starts at Y=385)
            pnlInfoGrid = new TableLayoutPanel();
            pnlInfoGrid.Location = new Point(15, 385);
            pnlInfoGrid.Size = new Size(330, 88);
            pnlInfoGrid.ColumnCount = 1;
            pnlInfoGrid.RowCount = 3;
            pnlInfoGrid.CellBorderStyle = TableLayoutPanelCellBorderStyle.Single;
            pnlInfoGrid.BackColor = Color.FromArgb(249, 250, 251);
            
            pnlInfoGrid.ColumnStyles.Clear();
            pnlInfoGrid.RowStyles.Clear();
            pnlInfoGrid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            pnlInfoGrid.RowStyles.Add(new RowStyle(SizeType.Absolute, 28f));
            pnlInfoGrid.RowStyles.Add(new RowStyle(SizeType.Absolute, 28f));
            pnlInfoGrid.RowStyles.Add(new RowStyle(SizeType.Absolute, 28f));

            // Row 1: FlowLayoutPanel containing Arch and Entropy labels
            pnlForensic = new FlowLayoutPanel();
            pnlForensic.Dock = DockStyle.Fill;
            pnlForensic.FlowDirection = FlowDirection.LeftToRight;
            pnlForensic.WrapContents = false;
            pnlForensic.BackColor = Color.Transparent;
            pnlForensic.Margin = new Padding(0);
            pnlForensic.Padding = new Padding(2, 2, 2, 2);

            lblArch = CreateForensicLabel("Arch: --");
            lblEntropy = CreateForensicLabel("Entropy: --");

            pnlForensic.Controls.Add(lblArch);
            pnlForensic.Controls.Add(lblEntropy);

            // Row 2: Digital Signature Status Label
            lblSignature = new Label();
            lblSignature.Dock = DockStyle.Fill;
            lblSignature.Font = new Font("Segoe UI", 8.5f, FontStyle.Bold);
            lblSignature.Text = Locale.T("SignatureChecking");
            lblSignature.ForeColor = Color.FromArgb(75, 85, 99);
            lblSignature.AutoEllipsis = true;
            lblSignature.TextAlign = ContentAlignment.MiddleLeft;
            lblSignature.Margin = new Padding(5, 0, 5, 0);
            lblSignature.BackColor = Color.Transparent;
            lblSignature.AutoSize = false;

            // Row 3: VirusTotal Fast LinkLabel API Query
            lblVirusTotal = new LinkLabel();
            lblVirusTotal.Dock = DockStyle.Fill;
            lblVirusTotal.Font = new Font("Segoe UI", 8.5f, FontStyle.Regular);
            lblVirusTotal.Text = Locale.T("VtWaiting");
            lblVirusTotal.LinkBehavior = LinkBehavior.HoverUnderline;
            lblVirusTotal.ActiveLinkColor = Color.FromArgb(37, 99, 235);
            lblVirusTotal.LinkColor = Color.FromArgb(29, 78, 216);
            lblVirusTotal.TextAlign = ContentAlignment.MiddleLeft;
            lblVirusTotal.Margin = new Padding(5, 0, 5, 0);
            lblVirusTotal.BackColor = Color.Transparent;
            lblVirusTotal.AutoSize = false;
            lblVirusTotal.LinkClicked += (s, e) => {
                if (lblVirusTotal.Text.Contains(Locale.T("VtNoKey").Replace("(Click)", "").Trim()))
                {
                    OpenSettingsDialog();
                }
                else
                {
                    if (calculatedHashes.ContainsKey("SHA-256"))
                    {
                        string sha256Val = calculatedHashes["SHA-256"];
                        Process.Start(new ProcessStartInfo("https://www.virustotal.com/gui/file/" + sha256Val) { UseShellExecute = true });
                    }
                }
            };

            pnlInfoGrid.Controls.Add(pnlForensic, 0, 0);
            pnlInfoGrid.Controls.Add(lblSignature, 0, 1);
            pnlInfoGrid.Controls.Add(lblVirusTotal, 0, 2);
            this.Controls.Add(pnlInfoGrid);

            lnkSettings = new LinkLabel();
            lnkSettings.Text = Locale.T("MenuSettings");
            lnkSettings.Location = new Point(275, 478);
            lnkSettings.Size = new Size(70, 20);
            lnkSettings.TextAlign = ContentAlignment.MiddleRight;
            lnkSettings.LinkBehavior = LinkBehavior.HoverUnderline;
            lnkSettings.ActiveLinkColor = Color.FromArgb(37, 99, 235);
            lnkSettings.LinkColor = Color.FromArgb(75, 85, 99);
            lnkSettings.LinkClicked += (s, e) => OpenSettingsDialog();
            this.Controls.Add(lnkSettings);

            // Subtle brand advertisement label
            LinkLabel lnkWebsite = new LinkLabel();
            lnkWebsite.Text = "SuperHashTab";
            lnkWebsite.Location = new Point(15, 478);
            lnkWebsite.Size = new Size(150, 20);
            lnkWebsite.TextAlign = ContentAlignment.MiddleLeft;
            lnkWebsite.LinkBehavior = LinkBehavior.HoverUnderline;
            lnkWebsite.ActiveLinkColor = Color.FromArgb(37, 99, 235);
            lnkWebsite.LinkColor = Color.FromArgb(75, 85, 99);
            lnkWebsite.LinkClicked += (s, e) => {
                try { Process.Start(new ProcessStartInfo("https://github.com/SkayLie74/SuperHashTab") { UseShellExecute = true }); } catch { }
            };
            this.Controls.Add(lnkWebsite);

            this.SizeChanged += (s, e) => {
                int width = this.Width;
                listView.Width = width - 30;
                progressBar.Width = width - 30;
                lblProgress.Width = width - 30;
                pnlInfoGrid.Width = width - 30;
                grpCompare.Width = width - 30;
                txtCompare.Width = grpCompare.Width - 30;
                lblMatch.Width = grpCompare.Width - 30;
                btnCompareFile.Width = grpCompare.Width - 30;
                lnkSettings.Left = width - 85;
            };
        }

        private Label CreateForensicLabel(string text)
        {
            Label lbl = new Label();
            lbl.Text = text;
            lbl.AutoSize = true;
            lbl.Font = new Font("Segoe UI", 8f, FontStyle.Bold);
            lbl.ForeColor = Color.FromArgb(75, 85, 99);
            lbl.Margin = new Padding(6, 4, 6, 4);
            lbl.TextAlign = ContentAlignment.MiddleLeft;
            return lbl;
        }

        private void AddEnabledListViewItems()
        {
            listView.Items.Clear();
            
            List<string> enabledList = new List<string>();
            foreach (var pair in enabledAlgos)
            {
                if (pair.Value)
                {
                    enabledList.Add(pair.Key);
                }
            }
            
            enabledList.Sort(StringComparer.OrdinalIgnoreCase);
            
            foreach (string algoName in enabledList)
            {
                AddListViewPlaceholder(algoName);
            }
        }

        private void AddListViewPlaceholder(string algoName)
        {
            ListViewItem item = new ListViewItem(algoName);
            item.SubItems.Add(Locale.T("Calculating"));
            listView.Items.Add(item);
        }

        private void TryPasteFromClipboardOnLoad()
        {
            try
            {
                if (Clipboard.ContainsText())
                {
                    string clipText = Clipboard.GetText().Trim();
                    if (IsValidHashFormat(clipText))
                    {
                        txtCompare.ForeColor = Color.FromArgb(31, 41, 55);
                        txtCompare.Text = clipText;
                        PerformHashComparison();
                    }
                }
            }
            catch { }
        }

        private bool IsValidHashFormat(string text)
        {
            if (string.IsNullOrEmpty(text)) return false;
            string clean = text.Trim();
            int len = clean.Length;

            if (clean.Contains(":") && clean.Split(':').Length == 3)
            {
                // Validate ssdeep hash format
                string[] parts = clean.Split(':');
                int val;
                if (int.TryParse(parts[0], out val))
                {
                    if (!string.IsNullOrEmpty(parts[1]) && !string.IsNullOrEmpty(parts[2]))
                    {
                        return true;
                    }
                }
            }

            if (len == 70)
            {
                // Validate TLSH format: T1 followed by 68 hex characters (case-insensitive)
                if (clean.StartsWith("T1", StringComparison.OrdinalIgnoreCase))
                {
                    for (int i = 2; i < len; i++)
                    {
                        char c = clean[i];
                        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                            return false;
                    }
                    return true;
                }
            }

            if (len == 8 || len == 16 || len == 32 || len == 40 || len == 64 || len == 96 || len == 128)
            {
                for (int i = 0; i < len; i++)
                {
                    char c = clean[i];
                    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                        return false;
                }
                return true;
            }

            return false;
        }

        private void StartCalculations()
        {
            if (isCalculating) return;

            calculatedHashes.Clear();
            AddEnabledListViewItems();
            
            progressBar.Value = 0;
            progressBar.Maximum = 100;
            lblProgress.Text = "0%";
            isCalculating = true;

            // Block copy report operations while calculating
            if (mnuSaveReport != null) mnuSaveReport.Enabled = false;
            if (mnuSaveHashFiles != null) mnuSaveHashFiles.Enabled = false;

            cts = new CancellationTokenSource();
            CancellationToken token = cts.Token;

            calcThread = new Thread(() => {
                try
                {
                    FileInfo fi = new FileInfo(sourceFilePath);
                    if (!fi.Exists)
                    {
                        throw new FileNotFoundException("Dosya bulunamadı.");
                    }

                    // Background thread: Shannon Entropy calculation
                    string entropyStatus;
                    double entropy = EntropyHelper.ComputeEntropy(sourceFilePath, out entropyStatus);
                    string shortEntropyStatus = "Low";
                    if (entropyStatus.Contains("High") || entropyStatus.Contains("Yüksek")) shortEntropyStatus = Locale.T("EntropyShortHigh");
                    else if (entropyStatus.Contains("Medium") || entropyStatus.Contains("Orta")) shortEntropyStatus = Locale.T("EntropyShortMed");
                    else shortEntropyStatus = Locale.T("EntropyShortLow");

                    this.BeginInvoke((MethodInvoker)delegate {
                        lblEntropy.Text = Locale.T("ForensicEntropy") + ": " + entropy.ToString("F2") + " (" + shortEntropyStatus + ")";
                        toolTipForensic.SetToolTip(lblEntropy, string.Format("Shannon Entropy: {0:F4}\n{1}", entropy, entropyStatus));
                    });

                    // Background thread: PE Parsing & Forensics
                    PEFile pe = new PEFile(sourceFilePath);
                    this.BeginInvoke((MethodInvoker)delegate {
                        if (pe.IsPE)
                        {
                            string machineName = pe.Is64Bit ? "x64" : "x86";
                            if (pe.Machine == 0xAA64) machineName = "ARM64";
                            else if (pe.Machine == 0x01c4) machineName = "ARM";
                            lblArch.Text = Locale.T("ForensicArch") + ": " + machineName;
                            
                            string subsystemName = "GUI";
                            if (pe.Subsystem == 3) subsystemName = "Console";
                            else if (pe.Subsystem == 1) subsystemName = "Native";
                            else if (pe.Subsystem == 9) subsystemName = "EFI Driver";
                            toolTipForensic.SetToolTip(lblArch, string.Format("Format: Portable Executable (PE)\nMachine: 0x{0:X4} ({1})\nSubsystem: {2}\nSections: {3}", pe.Machine, machineName, subsystemName, pe.NumberOfSections));
                        }
                        else
                        {
                            string ext = fi.Extension.ToUpper().TrimStart('.');
                            if (string.IsNullOrEmpty(ext)) ext = "RAW";
                            if (ext.Length > 12) ext = ext.Substring(0, 9) + "...";
                            lblArch.Text = Locale.T("FileType") + ": " + ext;
                            toolTipForensic.SetToolTip(lblArch, "Format: Non-PE File Object\nExtension: ." + fi.Extension.ToLower());
                        }
                    });

                    // Background thread: Verify digital signature in background
                    string signer;
                    var sigState = WinTrust.VerifySignatureState(sourceFilePath, out signer);
                    this.BeginInvoke((MethodInvoker)delegate {
                        if (sigState == WinTrust.SignatureState.Valid)
                        {
                            lblSignature.Text = Locale.T("SignatureValid", signer);
                            lblSignature.ForeColor = Color.FromArgb(5, 150, 105);
                            toolTipSignature.SetToolTip(lblSignature, "Valid Authenticode Digital Signature\nSigner: " + signer);
                        }
                        else if (sigState == WinTrust.SignatureState.Invalid)
                        {
                            lblSignature.Text = Locale.T("SignatureInvalid");
                            lblSignature.ForeColor = Color.FromArgb(220, 38, 38);
                            toolTipSignature.SetToolTip(lblSignature, "Digital Signature: Corrupted or Modified!");
                        }
                        else
                        {
                            lblSignature.Text = Locale.T("SignatureUnsigned");
                            lblSignature.ForeColor = Color.FromArgb(107, 114, 128);
                            toolTipSignature.SetToolTip(lblSignature, "File is not digitally signed.");
                        }
                    });

                    // Compute PE Forensics hashes in parallel background task
                    string sSdeepStr = "";
                    string tlshStr = "";
                    string impHashStr = "";
                    string authHashStr = "";
                    string richHashStr = "";
                    string importHashStr = "";
                    string pe256Str = "";
                    string iconMd5Str = "";
                    string secHashStr = "";

                    if (enabledAlgos["SSDEEP"]) sSdeepStr = SSDEEP.Compute(sourceFilePath);
                    if (enabledAlgos["TLSH"]) tlshStr = TLSH.Compute(sourceFilePath);
                    if (pe.IsPE)
                    {
                        if (enabledAlgos["ImpHash"]) impHashStr = PEHelper.GetImpHash(sourceFilePath, pe);
                        if (enabledAlgos["Authentihash"]) authHashStr = PEHelper.GetAuthentihash(sourceFilePath, pe);
                        if (enabledAlgos["RichPE Hash"]) richHashStr = PEHelper.GetRichPEHash(sourceFilePath, pe);
                        if (enabledAlgos["Import Hash"]) importHashStr = PEHelper.GetImportHash(sourceFilePath, pe);
                        if (enabledAlgos["PE256 (PE Header Hash)"]) pe256Str = PEHelper.GetPE256(sourceFilePath, pe);
                        if (enabledAlgos["Icon MD5"]) iconMd5Str = PEHelper.GetIconMD5(sourceFilePath);
                        if (enabledAlgos["Section Hash (PE Section Hash)"]) secHashStr = PEHelper.GetSectionHash(sourceFilePath, pe);
                    }

                    // Multi-algo cryptographic block calculations
                    long totalBytes = fi.Length;
                    
                    using (var fs = new FileStream(sourceFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                    {
                        // Initialize only enabled standard engines
                        CRC32 crc32 = enabledAlgos["CRC32"] ? new CRC32() : null;
                        MD5 md5 = enabledAlgos["MD5"] ? MD5.Create() : null;
                        SHA1 sha1 = enabledAlgos["SHA-1"] ? SHA1.Create() : null;
                        SHA256 sha256 = enabledAlgos["SHA-256"] ? SHA256.Create() : null;
                        SHA384 sha384 = enabledAlgos["SHA-384"] ? SHA384.Create() : null;
                        SHA512 sha512 = enabledAlgos["SHA-512"] ? SHA512.Create() : null;
                        SHA3 sha3_256 = enabledAlgos["SHA3-256"] ? new SHA3(256) : null;
                        SHA3 sha3_512 = enabledAlgos["SHA3-512"] ? new SHA3(512) : null;
                        Blake2b blake2b = enabledAlgos["BLAKE2b"] ? new Blake2b(512) : null;
                        Blake2s blake2s = enabledAlgos["BLAKE2s"] ? new Blake2s(256) : null;
                        Blake3 blake3 = enabledAlgos["BLAKE3"] ? new Blake3() : null;

                        byte[] buffer = new byte[1024 * 1024]; // 1MB buffer
                        int bytesRead;
                        long readBytesSoFar = 0;

                        while ((bytesRead = fs.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            if (token.IsCancellationRequested)
                            {
                                throw new OperationCanceledException();
                            }

                            // Transform block on all initialized standard algorithms
                            if (crc32 != null) crc32.TransformBlock(buffer, 0, bytesRead, null, 0);
                            if (md5 != null) md5.TransformBlock(buffer, 0, bytesRead, null, 0);
                            if (sha1 != null) sha1.TransformBlock(buffer, 0, bytesRead, null, 0);
                            if (sha256 != null) sha256.TransformBlock(buffer, 0, bytesRead, null, 0);
                            if (sha384 != null) sha384.TransformBlock(buffer, 0, bytesRead, null, 0);
                            if (sha512 != null) sha512.TransformBlock(buffer, 0, bytesRead, null, 0);
                            if (sha3_256 != null) sha3_256.TransformBlock(buffer, 0, bytesRead, null, 0);
                            if (sha3_512 != null) sha3_512.TransformBlock(buffer, 0, bytesRead, null, 0);
                            if (blake2b != null) blake2b.TransformBlock(buffer, 0, bytesRead, null, 0);
                            if (blake2s != null) blake2s.TransformBlock(buffer, 0, bytesRead, null, 0);
                            if (blake3 != null) blake3.TransformBlock(buffer, 0, bytesRead, null, 0);

                            readBytesSoFar += bytesRead;
                            int percent = totalBytes > 0 ? (int)((readBytesSoFar * 100) / totalBytes) : 100;
                            
                            this.BeginInvoke((MethodInvoker)delegate {
                                progressBar.Value = percent;
                                lblProgress.Text = percent + "%";
                            });
                        }

                        // Finalize
                        if (enabledAlgos["CRC32"]) crc32.TransformFinalBlock(new byte[0], 0, 0);
                        if (enabledAlgos["MD5"]) md5.TransformFinalBlock(new byte[0], 0, 0);
                        if (enabledAlgos["SHA-1"]) sha1.TransformFinalBlock(new byte[0], 0, 0);
                        if (enabledAlgos["SHA-256"]) sha256.TransformFinalBlock(new byte[0], 0, 0);
                        if (enabledAlgos["SHA-384"]) sha384.TransformFinalBlock(new byte[0], 0, 0);
                        if (enabledAlgos["SHA-512"]) sha512.TransformFinalBlock(new byte[0], 0, 0);
                        if (enabledAlgos["SHA3-256"]) sha3_256.TransformFinalBlock(new byte[0], 0, 0);
                        if (enabledAlgos["SHA3-512"]) sha3_512.TransformFinalBlock(new byte[0], 0, 0);
                        if (enabledAlgos["BLAKE2b"]) blake2b.TransformFinalBlock(new byte[0], 0, 0);
                        if (enabledAlgos["BLAKE2s"]) blake2s.TransformFinalBlock(new byte[0], 0, 0);
                        if (enabledAlgos["BLAKE3"]) blake3.TransformFinalBlock(new byte[0], 0, 0);

                        string crc32Str = enabledAlgos["CRC32"] ? FormatHash(crc32.Hash) : "";
                        string md5Str = enabledAlgos["MD5"] ? FormatHash(md5.Hash) : "";
                        string sha1Str = enabledAlgos["SHA-1"] ? FormatHash(sha1.Hash) : "";
                        string sha256Str = enabledAlgos["SHA-256"] ? FormatHash(sha256.Hash) : "";
                        string sha384Str = enabledAlgos["SHA-384"] ? FormatHash(sha384.Hash) : "";
                        string sha512Str = enabledAlgos["SHA-512"] ? FormatHash(sha512.Hash) : "";
                        string sha3_256Str = enabledAlgos["SHA3-256"] ? FormatHash(sha3_256.Hash) : "";
                        string sha3_512Str = enabledAlgos["SHA3-512"] ? FormatHash(sha3_512.Hash) : "";
                        string blake2bStr = enabledAlgos["BLAKE2b"] ? FormatHash(blake2b.Hash) : "";
                        string blake2sStr = enabledAlgos["BLAKE2s"] ? FormatHash(blake2s.Hash) : "";
                        string blake3Str = enabledAlgos["BLAKE3"] ? FormatHash(blake3.Hash) : "";

                        this.BeginInvoke((MethodInvoker)delegate {
                            // Update dynamic ListView using robust name-based lookups
                            if (enabledAlgos["SHA-256"]) UpdateListViewItem("SHA-256", sha256Str);
                            if (enabledAlgos["SHA-512"]) UpdateListViewItem("SHA-512", sha512Str);
                            if (enabledAlgos["SHA-384"]) UpdateListViewItem("SHA-384", sha384Str);
                            if (enabledAlgos["SHA3-256"]) UpdateListViewItem("SHA3-256", sha3_256Str);
                            if (enabledAlgos["SHA3-512"]) UpdateListViewItem("SHA3-512", sha3_512Str);
                            if (enabledAlgos["BLAKE2b"]) UpdateListViewItem("BLAKE2b", blake2bStr);
                            if (enabledAlgos["BLAKE2s"]) UpdateListViewItem("BLAKE2s", blake2sStr);
                            if (enabledAlgos["BLAKE3"]) UpdateListViewItem("BLAKE3", blake3Str);
                            if (enabledAlgos["MD5"]) UpdateListViewItem("MD5", md5Str);
                            if (enabledAlgos["SHA-1"]) UpdateListViewItem("SHA-1", sha1Str);
                            if (enabledAlgos["CRC32"]) UpdateListViewItem("CRC32", crc32Str);
                            if (enabledAlgos["SSDEEP"]) UpdateListViewItem("SSDEEP", sSdeepStr);
                            if (enabledAlgos["TLSH"]) UpdateListViewItem("TLSH", tlshStr);
                            if (enabledAlgos["ImpHash"]) UpdateListViewItem("ImpHash", impHashStr);
                            if (enabledAlgos["Authentihash"]) UpdateListViewItem("Authentihash", authHashStr);
                            if (enabledAlgos["RichPE Hash"]) UpdateListViewItem("RichPE Hash", richHashStr);
                            if (enabledAlgos["Import Hash"]) UpdateListViewItem("Import Hash", importHashStr);
                            if (enabledAlgos["PE256 (PE Header Hash)"]) UpdateListViewItem("PE256 (PE Header Hash)", pe256Str);
                            if (enabledAlgos["Icon MD5"]) UpdateListViewItem("Icon MD5", iconMd5Str);
                            if (enabledAlgos["Section Hash (PE Section Hash)"]) UpdateListViewItem("Section Hash (PE Section Hash)", secHashStr);

                            // Auto-fit column 1 (hashes) to prevent truncation, but keep column 0 at robust fixed width
                            listView.Columns[0].Width = 140;
                            listView.Columns[1].Width = -2;

                            // Force full repaint — prevents ghost items that only show on mouse hover
                            listView.Invalidate(true);
                            listView.Update();
                            this.Invalidate(true);

                            progressBar.Value = 100;
                            lblProgress.Text = Locale.T("ProgressDone");
                            isCalculating = false;

                            if (mnuSaveReport != null) mnuSaveReport.Enabled = true;
                            if (mnuSaveHashFiles != null) mnuSaveHashFiles.Enabled = true;

                            // Trigger comparison logic in case user pasted hash beforehand
                            PerformHashComparison();

                            // Query VirusTotal database report in background thread if SHA-256 computed
                            if (enabledAlgos["SHA-256"])
                            {
                                QueryVirusTotalReport(sha256Str);
                            }
                            else
                            {
                                lblVirusTotal.Text = "VirusTotal: SHA-256 hash not computed";
                            }
                        });
                    }
                }
                catch (OperationCanceledException)
                {
                    this.BeginInvoke((MethodInvoker)delegate {
                        lblProgress.Text = "Canceled";
                        isCalculating = false;
                    });
                }
                catch (Exception ex)
                {
                    this.BeginInvoke((MethodInvoker)delegate {
                        lblProgress.Text = Locale.T("ProgressError");
                        MessageBox.Show(Locale.T("MsgHashCalculationError", ex.Message), "Hata", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        isCalculating = false;
                    });
                }
            });
            calcThread.Name = "SuperHashTabCalculationThread";
            calcThread.IsBackground = true;
            calcThread.Start();
        }

        private string FormatHash(byte[] bytes)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < bytes.Length; i++)
            {
                sb.Append(bytes[i].ToString(optLowercase ? "x2" : "X2"));
            }
            return sb.ToString();
        }

        private void UpdateListViewItem(string algoName, string hashValue)
        {
            // Robust name-based lookups — prevents index mapping issues
            foreach (ListViewItem item in listView.Items)
            {
                if (item.Text == algoName)
                {
                    item.SubItems[1].Text = hashValue;
                    calculatedHashes[algoName] = hashValue;
                    break;
                }
            }
        }

        private string FormatFileSize(long bytes)
        {
            string[] suffixes = { "B", "KB", "MB", "GB", "TB" };
            double val = bytes;
            int i = 0;
            while (val >= 1024 && i < suffixes.Length - 1)
            {
                val /= 1024;
                i++;
            }
            return string.Format("{0:F2} {1}", val, suffixes[i]);
        }

        private void PerformHashComparison()
        {
            string target = txtCompare.Text.Trim();
            if (string.IsNullOrEmpty(target) || target == Locale.T("ComparePlaceholder"))
            {
                lblMatch.Text = "";
                lblMatch.BackColor = Color.Transparent;
                return;
            }

            bool isMatch = false;
            foreach (ListViewItem item in listView.Items)
            {
                string calculated = item.SubItems[1].Text.Trim();
                if (string.IsNullOrEmpty(calculated) || calculated == Locale.T("Calculating"))
                    continue;

                if (calculated.Equals(target, StringComparison.OrdinalIgnoreCase))
                {
                    isMatch = true;
                    break;
                }
            }

            if (isMatch)
            {
                lblMatch.Text = Locale.T("MsgComparisonMatch");
                lblMatch.ForeColor = Color.White;
                lblMatch.BackColor = Color.FromArgb(16, 185, 129); // Modern Emerald Green
            }
            else
            {
                lblMatch.Text = Locale.T("MsgComparisonMismatch");
                lblMatch.ForeColor = Color.White;
                lblMatch.BackColor = Color.FromArgb(239, 68, 68); // Modern Rose Red
            }
        }

        private void SelectAndCompareFile()
        {
            using (OpenFileDialog ofd = new OpenFileDialog())
            {
                ofd.Title = Locale.T("CompareButton");
                ofd.Filter = "All Files (*.*)|*.*";
                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    CompareWithFile(ofd.FileName);
                }
            }
        }

        private void CompareWithFile(string filePath)
        {
            if (string.IsNullOrEmpty(filePath)) return;
            if (filePath.Equals(sourceFilePath, StringComparison.OrdinalIgnoreCase))
            {
                MessageBox.Show(Locale.T("MsgSameFileCompare"), Locale.T("MsgSameFileTitle"), MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            // Create a premium, clean progress window
            Form progForm = new Form();
            progForm.Text = Locale.T("MsgCompareTaskName");
            progForm.Size = new Size(300, 100);
            progForm.FormBorderStyle = FormBorderStyle.FixedDialog;
            progForm.StartPosition = FormStartPosition.CenterParent;
            progForm.ControlBox = false;

            ProgressBar pb = new ProgressBar();
            pb.Location = new Point(20, 20);
            pb.Size = new Size(245, 20);
            pb.Style = ProgressBarStyle.Marquee;
            progForm.Controls.Add(pb);

            // Fetch the largest enabled cryptographic standard algorithm for comparison
            string bestAlgo = "SHA-256";
            if (enabledAlgos.ContainsKey("SHA-256") && enabledAlgos["SHA-256"]) bestAlgo = "SHA-256";
            else if (enabledAlgos.ContainsKey("SHA-1") && enabledAlgos["SHA-1"]) bestAlgo = "SHA-1";
            else if (enabledAlgos.ContainsKey("MD5") && enabledAlgos["MD5"]) bestAlgo = "MD5";
            else
            {
                // Fallback: check if we can calculate SHA-256 regardless of settings
                bestAlgo = "SHA-256";
            }

            Thread t = new Thread(() => {
                try
                {
                    string targetHash = "";
                    using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                    {
                        byte[] hashBytes;
                        if (bestAlgo == "SHA-1")
                        {
                            using (var sha = SHA1.Create()) hashBytes = sha.ComputeHash(fs);
                        }
                        else if (bestAlgo == "MD5")
                        {
                            using (var md5 = MD5.Create()) hashBytes = md5.ComputeHash(fs);
                        }
                        else
                        {
                            using (var sha = SHA256.Create()) hashBytes = sha.ComputeHash(fs);
                        }
                        
                        StringBuilder sb = new StringBuilder();
                        for (int i = 0; i < hashBytes.Length; i++)
                        {
                            sb.Append(hashBytes[i].ToString(optLowercase ? "x2" : "X2"));
                        }
                        targetHash = sb.ToString();
                    }

                    this.BeginInvoke((MethodInvoker)delegate {
                        progForm.Close();
                        txtCompare.ForeColor = Color.FromArgb(31, 41, 55);
                        txtCompare.Text = targetHash;
                        PerformHashComparison();
                    });
                }
                catch (Exception ex)
                {
                    this.BeginInvoke((MethodInvoker)delegate {
                        progForm.Close();
                        MessageBox.Show(Locale.T("MsgCompareError", ex.Message), Locale.T("MsgCompareReadTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
                    });
                }
            });

            progForm.Load += (s, e) => t.Start();
            progForm.ShowDialog(this);
        }

        private void QueryThreatIntel(string engine)
        {
            string hash = "";

            // 1. Try to get a valid cryptographic hash from the selected ListView item
            if (listView.SelectedItems.Count > 0)
            {
                string selectedHash = listView.SelectedItems[0].SubItems[1].Text.Trim();
                // Check if it's a valid hex hash format (MD5=32, SHA1=40, SHA256=64 chars) and not a file size/date
                if (!string.IsNullOrEmpty(selectedHash) && 
                    (selectedHash.Length == 32 || selectedHash.Length == 40 || selectedHash.Length == 64) && 
                    !selectedHash.Contains(".") && !selectedHash.Contains(" ") && !selectedHash.Contains(":"))
                {
                    hash = selectedHash;
                }
            }

            // 2. If no valid hash is selected, automatically fall back to the best available calculated file hash
            if (string.IsNullOrEmpty(hash))
            {
                if (calculatedHashes.ContainsKey("SHA-256"))
                    hash = calculatedHashes["SHA-256"];
                else if (calculatedHashes.ContainsKey("SHA-1"))
                    hash = calculatedHashes["SHA-1"];
                else if (calculatedHashes.ContainsKey("MD5"))
                    hash = calculatedHashes["MD5"];
            }

            // Clean the hash from any potential whitespace/case issues
            if (!string.IsNullOrEmpty(hash))
            {
                hash = hash.Trim();
            }

            // 3. Verify we have a valid queryable hash
            if (string.IsNullOrEmpty(hash) || (hash.Length != 32 && hash.Length != 40 && hash.Length != 64))
            {
                MessageBox.Show(Locale.T("MsgSelectValidHash"), Locale.T("MsgSelectHashError"), MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            string url = "";
            if (engine == "VT")
                url = "https://www.virustotal.com/gui/file/" + hash;
            else if (engine == "HA")
                url = "https://www.hybrid-analysis.com/search?query=" + hash;
            else if (engine == "OTX")
                url = "https://otx.alienvault.com/indicator/file/" + hash;
            else if (engine == "ANYRUN")
                url = "https://any.run/submissions/#query=" + hash;
            else if (engine == "Google")
                url = "https://www.google.com/search?q=" + hash;

            if (!string.IsNullOrEmpty(url))
            {
                try
                {
                    Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
                }
                catch
                {
                    try
                    {
                        Process.Start("explorer.exe", "\"" + url + "\"");
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show("Error opening browser: " + ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }
        }

        private void QueryVirusTotalReport(string sha256Str)
        {
            if (string.IsNullOrEmpty(vtApiKey))
            {
                lblVirusTotal.Text = Locale.T("VtNoKey");
                return;
            }

            lblVirusTotal.Text = Locale.T("VtWaiting");

            Thread vtThread = new Thread(() => {
                try
                {
                    // Call the secure VirusTotal API v3 REST endpoint
                    var request = (HttpWebRequest)WebRequest.Create("https://www.virustotal.com/api/v3/files/" + sha256Str);
                    request.Headers.Add("x-apikey", vtApiKey);
                    request.Method = "GET";
                    request.Timeout = 10000;

                    using (var response = request.GetResponse())
                    using (var stream = response.GetResponseStream())
                    using (var reader = new StreamReader(stream))
                    {
                        string json = reader.ReadToEnd();
                        
                        // Parse JSON dynamically without third-party dependencies (lightweight C# code)
                        int posPos = json.IndexOf("\"positives\"");
                        int totalPos = json.IndexOf("\"total\"");
                        
                        int negatives = 0;
                        int totalCount = 0;

                        // Check fallback fields for dynamic schemas
                        if (posPos == -1) posPos = json.IndexOf("\"harmless\"");
                        if (totalPos == -1) totalPos = json.IndexOf("\"malicious\"");

                        if (posPos > 0)
                        {
                            int colon = json.IndexOf(':', posPos);
                            int comma = json.IndexOf(',', colon);
                            if (comma > 0)
                            {
                                int.TryParse(json.Substring(colon + 1, comma - colon - 1).Trim(), out negatives);
                            }
                        }

                        if (totalPos > 0)
                        {
                            int colon = json.IndexOf(':', totalPos);
                            int comma = json.IndexOf(',', colon);
                            if (comma > 0)
                            {
                                int.TryParse(json.Substring(colon + 1, comma - colon - 1).Trim(), out totalCount);
                            }
                        }

                        // Parse out real engine categories if present
                        int statsPos = json.IndexOf("\"last_analysis_stats\"");
                        if (statsPos > 0)
                        {
                            int maliciousPos = json.IndexOf("\"malicious\"", statsPos);
                            int harmlessPos = json.IndexOf("\"harmless\"", statsPos);
                            int undetectedPos = json.IndexOf("\"undetected\"", statsPos);

                            int malicious = 0;
                            int harmless = 0;
                            int undetected = 0;

                            if (maliciousPos > 0)
                            {
                                int colon = json.IndexOf(':', maliciousPos);
                                int comma = json.IndexOf(',', colon);
                                int.TryParse(json.Substring(colon + 1, comma - colon - 1).Trim(), out malicious);
                            }
                            if (harmlessPos > 0)
                            {
                                int colon = json.IndexOf(':', harmlessPos);
                                int comma = json.IndexOf(',', colon);
                                int.TryParse(json.Substring(colon + 1, comma - colon - 1).Trim(), out harmless);
                            }
                            if (undetectedPos > 0)
                            {
                                int colon = json.IndexOf(':', undetectedPos);
                                int closingBrace = json.IndexOf('}', colon);
                                int comma = json.IndexOf(',', colon);
                                int endIdx = (comma > 0 && comma < closingBrace) ? comma : closingBrace;
                                int.TryParse(json.Substring(colon + 1, endIdx - colon - 1).Trim(), out undetected);
                            }

                            negatives = malicious;
                            totalCount = harmless + undetected + malicious;
                        }

                        this.BeginInvoke((MethodInvoker)delegate {
                            lblVirusTotal.Text = string.Format("VirusTotal: {0}/{1}", negatives, totalCount);
                            if (negatives > 0)
                            {
                                lblVirusTotal.LinkColor = Color.FromArgb(220, 38, 38);
                            }
                            else
                            {
                                lblVirusTotal.LinkColor = Color.FromArgb(5, 150, 105);
                            }
                        });
                    }
                }
                catch (WebException ex)
                {
                    this.BeginInvoke((MethodInvoker)delegate {
                        var response = ex.Response as HttpWebResponse;
                        if (response != null && response.StatusCode == HttpStatusCode.NotFound)
                        {
                            lblVirusTotal.Text = Locale.T("VtNotFound");
                            lblVirusTotal.LinkColor = Color.FromArgb(107, 114, 128);
                        }
                        else
                        {
                            lblVirusTotal.Text = Locale.T("VtConnError");
                            lblVirusTotal.LinkColor = Color.FromArgb(107, 114, 128);
                        }
                    });
                }
                catch
                {
                    this.BeginInvoke((MethodInvoker)delegate {
                        lblVirusTotal.Text = Locale.T("VtQueryError");
                        lblVirusTotal.LinkColor = Color.FromArgb(107, 114, 128);
                    });
                }
            });

            vtThread.IsBackground = true;
            vtThread.Start();
        }

        private void SaveHashesToFile()
        {
            if (calculatedHashes.Count == 0)
            {
                MessageBox.Show(Locale.T("MsgHashFilesNone"), "Hata", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            using (SaveFileDialog sfd = new SaveFileDialog())
            {
                sfd.Title = Locale.T("MsgSaveTitle");
                sfd.Filter = Locale.T("MsgSaveFilter");
                sfd.FileName = Path.GetFileName(sourceFilePath) + "_hashes";

                if (sfd.ShowDialog() == DialogResult.OK)
                {
                    try
                    {
                        string ext = Path.GetExtension(sfd.FileName).ToLower();
                        if (ext == ".html")
                        {
                            ExportHtmlReport(sfd.FileName);
                        }
                        else if (ext == ".json")
                        {
                            ExportJsonReport(sfd.FileName);
                        }
                        else if (ext == ".csv")
                        {
                            ExportCsvReport(sfd.FileName);
                        }
                        else
                        {
                            ExportTextReport(sfd.FileName);
                        }

                        lblProgress.Text = Locale.T("MsgExportSuccess", "Analysis report successfully exported!");
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show(Locale.T("MsgExportFailed", ex.Message), "Hata", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }
        }

        private void SaveAsHashFiles()
        {
            if (calculatedHashes.Count == 0)
            {
                MessageBox.Show(Locale.T("MsgHashFilesNone"), "Hata", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            using (FolderBrowserDialog fbd = new FolderBrowserDialog())
            {
                fbd.Description = Locale.T("MsgHashFilesSaveTitle");
                if (fbd.ShowDialog() == DialogResult.OK)
                {
                    try
                    {
                        string targetDir = fbd.SelectedPath;
                        string cleanFileName = Path.GetFileName(sourceFilePath);
                        List<string> exportKeys = new List<string>(calculatedHashes.Keys);
                        int count = 0;

                        for (int i = 0; i < exportKeys.Count; i++)
                        {
                            string key = exportKeys[i];
                            string cleanHashVal = calculatedHashes[key].Trim();
                            if (string.IsNullOrEmpty(cleanHashVal) || cleanHashVal.Contains("."))
                                continue;

                            // Format: sha256, sha512, md5, etc.
                            string safeExt = key.Replace(" ", "").Replace("(", "").Replace(")", "").ToLower();
                            string finalPath = Path.Combine(targetDir, string.Format("{0}.{1}", cleanFileName, safeExt));
                            
                            File.WriteAllText(finalPath, cleanHashVal + "\r\n", Encoding.UTF8);
                            count++;
                        }

                        lblProgress.Text = string.Format(Locale.T("MsgHashFilesSaved", "{0} hash files successfully saved!"), count);
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show("Hata oluştu: " + ex.Message, "Hata", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }
        }

        private void CopyAsMagnetLink()
        {
            if (calculatedHashes.ContainsKey("SHA-1"))
            {
                string sha1 = calculatedHashes["SHA-1"].ToLower();
                if (!string.IsNullOrEmpty(sha1) && !sha1.Contains("."))
                {
                    string magnet = string.Format("magnet:?xt=urn:btih:{0}&dn={1}", sha1, Uri.EscapeDataString(Path.GetFileName(sourceFilePath)));
                    Clipboard.SetText(magnet);
                    lblProgress.Text = Locale.T("MsgMagnetSuccess", "Magnet link successfully copied!");
                }
                else
                {
                    MessageBox.Show(Locale.T("MsgMagnetError"), "Hata", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }
            else
            {
                MessageBox.Show(Locale.T("MsgMagnetError"), "Hata", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private void ExportHtmlReport(string path)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("<!DOCTYPE html>");
            sb.AppendLine("<html>");
            sb.AppendLine("<head>");
            sb.AppendLine("    <meta charset=\"utf-8\">");
            sb.AppendLine("    <title>SuperHashTab Premium Analysis Report</title>");
            sb.AppendLine("    <style>");
            sb.AppendLine("        body { font-family: 'Segoe UI', system-ui, sans-serif; background-color: #f9fafb; color: #111827; margin: 0; padding: 40px; }");
            sb.AppendLine("        .container { max-width: 900px; margin: 0 auto; background: #ffffff; padding: 40px; border-radius: 16px; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.05), 0 8px 10px -6px rgba(0,0,0,0.05); }");
            sb.AppendLine("        h1 { margin-top: 0; font-size: 28px; color: #1e3a8a; border-bottom: 2px solid #eff6ff; padding-bottom: 15px; }");
            sb.AppendLine("        .meta-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 30px; background: #f3f4f6; padding: 20px; border-radius: 12px; }");
            sb.AppendLine("        .meta-item { font-size: 14px; }");
            sb.AppendLine("        .meta-label { font-weight: bold; color: #4b5563; }");
            sb.AppendLine("        table { width: 100%; border-collapse: collapse; margin-top: 20px; }");
            sb.AppendLine("        th, td { padding: 14px 16px; text-align: left; border-bottom: 1px solid #e5e7eb; }");
            sb.AppendLine("        th { background-color: #f8fafc; font-weight: bold; color: #374151; }");
            sb.AppendLine("        td.algo { font-weight: bold; color: #1f2937; width: 200px; }");
            sb.AppendLine("        td.hash { font-family: 'Consolas', monospace; font-size: 14px; color: #0f172a; word-break: break-all; }");
            sb.AppendLine("        .footer { margin-top: 40px; text-align: center; font-size: 12px; color: #9ca3af; }");
            sb.AppendLine("    </style>");
            sb.AppendLine("</head>");
            sb.AppendLine("<body>");
            sb.AppendLine("    <div class=\"container\">");
            sb.AppendLine("        <h1>SuperHashTab Forensic Analysis Report</h1>");
            sb.AppendLine("        <div class=\"meta-grid\">");
            sb.AppendLine("            <div class=\"meta-item\"><span class=\"meta-label\">File Name:</span> " + Path.GetFileName(sourceFilePath) + "</div>");
            sb.AppendLine("            <div class=\"meta-item\"><span class=\"meta-label\">File Size:</span> " + FormatFileSize(new FileInfo(sourceFilePath).Length) + "</div>");
            sb.AppendLine("            <div class=\"meta-item\"><span class=\"meta-label\">Analysis Time:</span> " + DateTime.Now.ToString("F") + "</div>");
            sb.AppendLine("            <div class=\"meta-item\"><span class=\"meta-label\">Signature Status:</span> " + lblSignature.Text.Trim() + "</div>");
            sb.AppendLine("        </div>");
            sb.AppendLine("        <table>");
            sb.AppendLine("            <thead>");
            sb.AppendLine("                <tr>");
            sb.AppendLine("                    <th>Algorithm</th>");
            sb.AppendLine("                    <th>Cryptographic Hash Value</th>");
            sb.AppendLine("                </tr>");
            sb.AppendLine("            </thead>");
            sb.AppendLine("            <tbody>");

            List<string> exportKeys = new List<string>(calculatedHashes.Keys);
            for (int i = 0; i < exportKeys.Count; i++)
            {
                string key = exportKeys[i];
                sb.AppendLine("                <tr>");
                sb.AppendLine("                    <td class=\"algo\">" + key + "</td>");
                sb.AppendLine("                    <td class=\"hash\">" + calculatedHashes[key] + "</td>");
                sb.AppendLine("                </tr>");
            }

            sb.AppendLine("            </tbody>");
            sb.AppendLine("        </table>");
            sb.AppendLine("        <div class=\"footer\">Generated automatically by SuperHashTab Premium Extension</div>");
            sb.AppendLine("    </div>");
            sb.AppendLine("</body>");
            sb.AppendLine("</html>");

            File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
        }

        private void ExportJsonReport(string path)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("{");
            sb.AppendLine("    \"file_name\": \"" + Path.GetFileName(sourceFilePath).Replace("\\", "\\\\").Replace("\"", "\\\"") + "\",");
            sb.AppendLine("    \"file_size_bytes\": " + new FileInfo(sourceFilePath).Length + ",");
            sb.AppendLine("    \"analysis_timestamp\": \"" + DateTime.Now.ToString("o") + "\",");
            sb.AppendLine("    \"signature_status\": \"" + lblSignature.Text.Trim().Replace("\"", "\\\"") + "\",");
            sb.AppendLine("    \"hashes\": {");

            List<string> exportKeys = new List<string>(calculatedHashes.Keys);
            for (int i = 0; i < exportKeys.Count; i++)
            {
                string key = exportKeys[i];
                string comma = (i == exportKeys.Count - 1) ? "" : ",";
                sb.AppendLine("        \"" + key + "\": \"" + calculatedHashes[key] + "\"" + comma);
            }

            sb.AppendLine("    }");
            sb.AppendLine("}");

            File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
        }

        private void ExportCsvReport(string path)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("\"Algorithm\",\"Hash Value\"");

            List<string> exportKeys = new List<string>(calculatedHashes.Keys);
            foreach (var key in exportKeys)
            {
                sb.AppendLine(string.Format("\"{0}\",\"{1}\"", key.Replace("\"", "\"\""), calculatedHashes[key].Replace("\"", "\"\"")));
            }

            File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
        }

        private void ExportTextReport(string path)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("SuperHashTab Forensic Analysis Report");
            sb.AppendLine("=====================================");
            sb.AppendLine("File Name: " + Path.GetFileName(sourceFilePath));
            sb.AppendLine("File Size: " + FormatFileSize(new FileInfo(sourceFilePath).Length));
            sb.AppendLine("Analysis Time: " + DateTime.Now.ToString("F"));
            sb.AppendLine("Signature Status: " + lblSignature.Text.Trim());
            sb.AppendLine("=====================================");
            sb.AppendLine();

            List<string> exportKeys = new List<string>(calculatedHashes.Keys);
            foreach (var key in exportKeys)
            {
                sb.AppendLine(key + ": " + calculatedHashes[key]);
            }

            File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
        }

        private void OpenSettingsDialog()
        {
            using (SettingsForm form = new SettingsForm())
            {
                if (form.ShowDialog(this) == DialogResult.OK)
                {
                    // Reload active configuration selections
                    LoadSettings();

                    // Instantly cancel ongoing computations and restart to apply new selection list
                    if (cts != null)
                    {
                        cts.Cancel();
                    }
                    StartCalculations();
                }
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (cts != null)
                {
                    cts.Cancel();
                    cts.Dispose();
                }
                if (toolTipForensic != null)
                {
                    toolTipForensic.Dispose();
                }
                if (toolTipSignature != null)
                {
                    toolTipSignature.Dispose();
                }
            }
            base.Dispose(disposing);
        }
    }
}
