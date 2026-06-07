using System;
using System.IO;
using System.Drawing;
using System.Windows.Forms;
using Microsoft.Win32;

namespace SuperHashTab
{
    // Settings dialog matching HashTab settings screenshot
    public class SettingsForm : Form
    {
        private CheckedListBox chkListHashes;
        private CheckBox chkLowercase;
        private TextBox txtVtApiKey;
        private Button btnSelectAll;
        private Button btnSelectNone;
        private Button btnReset;
        private Button btnOk;
        private Button btnCancel;
        private GroupBox grpHashes;

        public SettingsForm()
        {
            InitializeUI();
            LoadRegistrySettings();
        }

        private void InitializeUI()
        {
            this.Text = Locale.T("SettingsTitle");
            this.Size = new Size(450, 560);
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.StartPosition = FormStartPosition.CenterParent;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.ShowIcon = true;
            this.Font = new Font("Segoe UI", 9f);
            this.BackColor = SystemColors.Control;

            try
            {
                string dllPath = typeof(SettingsForm).Assembly.Location;
                string folder = Path.GetDirectoryName(dllPath);
                string iconPath = Path.Combine(folder, "SuperHashTab.ico");
                if (File.Exists(iconPath))
                {
                    this.Icon = new Icon(iconPath);
                }
            }
            catch { }

            grpHashes = new GroupBox();
            grpHashes.Text = Locale.T("SettingsShowHashes");
            grpHashes.Location = new Point(15, 15);
            grpHashes.Size = new Size(405, 330);

            chkListHashes = new CheckedListBox();
            chkListHashes.Location = new Point(15, 25);
            chkListHashes.Size = new Size(250, 290);
            chkListHashes.BorderStyle = BorderStyle.FixedSingle;
            chkListHashes.CheckOnClick = true;
            chkListHashes.Sorted = true;
            
            // Add all 20 in sequence
            chkListHashes.Items.Add("SHA-256");
            chkListHashes.Items.Add("SHA-512");
            chkListHashes.Items.Add("SHA-384");
            chkListHashes.Items.Add("SHA3-256");
            chkListHashes.Items.Add("SHA3-512");
            chkListHashes.Items.Add("BLAKE2b");
            chkListHashes.Items.Add("BLAKE2s");
            chkListHashes.Items.Add("BLAKE3");
            chkListHashes.Items.Add("MD5");
            chkListHashes.Items.Add("SHA-1");
            chkListHashes.Items.Add("CRC32");
            chkListHashes.Items.Add("SSDEEP");
            chkListHashes.Items.Add("TLSH");
            chkListHashes.Items.Add("ImpHash");
            chkListHashes.Items.Add("Authentihash");
            chkListHashes.Items.Add("RichPE Hash");
            chkListHashes.Items.Add("Import Hash");
            chkListHashes.Items.Add("PE256 (PE Header Hash)");
            chkListHashes.Items.Add("Icon MD5");
            chkListHashes.Items.Add("Section Hash (PE Section Hash)");

            grpHashes.Controls.Add(chkListHashes);

            btnSelectAll = new Button();
            btnSelectAll.Text = Locale.T("SettingsSelectAll");
            btnSelectAll.Location = new Point(280, 25);
            btnSelectAll.Size = new Size(110, 28);
            btnSelectAll.FlatStyle = FlatStyle.System;
            btnSelectAll.Click += (s, e) => ToggleAllItems(true);
            grpHashes.Controls.Add(btnSelectAll);

            btnSelectNone = new Button();
            btnSelectNone.Text = Locale.T("SettingsSelectNone");
            btnSelectNone.Location = new Point(280, 60);
            btnSelectNone.Size = new Size(110, 28);
            btnSelectNone.FlatStyle = FlatStyle.System;
            btnSelectNone.Click += (s, e) => ToggleAllItems(false);
            grpHashes.Controls.Add(btnSelectNone);

            btnReset = new Button();
            btnReset.Text = Locale.T("SettingsReset");
            btnReset.Location = new Point(280, 95);
            btnReset.Size = new Size(110, 28);
            btnReset.FlatStyle = FlatStyle.System;
            btnReset.Click += (s, e) => ResetToDefaults();
            grpHashes.Controls.Add(btnReset);

            this.Controls.Add(grpHashes);

            // VirusTotal API Section
            GroupBox grpVT = new GroupBox();
            grpVT.Text = Locale.T("SettingsVtGroup");
            grpVT.Location = new Point(15, 355);
            grpVT.Size = new Size(405, 70);

            Label lblVT = new Label();
            lblVT.Text = Locale.T("SettingsApiKeyLabel");
            lblVT.Location = new Point(15, 28);
            lblVT.Size = new Size(90, 20);
            grpVT.Controls.Add(lblVT);

            txtVtApiKey = new TextBox();
            txtVtApiKey.Location = new Point(110, 25);
            txtVtApiKey.Size = new Size(280, 23);
            grpVT.Controls.Add(txtVtApiKey);

            this.Controls.Add(grpVT);

            chkLowercase = new CheckBox();
            chkLowercase.Text = Locale.T("SettingsLowercase");
            chkLowercase.Location = new Point(15, 435);
            chkLowercase.Size = new Size(350, 25);
            this.Controls.Add(chkLowercase);

            btnOk = new Button();
            btnOk.Text = Locale.T("SettingsOk");
            btnOk.Location = new Point(230, 475);
            btnOk.Size = new Size(90, 28);
            btnOk.FlatStyle = FlatStyle.System;
            btnOk.Click += (s, e) => SaveAndClose();
            this.Controls.Add(btnOk);

            btnCancel = new Button();
            btnCancel.Text = Locale.T("SettingsCancel");
            btnCancel.Location = new Point(330, 475);
            btnCancel.Size = new Size(90, 28);
            btnCancel.FlatStyle = FlatStyle.System;
            btnCancel.Click += (s, e) => { this.DialogResult = DialogResult.Cancel; this.Close(); };
            this.Controls.Add(btnCancel);
        }

        private void ToggleAllItems(bool value)
        {
            for (int i = 0; i < chkListHashes.Items.Count; i++)
            {
                chkListHashes.SetItemChecked(i, value);
            }
        }

        private void ResetToDefaults()
        {
            for (int i = 0; i < chkListHashes.Items.Count; i++)
            {
                string item = chkListHashes.Items[i].ToString();
                if (item == "MD5" || item == "SHA-256")
                    chkListHashes.SetItemChecked(i, true);
                else
                    chkListHashes.SetItemChecked(i, false);
            }
            chkLowercase.Checked = false;
            txtVtApiKey.Text = "";
        }

        private void LoadRegistrySettings()
        {
            try
            {
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\SuperHashTab"))
                {
                    chkLowercase.Checked = (key != null && (int)key.GetValue("Lowercase", 0) == 1);
                    txtVtApiKey.Text = key != null ? (string)key.GetValue("VirusTotalApiKey", "") : "";
                    
                    for (int i = 0; i < chkListHashes.Items.Count; i++)
                    {
                        string item = chkListHashes.Items[i].ToString();
                        if (item == "SHA-256") chkListHashes.SetItemChecked(i, key == null || (int)key.GetValue("ShowSHA256", 1) == 1);
                        else if (item == "SHA-512") chkListHashes.SetItemChecked(i, key != null && (int)key.GetValue("ShowSHA512", 0) == 1);
                        else if (item == "SHA-384") chkListHashes.SetItemChecked(i, key != null && (int)key.GetValue("ShowSHA384", 0) == 1);
                        else if (item == "SHA3-256") chkListHashes.SetItemChecked(i, key != null && (int)key.GetValue("ShowSHA3_256", 0) == 1);
                        else if (item == "SHA3-512") chkListHashes.SetItemChecked(i, key != null && (int)key.GetValue("ShowSHA3_512", 0) == 1);
                        else if (item == "BLAKE2b") chkListHashes.SetItemChecked(i, key != null && (int)key.GetValue("ShowBLAKE2b", 0) == 1);
                        else if (item == "BLAKE2s") chkListHashes.SetItemChecked(i, key != null && (int)key.GetValue("ShowBLAKE2s", 0) == 1);
                        else if (item == "BLAKE3") chkListHashes.SetItemChecked(i, key != null && (int)key.GetValue("ShowBLAKE3", 0) == 1);
                        else if (item == "MD5") chkListHashes.SetItemChecked(i, key == null || (int)key.GetValue("ShowMD5", 1) == 1);
                        else if (item == "SHA-1") chkListHashes.SetItemChecked(i, key != null && (int)key.GetValue("ShowSHA1", 0) == 1);
                        else if (item == "CRC32") chkListHashes.SetItemChecked(i, key != null && (int)key.GetValue("ShowCRC32", 0) == 1);
                        else if (item == "SSDEEP") chkListHashes.SetItemChecked(i, key != null && (int)key.GetValue("ShowSSDEEP", 0) == 1);
                        else if (item == "TLSH") chkListHashes.SetItemChecked(i, key != null && (int)key.GetValue("ShowTLSH", 0) == 1);
                        else if (item == "ImpHash") chkListHashes.SetItemChecked(i, key != null && (int)key.GetValue("ShowImpHash", 0) == 1);
                        else if (item == "Authentihash") chkListHashes.SetItemChecked(i, key != null && (int)key.GetValue("ShowAuthentihash", 0) == 1);
                        else if (item == "RichPE Hash") chkListHashes.SetItemChecked(i, key != null && (int)key.GetValue("ShowRichPEHash", 0) == 1);
                        else if (item == "Import Hash") chkListHashes.SetItemChecked(i, key != null && (int)key.GetValue("ShowImportHash", 0) == 1);
                        else if (item == "PE256 (PE Header Hash)") chkListHashes.SetItemChecked(i, key != null && (int)key.GetValue("ShowPE256", 0) == 1);
                        else if (item == "Icon MD5") chkListHashes.SetItemChecked(i, key != null && (int)key.GetValue("ShowIconMD5", 0) == 1);
                        else if (item == "Section Hash (PE Section Hash)") chkListHashes.SetItemChecked(i, key != null && (int)key.GetValue("ShowSectionHash", 0) == 1);
                    }
                }
            }
            catch
            {
                ResetToDefaults();
            }
        }

        private void SaveAndClose()
        {
            try
            {
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\SuperHashTab"))
                {
                    key.SetValue("Lowercase", chkLowercase.Checked ? 1 : 0, RegistryValueKind.DWord);
                    key.SetValue("VirusTotalApiKey", txtVtApiKey.Text.Trim(), RegistryValueKind.String);
                    
                    for (int i = 0; i < chkListHashes.Items.Count; i++)
                    {
                        string item = chkListHashes.Items[i].ToString();
                        bool val = chkListHashes.GetItemChecked(i);
                        if (item == "SHA-256") key.SetValue("ShowSHA256", val ? 1 : 0, RegistryValueKind.DWord);
                        else if (item == "SHA-512") key.SetValue("ShowSHA512", val ? 1 : 0, RegistryValueKind.DWord);
                        else if (item == "SHA-384") key.SetValue("ShowSHA384", val ? 1 : 0, RegistryValueKind.DWord);
                        else if (item == "SHA3-256") key.SetValue("ShowSHA3_256", val ? 1 : 0, RegistryValueKind.DWord);
                        else if (item == "SHA3-512") key.SetValue("ShowSHA3_512", val ? 1 : 0, RegistryValueKind.DWord);
                        else if (item == "BLAKE2b") key.SetValue("ShowBLAKE2b", val ? 1 : 0, RegistryValueKind.DWord);
                        else if (item == "BLAKE2s") key.SetValue("ShowBLAKE2s", val ? 1 : 0, RegistryValueKind.DWord);
                        else if (item == "BLAKE3") key.SetValue("ShowBLAKE3", val ? 1 : 0, RegistryValueKind.DWord);
                        else if (item == "MD5") key.SetValue("ShowMD5", val ? 1 : 0, RegistryValueKind.DWord);
                        else if (item == "SHA-1") key.SetValue("ShowSHA1", val ? 1 : 0, RegistryValueKind.DWord);
                        else if (item == "CRC32") key.SetValue("ShowCRC32", val ? 1 : 0, RegistryValueKind.DWord);
                        else if (item == "SSDEEP") key.SetValue("ShowSSDEEP", val ? 1 : 0, RegistryValueKind.DWord);
                        else if (item == "TLSH") key.SetValue("ShowTLSH", val ? 1 : 0, RegistryValueKind.DWord);
                        else if (item == "ImpHash") key.SetValue("ShowImpHash", val ? 1 : 0, RegistryValueKind.DWord);
                        else if (item == "Authentihash") key.SetValue("ShowAuthentihash", val ? 1 : 0, RegistryValueKind.DWord);
                        else if (item == "RichPE Hash") key.SetValue("ShowRichPEHash", val ? 1 : 0, RegistryValueKind.DWord);
                        else if (item == "Import Hash") key.SetValue("ShowImportHash", val ? 1 : 0, RegistryValueKind.DWord);
                        else if (item == "PE256 (PE Header Hash)") key.SetValue("ShowPE256", val ? 1 : 0, RegistryValueKind.DWord);
                        else if (item == "Icon MD5") key.SetValue("ShowIconMD5", val ? 1 : 0, RegistryValueKind.DWord);
                        else if (item == "Section Hash (PE Section Hash)") key.SetValue("ShowSectionHash", val ? 1 : 0, RegistryValueKind.DWord);
                    }
                }
                this.DialogResult = DialogResult.OK;
                this.Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show("Ayarlar kaydedilirken hata oluştu: " + ex.Message, "Hata", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }
}
