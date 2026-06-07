using System;
using System.IO;
using System.Text;
using System.Collections.Generic;

namespace SuperHashTab
{
    public static class Locale
    {
        private static Dictionary<string, string> strings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        static Locale()
        {
            // Default English Strings
            strings["TabTitle"] = "File Hashes";
            strings["SignatureChecking"] = "  [..] Verifying digital signature...";
            strings["SignatureValid"] = "  [✓] Digital Signature: Valid ({0})";
            strings["SignatureInvalid"] = "  [!] Digital Signature: Invalid (Modified or Corrupted!)";
            strings["SignatureUnsigned"] = "  [!] Digital Signature: Unsigned";
            
            strings["ColName"] = "Name";
            strings["ColHash"] = "Hash Value";
            
            strings["MenuCopyValue"] = "Copy Selected Hash Value";
            strings["MenuCopyAll"] = "Copy All Hash Values";
            strings["MenuSaveReport"] = "Save Analysis Report to File...";
            strings["MenuCopyMagnet"] = "Copy Magnet Link";
            strings["MenuSettings"] = "Settings...";
            strings["MenuQueryOnline"] = "Query Online Threat Intelligence";
            strings["MenuQueryVT"] = "Query with VirusTotal";
            strings["MenuQueryHA"] = "Query with Hybrid-Analysis";
            strings["MenuQueryGoogle"] = "Search with Google";
            strings["MenuQueryOTX"] = "Query with AlienVault OTX";
            strings["MenuQueryAnyRun"] = "Analyze with Any.Run Sandbox";
            
            strings["ProgressReady"] = "Ready";
            strings["ProgressDone"] = "Completed";
            strings["ProgressError"] = "Error";
            
            strings["CompareGroup"] = "Hash Comparison:";
            strings["CompareButton"] = "Compare a file...";
            
            strings["VtWaiting"] = "VirusTotal: Waiting...";
            strings["VtNoKey"] = "VirusTotal: API key not set (Click)";
            strings["VtNoRecord"] = "VirusTotal: No record in database";
            strings["VtNotFound"] = "VirusTotal: Record not found";
            strings["VtConnError"] = "VirusTotal: Connection error";
            strings["VtQueryError"] = "VirusTotal: Query error";
            
            strings["SettingsTitle"] = "HashTab Settings";
            strings["SettingsShowHashes"] = "Show Hashes";
            strings["SettingsSelectAll"] = "Select All";
            strings["SettingsSelectNone"] = "Select None";
            strings["SettingsReset"] = "Reset";
            strings["SettingsVtGroup"] = "VirusTotal API Settings";
            strings["SettingsApiKeyLabel"] = "API Key:";
            strings["SettingsLowercase"] = "Use lowercase hash values";
            strings["SettingsOk"] = "OK";
            strings["SettingsCancel"] = "Cancel";
            
            strings["MsgSelectValidHash"] = "You must select a valid, calculated hash to query.";
            strings["MsgSelectHashError"] = "Query Error";
            strings["MsgHashCalculationError"] = "Hash calculation error: {0}";
            strings["MsgComparisonMatch"] = "MATCH!";
            strings["MsgComparisonMismatch"] = "MISMATCH";
            strings["MsgExportSuccess"] = "Analysis report successfully exported!";
            strings["MsgExportTitle"] = "Export Successful";
            strings["MsgExportFailed"] = "Failed to export report: {0}";
            
            strings["MsgSameFileCompare"] = "You cannot compare a file with itself!";
            strings["MsgSameFileTitle"] = "Information";
            strings["MsgCompareError"] = "Error occurred while reading the comparison file: {0}";
            strings["MsgCompareReadTitle"] = "Error";
            strings["MsgCompareTaskName"] = "Comparing...";
            
            strings["MsgSaveTitle"] = "Save Hash Values";
            strings["MsgSaveFilter"] = "Premium HTML Report (*.html)|*.html|JSON Report (*.json)|*.json|CSV Spreadsheet (*.csv)|*.csv|Text Document (*.txt)|*.txt";
            strings["MenuSaveHashFiles"] = "Save as Individual Hash Files...";
            strings["MsgHashFilesSaveTitle"] = "Choose Folder to Save Hash Files";
            strings["MsgHashFilesSaved"] = "Saved {0} hash file(s) to:\n{1}";
            strings["MsgHashFilesNone"] = "No hash values have been calculated yet.";
            strings["MsgMagnetSuccess"] = "Magnet Link successfully copied to clipboard!";
            strings["MsgMagnetTitle"] = "Success";
            strings["MsgMagnetError"] = "SHA-1 hash must be enabled and calculated to generate a Magnet Link.";
            strings["Calculating"] = "Calculating...";
            strings["FileType"] = "Type";
            strings["ComparePlaceholder"] = "Paste a hash or drag a file here...";
            strings["EntropyShortLow"] = "Low";
            strings["EntropyShortMed"] = "Med";
            strings["EntropyShortHigh"] = "High";
            
            LoadExternalLocale();
        }

        private static void LoadExternalLocale()
        {
            try
            {
                string dllPath = typeof(Locale).Assembly.Location;
                string folder = Path.GetDirectoryName(dllPath);
                
                string lang = "en";
                // Priority 1: Windows UI language (CultureInfo) — auto-detect
                // Priority 2: Explicit manual override in settings.ini (Language=xx, not 'auto' or 'en')
                // Priority 3: English fallback
                string localesDir = Path.Combine(folder, "locales");
                string systemLang = System.Globalization.CultureInfo.CurrentUICulture.TwoLetterISOLanguageName.ToLower();
                // Use system language if we have a locale file for it
                if (File.Exists(Path.Combine(localesDir, systemLang + ".json")))
                    lang = systemLang;

                // settings.ini can OVERRIDE with a specific language (but 'en' and 'auto' → use auto-detect above)
                string settingsFile = Path.Combine(folder, "settings.ini");
                if (File.Exists(settingsFile))
                {
                    foreach (string line in File.ReadAllLines(settingsFile, Encoding.UTF8))
                    {
                        string trimmed = line.Trim();
                        if (trimmed.StartsWith("Language", StringComparison.OrdinalIgnoreCase))
                        {
                            int eq = trimmed.IndexOf('=');
                            if (eq > 0)
                            {
                                string val = trimmed.Substring(eq + 1).Trim().ToLower();
                                // Only override if it's a real explicit language code (not 'auto' or 'en')
                                if (!string.IsNullOrEmpty(val) && val != "auto" && val != "en")
                                    lang = val;
                            }
                        }
                    }
                }

                string localeFile = Path.Combine(localesDir, lang + ".json");
                
                // Fallback: check same directory if locales subfolder is not found
                if (!File.Exists(localeFile))
                {
                    localeFile = Path.Combine(folder, lang + ".json");
                }
                
                if (File.Exists(localeFile))
                {
                    foreach (string line in File.ReadAllLines(localeFile, Encoding.UTF8))
                    {
                        string trimmed = line.Trim();
                        if (trimmed.StartsWith("{") || trimmed.StartsWith("}"))
                            continue;

                        int idx = trimmed.IndexOf(':');
                        if (idx > 0)
                        {
                            string key = trimmed.Substring(0, idx).Trim().Trim('"');
                            string val = trimmed.Substring(idx + 1).Trim().Trim(',', '"');
                            val = val.Replace("\\\"", "\"").Replace("\\\\", "\\");
                            if (!string.IsNullOrEmpty(key))
                            {
                                strings[key] = val;
                            }
                        }
                    }
                }
            }
            catch
            {
                // Fall back silently to default English
            }
        }

        public static string T(string key, params object[] args)
        {
            string val;
            if (strings.TryGetValue(key, out val))
            {
                if (args != null && args.Length > 0)
                {
                    try { return string.Format(val, args); } catch { return val; }
                }
                return val;
            }
            return key;
        }
    }
}
