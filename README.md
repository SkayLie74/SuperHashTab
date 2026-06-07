# 🚀 SuperHashTab

[![SuperHashTab CI](https://github.com/SkayLie74/SuperHashTab/actions/workflows/build.yml/badge.svg)](https://github.com/SkayLie74/SuperHashTab/actions/workflows/build.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows-blue.svg)](#)
[![Language: C#](https://img.shields.io/badge/Language-C%23-green.svg)](#)

An advanced, high-performance, open-source file hashing and forensics shell extension for Windows Explorer, featuring real-time digital signature verification and integrated VirusTotal threat intelligence.

---

## 🌐 Language Options / Dil Seçenekleri

*   [English (English Description)](#-english-description)
*   [Türkçe (Türkçe Açıklama)](#-türkçe-açıklama)

---

## 🇺🇸 English Description

SuperHashTab is a lightweight yet extremely powerful Windows Shell extension that integrates directly into the Windows Explorer properties sheet. It provides security researchers, digital forensics experts, and power users with deep cryptographic, file architecture, and threat intelligence statistics.

### ✨ Highlights

*   **20+ Cryptographic Algorithms**: Compute SHA-256, SHA-512, SHA-384, SHA3, BLAKE2b, BLAKE2s, BLAKE3, MD5, SHA-1, CRC32, SSDEEP, TLSH, ImpHash, Authentihash, RichPE Hash, Import Hash, PE256, Icon MD5, and PE Section Hash instantly.
*   **Advanced Digital Signature Verification (WinVerifyTrust)**: Verifies Authenticode digital signatures of executables (`.exe`, `.dll`) in real-time, displaying the name of valid signing publishers (e.g., *Riot Games*, *Microsoft*).
*   **Integrated VirusTotal Threat Intelligence**: Asynchronously queries file hashes against the VirusTotal API in the background. Renders detection ratios using dynamic heat-map color coding for security analysts:
    - 🟢 **VirusTotal: 0 / 70** (Clean)
    - 🟡 **VirusTotal: 2 / 71** (Low Risk / Suspicious / False Positive)
    - 🟠 **VirusTotal: 7 / 70** (Medium Risk)
    - 🔴 **VirusTotal: 48 / 70** (High Risk / Malicious!)
*   **Smart Clipboard Management**: Automatically detects, validates, and compares clipboard contents if a valid hash pattern (MD5, SHA, SSDEEP, etc.) is copied when opening the tab.
*   **Advanced Report Exporting**: Export all calculated hashes and security analysis results with a single click into premium **HTML Reports**, **JSON**, **CSV**, or **TXT** files silently.
*   **Cyber Threat Intelligence Menu**: Right-click any hash in the ListView to instantly fetch intelligence reports from **VirusTotal**, **Hybrid-Analysis**, **AlienVault OTX**, or **Any.Run Sandbox**.

### 🛠️ Installation & Update

1. Download the latest release from the [Releases](https://github.com/SkayLie74/SuperHashTab/releases) tab.
2. Run the **`SuperHashTab_Setup.exe`** executable.
3. Click **"Install / Update"**. The setup wizard will automatically deploy the extension to `C:\Program Files\SuperHashTab`, release any active file locks, register the COM component, and restart Explorer.

### 🗑️ Uninstall
You can easily uninstall SuperHashTab by:
- Going to Windows **Add or Remove Programs** (Settings -> Apps) and clicking Uninstall on **SuperHashTab**.
- Or running `SuperHashTab_Setup.exe` and clicking **"Uninstall Extension"**.

---

## 🇹🇷 Türkçe Açıklama

SuperHashTab, Windows Dosya Gezgini (Explorer) özellikler sekmesine doğrudan entegre olan, dijital imza doğrulaması ve **VirusTotal** siber tehdit istihbaratı entegrasyonuna sahip, yüksek performanslı ve açık kaynak kodlu gelişmiş bir dosya hash ve adli bilişim (forensics) uzantısıdır.

### ✨ Öne Çıkan Özellikler

*   **20+ Farklı Hash Algoritması**: SHA-256, SHA-512, SHA-384, SHA3, BLAKE2b, BLAKE2s, BLAKE3, MD5, SHA-1, CRC32, SSDEEP, TLSH, ImpHash, Authentihash, RichPE Hash, Import Hash, PE256, Icon MD5 ve PE Section Hash değerlerini anında hesaplayabilme.
*   **Gelişmiş Dijital İmza Doğrulaması (WinVerifyTrust)**: `.exe` veya `.dll` gibi yürütülebilir dosyaların Authenticode imzalarını gerçek zamanlı doğrular ve geçerli imza sahiplerinin (örn: *Riot Games*, *Microsoft*) isimlerini ekrana basar.
*   **Entegre VirusTotal Tehdit İstihbaratı**: Dosyaların hash değerlerini otomatik ve asenkron (arka planda) olarak sorgular. Sonucu güvenlik analistleri için dinamik **ısı haritası renk kodlaması** ile ekrana getirir:
    - 🟢 **VirusTotal: 0 / 70** (Temiz)
    - 🟡 **VirusTotal: 2 / 71** (Düşük Risk / Şüpheli / False Positive)
    - 🟠 **VirusTotal: 7 / 70** (Orta Risk)
    - 🔴 **VirusTotal: 48 / 70** (Yüksek Risk / Zararlı!)
*   **Akıllı Pano (Clipboard) Yönetimi**: Arayüz açıldığında panodaki içeriği kontrol eder. Yalnızca geçerli hash (MD5, SHA, SSDEEP vb.) şablonlarını otomatik yapıştırır ve karşılaştırır.
*   **Gelişmiş Rapor Dışa Aktarma**: Elde edilen tüm hash ve imza doğrulama sonuçlarını tek tıkla **HTML (Premium Rapor)**, **JSON**, **CSV** veya **TXT** formatında sessizce dışa aktarabilme.
*   **Siber Tehdit İstihbarat Menüsü**: ListView üzerindeki herhangi bir hash değerine sağ tıklayarak doğrudan **VirusTotal**, **Hybrid-Analysis**, **AlienVault OTX** veya **Any.Run** üzerinde tek tıkla tehdit analiz raporu alabilme.

### 🛠️ Kurulum ve Güncelleme

1. En son sürümü [Releases (Sürümler)](https://github.com/SkayLie74/SuperHashTab/releases) kısmından indirin.
2. **`SuperHashTab_Setup.exe`** dosyasını çalıştırın.
3. **"Kur / Güncelle"** butonuna tıklayın. Kurulum sihirbazı dosyaları otomatik olarak `C:\Program Files\SuperHashTab` dizinine kopyalayacak, dosya kilitlerini kaldıracak, COM kaydını yapacak ve Explorer'ı yeniden başlatacaktır.

### 🗑️ Kaldırma (Uninstall)
Eklentiyi sisteminizden tamamen kaldırmak için:
- Windows **Program Ekle veya Kaldır** (Ayarlar -> Uygulamalar) menüsünden **SuperHashTab** uygulamasını seçip Kaldır'a basabilirsiniz.
- Veya `SuperHashTab_Setup.exe` dosyasını çalıştırıp **"Eklentiyi Kaldır"** butonuna tıklayabilirsiniz.

---

## 💻 Developers / Derleme (Build)

```bash
# Clone the repository / Depoyu klonlayın
git clone https://github.com/SkayLie74/SuperHashTab.git
cd SuperHashTab

# Run build / Derleme yapın
.\build.bat
```

---

## 📂 Project Structure / Proje Klasör Yapısı

```text
SuperHashTab/
├── .github/workflows/
│   └── build.yml          # GitHub Actions Auto-Build Pipeline (CI/CD)
├── src/                   # Modular C# Source Codes
│   ├── AssemblyInfo.cs    # DLL version metadata
│   ├── Cryptography.cs    # Cryptography calculations & hash algorithms
│   ├── PeAnalyzer.cs      # PE header analyzer, entropy & digital signatures
│   ├── Locale.cs          # Dynamic multilingual localization engine
│   ├── SettingsForm.cs    # Settings window forms & layout
│   ├── HashTabControl.cs  # Main hash & forensics control panel
│   └── SuperHashTabShellExt.cs # COM factory class & shell integration
├── installer/             # Installer source codes
│   └── Setup.cs           # C# Windows Forms Setup Wizard source code
├── locales/               # Global translation JSON files (11 languages)
├── .gitignore             # Git ignore file
├── LICENSE                # MIT License
├── README.md              # Project documentation
├── build.bat              # Quick build compiler tool (builds DLL & Setup.exe)
└── SuperHashTab.ico       # High-fidelity project icon resource
```

---

## 📜 License / Lisans

This project is licensed under the **MIT License**. More details are in the `LICENSE` file. / Bu proje **MIT Lisansı** altında lisanslanmıştır. Daha fazla bilgi için `LICENSE` dosyasına göz atabilirsiniz.
