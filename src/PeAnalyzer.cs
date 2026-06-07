using System;
using System.IO;
using System.Text;
using System.Drawing;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace SuperHashTab
{
    // P/Invoke helpers used across the extension
    internal static class NativeMethods
    {
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        internal static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, string lParam);
    }

    // Win32 WinVerifyTrust digital signature validation engine
    public static class WinTrust
    {
        private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        private const string WINTRUST_ACTION_GENERIC_VERIFY_V2 = "{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}";

        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, WinTrustData pWinTrustData);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private class WinTrustData
        {
            public uint cbStruct = (uint)Marshal.SizeOf(typeof(WinTrustData));
            public IntPtr pPolicyCallbackData = IntPtr.Zero;
            public IntPtr pSIPCallbackData = IntPtr.Zero;
            public uint dwUIChoice = 2; // WTD_UI_NONE
            public uint fdwRevocationChecks = 0; // WTD_REVOKE_NONE
            public uint dwUnionChoice = 1; // WTD_CHOICE_FILE
            public IntPtr pFile = IntPtr.Zero;
            public uint dwStateAction = 0;
            public IntPtr hWVTStateData = IntPtr.Zero;
            public IntPtr pwszURLReference = IntPtr.Zero;
            public uint dwProvFlags = 0x00000040; // WTD_REVOCATION_CHECK_NONE
            public uint dwUIContext = 0;

            public WinTrustData(IntPtr pFilePtr)
            {
                this.pFile = pFilePtr;
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private class WinTrustFileInfo
        {
            public uint cbStruct = (uint)Marshal.SizeOf(typeof(WinTrustFileInfo));
            public string pcwszFilePath;
            public IntPtr hFile = IntPtr.Zero;
            public IntPtr pgKnownSubject = IntPtr.Zero;

            public WinTrustFileInfo(string filePath)
            {
                this.pcwszFilePath = filePath;
            }
        }

        public enum SignatureState
        {
            Valid,
            Unsigned,
            Invalid
        }

        public static SignatureState VerifySignatureState(string fileName, out string signerName)
        {
            signerName = "";
            try
            {
                WinTrustFileInfo fileInfo = new WinTrustFileInfo(fileName);
                IntPtr pFileInfo = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WinTrustFileInfo)));
                Marshal.StructureToPtr(fileInfo, pFileInfo, false);

                WinTrustData trustData = new WinTrustData(pFileInfo);
                IntPtr pTrustData = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WinTrustData)));
                Marshal.StructureToPtr(trustData, pTrustData, false);

                Guid actionGuid = new Guid(WINTRUST_ACTION_GENERIC_VERIFY_V2);
                int result = WinVerifyTrust(new IntPtr(-1), actionGuid, trustData);

                Marshal.FreeHGlobal(pFileInfo);
                Marshal.FreeHGlobal(pTrustData);

                if (result == 0)
                {
                    signerName = GetSignerName(fileName);
                    return SignatureState.Valid;
                }

                // All codes that mean "no signature / not signable" → Unsigned
                // 0x800B0100 = TRUST_E_NOSIGNATURE          (no signature at all)
                // 0x800B0003 = TRUST_E_SUBJECT_FORM_UNKNOWN (file format not signable, e.g. .json .txt)
                // 0x800B0001 = TRUST_E_PROVIDER_UNKNOWN     (no trust provider for this format)
                // 0x80092003 = CRYPT_E_FILE_ERROR           (can't read the file as a signed object)
                // 0x800B010E = TRUST_E_EXPLICIT_DISTRUST    (user explicitly distrusted — treat as invalid below)
                uint uresult = unchecked((uint)result);
                if (uresult == 0x800B0100 ||
                    uresult == 0x800B0003 ||
                    uresult == 0x800B0001 ||
                    uresult == 0x80092003)
                {
                    return SignatureState.Unsigned;
                }

                return SignatureState.Invalid;
            }
            catch
            {
                return SignatureState.Unsigned;
            }
        }

        public static bool VerifyEmbeddedSignature(string fileName)
        {
            try
            {
                WinTrustFileInfo fileInfo = new WinTrustFileInfo(fileName);
                IntPtr pFileInfo = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WinTrustFileInfo)));
                Marshal.StructureToPtr(fileInfo, pFileInfo, false);

                WinTrustData trustData = new WinTrustData(pFileInfo);
                IntPtr pTrustData = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WinTrustData)));
                Marshal.StructureToPtr(trustData, pTrustData, false);

                Guid actionGuid = new Guid(WINTRUST_ACTION_GENERIC_VERIFY_V2);
                int result = WinVerifyTrust(new IntPtr(-1), actionGuid, trustData);

                Marshal.FreeHGlobal(pFileInfo);
                Marshal.FreeHGlobal(pTrustData);

                return result == 0;
            }
            catch
            {
                return false;
            }
        }

        public static string GetSignerName(string filePath)
        {
            try
            {
                using (var cert = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(filePath))
                {
                    string subject = cert.Subject;
                    string org = ParseSubjectField(subject, "O=");
                    if (string.IsNullOrEmpty(org))
                        org = ParseSubjectField(subject, "CN=");
                    return string.IsNullOrEmpty(org) ? cert.Issuer : org;
                }
            }
            catch
            {
                return "";
            }
        }

        private static string ParseSubjectField(string subject, string fieldPrefix)
        {
            int idx = subject.IndexOf(fieldPrefix, StringComparison.OrdinalIgnoreCase);
            if (idx == -1) return "";
            idx += fieldPrefix.Length;
            int commaIdx = subject.IndexOf(',', idx);
            if (commaIdx == -1)
                return subject.Substring(idx).Trim(' ', '"');
            else
                return subject.Substring(idx, commaIdx - idx).Trim(' ', '"');
        }
    }

    // Shannon Entropy Calculator for file obfuscation/encryption/compression detection
    public static class EntropyHelper
    {
        public static double ComputeEntropy(string filePath, out string status)
        {
            status = "Low";
            try
            {
                long[] counts = new long[256];
                long totalBytes = 0;
                
                using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    byte[] buffer = new byte[65536];
                    int bytesRead;
                    while ((bytesRead = fs.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        for (int i = 0; i < bytesRead; i++)
                        {
                            counts[buffer[i]]++;
                        }
                        totalBytes += bytesRead;
                    }
                }
                
                if (totalBytes == 0) return 0.0;
                
                double entropy = 0.0;
                for (int i = 0; i < 256; i++)
                {
                    if (counts[i] > 0)
                    {
                        double p = (double)counts[i] / totalBytes;
                        entropy -= p * Math.Log(p, 2);
                    }
                }
                
                if (entropy < 4.5)
                    status = Locale.T("EntropyLow");
                else if (entropy < 6.8)
                    status = Locale.T("EntropyMedium");
                else
                    status = Locale.T("EntropyHigh");
                    
                return entropy;
            }
            catch
            {
                return 0.0;
            }
        }
    }

    // Advanced portable PE structural parser class
    public class PEFile
    {
        public bool IsPE { get; private set; }
        public bool Is64Bit { get; private set; }
        public ushort Machine { get; private set; }
        public uint PEHeaderOffset { get; private set; }
        public ushort NumberOfSections { get; private set; }
        public ushort Characteristics { get; private set; }
        public ushort Subsystem { get; private set; }
        public uint AddressOfEntryPoint { get; private set; }
        public uint ImageBase32 { get; private set; }
        public ulong ImageBase64 { get; private set; }
        public uint SectionAlignment { get; private set; }
        public uint FileAlignment { get; private set; }
        
        public uint ImportTableVA { get; private set; }
        public uint ImportTableSize { get; private set; }
        public uint ResourceTableVA { get; private set; }
        public uint ResourceTableSize { get; private set; }
        public uint SecurityTableOffset { get; private set; }
        public uint SecurityTableSize { get; private set; }

        public class PESection
        {
            public string Name;
            public uint VirtualAddress;
            public uint VirtualSize;
            public uint PointerToRawData;
            public uint SizeOfRawData;
            public uint Characteristics;
        }

        public List<PESection> Sections = new List<PESection>();

        public PEFile(string path)
        {
            try
            {
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (BinaryReader br = new BinaryReader(fs))
                {
                    if (fs.Length < 64) return;
                    fs.Position = 0x3C;
                    uint e_lfanew = br.ReadUInt32();
                    if (fs.Length < e_lfanew + 24) return;
                    fs.Position = e_lfanew;
                    uint peSig = br.ReadUInt32();
                    if (peSig != 0x00004550) return; // "PE\0\0"
                    
                    IsPE = true;
                    PEHeaderOffset = e_lfanew;
                    
                    // File Header
                    fs.Position = e_lfanew + 4;
                    ushort machine = br.ReadUInt16();
                    Machine = machine;
                    NumberOfSections = br.ReadUInt16();
                    uint timeDateStamp = br.ReadUInt32();
                    fs.Position = e_lfanew + 20;
                    ushort sizeOfOptionalHeader = br.ReadUInt16();
                    Characteristics = br.ReadUInt16();
                    
                    // Optional Header
                    uint optHeaderOffset = e_lfanew + 24;
                    fs.Position = optHeaderOffset;
                    ushort magic = br.ReadUInt16();
                    Is64Bit = (magic == 0x20B); // PE32+
                    
                    fs.Position = optHeaderOffset + 16;
                    AddressOfEntryPoint = br.ReadUInt32();
                    
                    if (Is64Bit)
                    {
                        fs.Position = optHeaderOffset + 24;
                        ImageBase64 = br.ReadUInt64();
                        SectionAlignment = br.ReadUInt32();
                        FileAlignment = br.ReadUInt32();
                        fs.Position = optHeaderOffset + 68;
                        Subsystem = br.ReadUInt16();
                        
                        fs.Position = optHeaderOffset + 112 + 8; // Skip Export
                        ImportTableVA = br.ReadUInt32();
                        ImportTableSize = br.ReadUInt32();
                        ResourceTableVA = br.ReadUInt32();
                        ResourceTableSize = br.ReadUInt32();
                        fs.Position = optHeaderOffset + 112 + 32; // Security
                        SecurityTableOffset = br.ReadUInt32();
                        SecurityTableSize = br.ReadUInt32();
                    }
                    else
                    {
                        fs.Position = optHeaderOffset + 28;
                        ImageBase32 = br.ReadUInt32();
                        SectionAlignment = br.ReadUInt32();
                        FileAlignment = br.ReadUInt32();
                        fs.Position = optHeaderOffset + 68;
                        Subsystem = br.ReadUInt16();
                        
                        fs.Position = optHeaderOffset + 96 + 8; // Skip Export
                        ImportTableVA = br.ReadUInt32();
                        ImportTableSize = br.ReadUInt32();
                        ResourceTableVA = br.ReadUInt32();
                        ResourceTableSize = br.ReadUInt32();
                        fs.Position = optHeaderOffset + 96 + 32; // Security
                        SecurityTableOffset = br.ReadUInt32();
                        SecurityTableSize = br.ReadUInt32();
                    }
                    
                    // Parse Sections
                    uint sectionHeaderStart = optHeaderOffset + sizeOfOptionalHeader;
                    for (int i = 0; i < NumberOfSections; i++)
                    {
                        fs.Position = sectionHeaderStart + (i * 40);
                        byte[] nameBytes = br.ReadBytes(8);
                        int nameLen = 0;
                        while (nameLen < 8 && nameBytes[nameLen] != 0) nameLen++;
                        string name = Encoding.ASCII.GetString(nameBytes, 0, nameLen);
                        
                        PESection sec = new PESection();
                        sec.Name = name;
                        sec.VirtualSize = br.ReadUInt32();
                        sec.VirtualAddress = br.ReadUInt32();
                        sec.SizeOfRawData = br.ReadUInt32();
                        sec.PointerToRawData = br.ReadUInt32();
                        fs.Position += 12;
                        sec.Characteristics = br.ReadUInt32();
                        
                        Sections.Add(sec);
                    }
                }
            }
            catch
            {
                IsPE = false;
            }
        }

        public uint RvaToOffset(uint rva)
        {
            foreach (var sec in Sections)
            {
                if (rva >= sec.VirtualAddress && rva < sec.VirtualAddress + sec.VirtualSize)
                {
                    return sec.PointerToRawData + (rva - sec.VirtualAddress);
                }
            }
            return rva;
        }
    }

    // Forensics PE analysis helper class
    public static class PEHelper
    {
        public static string GetImpHash(string path, PEFile pe)
        {
            if (!pe.IsPE || pe.ImportTableVA == 0) return "";
            try
            {
                List<string> imports = new List<string>();
                uint importOffset = pe.RvaToOffset(pe.ImportTableVA);
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (BinaryReader br = new BinaryReader(fs))
                {
                    fs.Position = importOffset;
                    while (true)
                    {
                        uint iltVA = br.ReadUInt32();
                        uint timeDateStamp = br.ReadUInt32();
                        uint forwarderChain = br.ReadUInt32();
                        uint nameVA = br.ReadUInt32();
                        uint iatVA = br.ReadUInt32();

                        if (iltVA == 0 && nameVA == 0) break;

                        long savedPos = fs.Position;

                        // Read DLL name
                        fs.Position = pe.RvaToOffset(nameVA);
                        StringBuilder dllNameBuilder = new StringBuilder();
                        while (true)
                        {
                            byte b = br.ReadByte();
                            if (b == 0) break;
                            dllNameBuilder.Append((char)b);
                        }
                        string dllName = dllNameBuilder.ToString().ToLower();
                        if (dllName.EndsWith(".dll")) dllName = dllName.Substring(0, dllName.Length - 4);

                        // Read imported APIs
                        uint tableVA = iltVA != 0 ? iltVA : iatVA;
                        fs.Position = pe.RvaToOffset(tableVA);
                        while (true)
                        {
                            ulong val = pe.Is64Bit ? br.ReadUInt64() : br.ReadUInt32();
                            if (val == 0) break;

                            bool isOrdinal = pe.Is64Bit ? ((val & 0x8000000000000000) != 0) : ((val & 0x80000000) != 0);
                            if (isOrdinal)
                            {
                                ushort ord = (ushort)(val & 0xFFFF);
                                imports.Add(dllName + "." + ord);
                            }
                            else
                            {
                                uint nameRva = (uint)(val & 0x7FFFFFFF);
                                long apiSavedPos = fs.Position;
                                fs.Position = pe.RvaToOffset(nameRva) + 2; // Skip Hint
                                StringBuilder apiNameBuilder = new StringBuilder();
                                while (true)
                                {
                                    byte b = br.ReadByte();
                                    if (b == 0) break;
                                    apiNameBuilder.Append((char)b);
                                }
                                imports.Add(dllName + "." + apiNameBuilder.ToString().ToLower());
                                fs.Position = apiSavedPos;
                            }
                        }
                        fs.Position = savedPos;
                    }
                }

                if (imports.Count == 0) return "";
                string importStr = string.Join(",", imports.ToArray());
                using (MD5 md5 = MD5.Create())
                {
                    byte[] hash = md5.ComputeHash(Encoding.ASCII.GetBytes(importStr));
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < hash.Length; i++) sb.Append(hash[i].ToString("x2"));
                    return sb.ToString();
                }
            }
            catch
            {
                return "";
            }
        }

        public static string GetImportHash(string path, PEFile pe)
        {
            if (!pe.IsPE || pe.ImportTableVA == 0 || pe.ImportTableSize == 0) return "";
            try
            {
                uint offset = pe.RvaToOffset(pe.ImportTableVA);
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    fs.Position = offset;
                    byte[] data = new byte[pe.ImportTableSize];
                    int read = fs.Read(data, 0, data.Length);
                    using (MD5 md5 = MD5.Create())
                    {
                        byte[] hash = md5.ComputeHash(data, 0, read);
                        StringBuilder sb = new StringBuilder();
                        for (int i = 0; i < hash.Length; i++) sb.Append(hash[i].ToString("x2"));
                        return sb.ToString();
                    }
                }
            }
            catch
            {
                return "";
            }
        }

        public static string GetAuthentihash(string path, PEFile pe)
        {
            if (!pe.IsPE) return "";
            try
            {
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (SHA256 sha = SHA256.Create())
                {
                    byte[] buffer = new byte[1024 * 1024];
                    int read;

                    uint checksumOffset = pe.PEHeaderOffset + 24 + 64;
                    uint securityDirOffset = pe.Is64Bit ? (pe.PEHeaderOffset + 24 + 144) : (pe.PEHeaderOffset + 24 + 128);

                    long fileLength = fs.Length;
                    long limit = pe.SecurityTableOffset > 0 && pe.SecurityTableOffset < fileLength ? pe.SecurityTableOffset : fileLength;

                    long currentPos = 0;
                    fs.Position = 0;

                    while (currentPos < limit)
                    {
                        int toRead = (int)Math.Min(buffer.Length, limit - currentPos);
                        read = fs.Read(buffer, 0, toRead);
                        if (read <= 0) break;

                        for (int i = 0; i < read; i++)
                        {
                            long pos = currentPos + i;
                            if (pos >= checksumOffset && pos < checksumOffset + 4)
                            {
                                buffer[i] = 0;
                            }
                            if (pos >= securityDirOffset && pos < securityDirOffset + 8)
                            {
                                buffer[i] = 0;
                            }
                        }

                        sha.TransformBlock(buffer, 0, read, null, 0);
                        currentPos += read;
                    }

                    sha.TransformFinalBlock(new byte[0], 0, 0);
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < sha.Hash.Length; i++) sb.Append(sha.Hash[i].ToString("x2"));
                    return sb.ToString();
                }
            }
            catch
            {
                return "";
            }
        }

        public static string GetRichPEHash(string path, PEFile pe)
        {
            if (!pe.IsPE) return "";
            try
            {
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (BinaryReader br = new BinaryReader(fs))
                {
                    if (pe.PEHeaderOffset < 0x80) return "";
                    fs.Position = 0x80;
                    byte[] headerData = br.ReadBytes((int)(pe.PEHeaderOffset - 0x80));
                    
                    int richIndex = -1;
                    for (int i = 0; i < headerData.Length - 7; i++)
                    {
                        if (headerData[i] == 0x52 && headerData[i + 1] == 0x69 && headerData[i + 2] == 0x63 && headerData[i + 3] == 0x68)
                        {
                            richIndex = i;
                            break;
                        }
                    }
                    if (richIndex == -1) return "";

                    uint xorKey = BitConverter.ToUInt32(headerData, richIndex + 4);

                    int dansIndex = -1;
                    for (int i = richIndex - 4; i >= 0; i--)
                    {
                        if (headerData[i] == 0x44 && headerData[i + 1] == 0x61 && headerData[i + 2] == 0x6e && headerData[i + 3] == 0x53)
                        {
                            dansIndex = i;
                            break;
                        }
                    }
                    if (dansIndex == -1) return "";

                    int richLen = richIndex - dansIndex;
                    byte[] richDecrypted = new byte[richLen];
                    for (int i = 0; i < richLen; i++)
                    {
                        byte keyByte = (byte)(xorKey >> ((i % 4) * 8) & 0xFF);
                        richDecrypted[i] = (byte)(headerData[dansIndex + i] ^ keyByte);
                    }

                    using (MD5 md5 = MD5.Create())
                    {
                        byte[] hash = md5.ComputeHash(richDecrypted);
                        StringBuilder sb = new StringBuilder();
                        for (int i = 0; i < hash.Length; i++) sb.Append(hash[i].ToString("x2"));
                        return sb.ToString();
                    }
                }
            }
            catch
            {
                return "";
            }
        }

        public static string GetPE256(string path, PEFile pe)
        {
            if (!pe.IsPE) return "";
            try
            {
                using (MemoryStream ms = new MemoryStream())
                using (BinaryWriter bw = new BinaryWriter(ms))
                {
                    bw.Write(pe.Subsystem);
                    bw.Write(pe.Characteristics);
                    bw.Write(pe.Is64Bit ? (ushort)0x20B : (ushort)0x10B);
                    bw.Write(pe.SectionAlignment);
                    bw.Write(pe.FileAlignment);
                    bw.Write(pe.AddressOfEntryPoint);
                    bw.Write(pe.NumberOfSections);
                    foreach (var sec in pe.Sections)
                    {
                        bw.Write(sec.VirtualSize);
                        bw.Write(sec.SizeOfRawData);
                        bw.Write(sec.Characteristics);
                    }

                    using (SHA256 sha = SHA256.Create())
                    {
                        byte[] hash = sha.ComputeHash(ms.ToArray());
                        StringBuilder sb = new StringBuilder();
                        for (int i = 0; i < hash.Length; i++) sb.Append(hash[i].ToString("x2"));
                        return sb.ToString();
                    }
                }
            }
            catch
            {
                return "";
            }
        }

        public static string GetIconMD5(string path)
        {
            try
            {
                using (Icon icon = Icon.ExtractAssociatedIcon(path))
                {
                    if (icon == null) return "";
                    using (MemoryStream ms = new MemoryStream())
                    {
                        icon.Save(ms);
                        using (MD5 md5 = MD5.Create())
                        {
                            byte[] hash = md5.ComputeHash(ms.ToArray());
                            StringBuilder sb = new StringBuilder();
                            for (int i = 0; i < hash.Length; i++) sb.Append(hash[i].ToString("x2"));
                            return sb.ToString();
                        }
                    }
                }
            }
            catch
            {
                return "";
            }
        }

        public static string GetSectionHash(string path, PEFile pe)
        {
            if (!pe.IsPE || pe.Sections.Count == 0) return "";
            try
            {
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (MD5 md5 = MD5.Create())
                {
                    List<byte> combinedHashBytes = new List<byte>();
                    foreach (var sec in pe.Sections)
                    {
                        if (sec.PointerToRawData > 0 && sec.SizeOfRawData > 0)
                        {
                            fs.Position = sec.PointerToRawData;
                            byte[] data = new byte[sec.SizeOfRawData];
                            int read = fs.Read(data, 0, data.Length);
                            byte[] secHash = md5.ComputeHash(data, 0, read);
                            combinedHashBytes.AddRange(secHash);
                        }
                    }

                    if (combinedHashBytes.Count == 0) return "";
                    byte[] finalHash = md5.ComputeHash(combinedHashBytes.ToArray());
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < finalHash.Length; i++) sb.Append(finalHash[i].ToString("x2"));
                    return sb.ToString();
                }
            }
            catch
            {
                return "";
            }
        }
    }
}
