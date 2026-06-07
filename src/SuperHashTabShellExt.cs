using System;
using System.IO;
using System.Text;
using System.Drawing;
using System.Threading;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Diagnostics;
using System.Collections.Generic;
using Microsoft.Win32;

namespace SuperHashTab
{
    // COM Interface definitions
    [ComImport]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    [Guid("000214E8-0000-0000-C000-000000000046")]
    public interface IShellExtInit
    {
        [PreserveSig]
        int Initialize(IntPtr pidlFolder, IntPtr pDataObj, IntPtr hKeyProgID);
    }

    [ComImport]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    [Guid("000214E9-0000-0000-C000-000000000046")]
    public interface IShellPropSheetExt
    {
        [PreserveSig]
        int AddPages(IntPtr lpfnAddPage, IntPtr lParam);

        [PreserveSig]
        int ReplacePage(uint uPageID, IntPtr lpfnReplaceWith, IntPtr lParam);
    }

    // COM Class implementation
    [ComVisible(true)]
    [Guid("A95DDF0F-87E8-4CD4-B97F-9F1F0E4D5174")]
    [ClassInterface(ClassInterfaceType.None)]
    public class HashTabShellExt : IShellExtInit, IShellPropSheetExt
    {
        private string filePath = "";
        private DlgProc dlgProcDelegate;
        private PropSheetPageProc pageCallbackDelegate;
        private IntPtr hDlg = IntPtr.Zero;
        private HashTabControl hashControl;

        public int Initialize(IntPtr pidlFolder, IntPtr pDataObj, IntPtr hKeyProgID)
        {
            if (pDataObj == IntPtr.Zero)
                return HRESULT.E_INVALIDARG;

            try
            {
                System.Runtime.InteropServices.ComTypes.IDataObject dataObject = (System.Runtime.InteropServices.ComTypes.IDataObject)Marshal.GetObjectForIUnknown(pDataObj);
                FORMATETC formatEtc = new FORMATETC();
                formatEtc.cfFormat = 15; // CF_HDROP
                formatEtc.ptd = IntPtr.Zero;
                formatEtc.dwAspect = DVASPECT.DVASPECT_CONTENT;
                formatEtc.lindex = -1;
                formatEtc.tymed = TYMED.TYMED_HGLOBAL;

                STGMEDIUM medium;
                dataObject.GetData(ref formatEtc, out medium);

                if (medium.tymed == TYMED.TYMED_HGLOBAL)
                {
                    IntPtr hDrop = medium.unionmember;
                    uint count = DragQueryFile(hDrop, 0xFFFFFFFF, null, 0);
                    if (count > 0)
                    {
                        StringBuilder sb = new StringBuilder(260);
                        DragQueryFile(hDrop, 0, sb, (uint)sb.Capacity);
                        this.filePath = sb.ToString();
                    }
                }
                return HRESULT.S_OK;
            }
            catch (Exception)
            {
                return HRESULT.E_FAIL;
            }
        }

        public int AddPages(IntPtr lpfnAddPage, IntPtr lParam)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                return HRESULT.S_OK;

            try
            {
                DLGTEMPLATE template = new DLGTEMPLATE();
                template.style = WS_CHILD | WS_VISIBLE | DS_SETFONT | DS_3DLOOK;
                template.dwExtendedStyle = 0;
                template.citms = 0;
                template.x = 0;
                template.y = 0;
                template.cx = 250;
                template.cy = 220;

                byte[] templateBytes = CreateDialogTemplate(template, "Segoe UI", 9, Locale.T("TabTitle"));

                IntPtr pTemplate = Marshal.AllocHGlobal(templateBytes.Length);
                Marshal.Copy(templateBytes, 0, pTemplate, templateBytes.Length);

                PROPSHEETPAGE psp = new PROPSHEETPAGE();
                psp.dwSize = (uint)Marshal.SizeOf(typeof(PROPSHEETPAGE));
                psp.dwFlags = PSP_DLGINDIRECT | PSP_USECALLBACK | PSP_USETITLE;
                psp.hInstance = Marshal.GetHINSTANCE(typeof(HashTabShellExt).Module);
                psp.pTemplate = pTemplate;
                psp.pszTitle = Locale.T("TabTitle");

                this.dlgProcDelegate = new DlgProc(DialogProcedure);
                psp.pfnDlgProc = Marshal.GetFunctionPointerForDelegate(this.dlgProcDelegate);

                this.pageCallbackDelegate = new PropSheetPageProc(PageCallback);
                psp.pfnCallback = Marshal.GetFunctionPointerForDelegate(this.pageCallbackDelegate);

                GCHandle gch = GCHandle.Alloc(this);
                psp.lParam = GCHandle.ToIntPtr(gch);

                IntPtr hPage = CreatePropertySheetPage(ref psp);
                if (hPage != IntPtr.Zero)
                {
                    LPFNADDPROPSHEETPAGE addPage = (LPFNADDPROPSHEETPAGE)Marshal.GetDelegateForFunctionPointer(lpfnAddPage, typeof(LPFNADDPROPSHEETPAGE));
                    if (addPage(hPage, lParam))
                    {
                        return HRESULT.S_OK;
                    }
                    else
                    {
                        DestroyPropertySheetPage(hPage);
                    }
                }
                return HRESULT.E_FAIL;
            }
            catch (Exception)
            {
                return HRESULT.E_FAIL;
            }
        }

        public int ReplacePage(uint uPageID, IntPtr lpfnReplaceWith, IntPtr lParam)
        {
            return HRESULT.E_NOTIMPL;
        }

        private byte[] CreateDialogTemplate(DLGTEMPLATE template, string fontName, ushort fontSize, string title)
        {
            using (MemoryStream ms = new MemoryStream())
            using (BinaryWriter bw = new BinaryWriter(ms))
            {
                bw.Write(template.style);
                bw.Write(template.dwExtendedStyle);
                bw.Write(template.citms);
                bw.Write(template.x);
                bw.Write(template.y);
                bw.Write(template.cx);
                bw.Write(template.cy);

                bw.Write((ushort)0);
                bw.Write((ushort)0);

                byte[] titleBytes = Encoding.Unicode.GetBytes(title + "\0");
                bw.Write(titleBytes);

                if ((template.style & DS_SETFONT) != 0)
                {
                    bw.Write(fontSize);
                    byte[] fontBytes = Encoding.Unicode.GetBytes(fontName + "\0");
                    bw.Write(fontBytes);
                }

                return ms.ToArray();
            }
        }

        private IntPtr DialogProcedure(IntPtr hWnd, uint uMsg, IntPtr wParam, IntPtr lParam)
        {
            switch (uMsg)
            {
                case WM_INITDIALOG:
                    try
                    {
                        PROPSHEETPAGE psp = (PROPSHEETPAGE)Marshal.PtrToStructure(lParam, typeof(PROPSHEETPAGE));
                        GCHandle gch = GCHandle.FromIntPtr(psp.lParam);
                        HashTabShellExt instance = (HashTabShellExt)gch.Target;

                        instance.hDlg = hWnd;

                        instance.hashControl = new HashTabControl(instance.filePath);
                        SetParent(instance.hashControl.Handle, hWnd);

                        RECT rect = new RECT();
                        GetClientRect(hWnd, out rect);
                        instance.hashControl.SetBounds(0, 0, rect.right - rect.left, rect.bottom - rect.top);
                    }
                    catch (Exception)
                    {
                    }
                    return (IntPtr)1;

                case WM_SIZE:
                    if (this.hashControl != null)
                    {
                        RECT rect = new RECT();
                        GetClientRect(hWnd, out rect);
                        this.hashControl.SetBounds(0, 0, rect.right - rect.left, rect.bottom - rect.top);
                    }
                    break;

                case WM_DESTROY:
                    if (this.hashControl != null)
                    {
                        this.hashControl.Dispose();
                        this.hashControl = null;
                    }
                    break;
            }
            return IntPtr.Zero;
        }

        private uint PageCallback(IntPtr hwnd, uint uMsg, IntPtr ppsp)
        {
            if (uMsg == PSPCB_RELEASE)
            {
                try
                {
                    PROPSHEETPAGE psp = (PROPSHEETPAGE)Marshal.PtrToStructure(ppsp, typeof(PROPSHEETPAGE));
                    if (psp.pTemplate != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(psp.pTemplate);
                    }
                    if (psp.lParam != IntPtr.Zero)
                    {
                        GCHandle gch = GCHandle.FromIntPtr(psp.lParam);
                        if (gch.IsAllocated)
                        {
                            gch.Free();
                        }
                    }
                }
                catch (Exception)
                {
                }
            }
            return 1;
        }

        [ComRegisterFunction]
        public static void Register(Type t)
        {
            try
            {
                using (RegistryKey key = Registry.ClassesRoot.CreateSubKey(@"*\shellex\PropertySheetHandlers\SuperHashTab"))
                {
                    key.SetValue("", "{" + t.GUID.ToString().ToUpper() + "}");
                }
                using (RegistryKey key = Registry.ClassesRoot.CreateSubKey(@"Directory\shellex\PropertySheetHandlers\SuperHashTab"))
                {
                    key.SetValue("", "{" + t.GUID.ToString().ToUpper() + "}");
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine("Failed to register: " + ex.Message);
            }
        }

        [ComUnregisterFunction]
        public static void Unregister(Type t)
        {
            try
            {
                Registry.ClassesRoot.DeleteSubKeyTree(@"*\shellex\PropertySheetHandlers\SuperHashTab", false);
                Registry.ClassesRoot.DeleteSubKeyTree(@"Directory\shellex\PropertySheetHandlers\SuperHashTab", false);
            }
            catch (Exception ex)
            {
                Trace.WriteLine("Failed to unregister: " + ex.Message);
            }
        }

        // P/Invoke Imports
        [DllImport("shell32.dll", CharSet = CharSet.Auto)]
        private static extern uint DragQueryFile(IntPtr hDrop, uint iFile, StringBuilder lpszFile, uint cch);

        [DllImport("comctl32.dll", EntryPoint = "CreatePropertySheetPageW", CharSet = CharSet.Unicode)]
        private static extern IntPtr CreatePropertySheetPage(ref PROPSHEETPAGE psp);

        [DllImport("comctl32.dll", EntryPoint = "DestroyPropertySheetPage")]
        private static extern bool DestroyPropertySheetPage(IntPtr hPage);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr SetParent(IntPtr hWndChild, IntPtr hWndNewParent);

        [DllImport("user32.dll")]
        private static extern bool GetClientRect(IntPtr hWnd, out RECT lpRect);

        // Win32 structures
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool LPFNADDPROPSHEETPAGE(IntPtr hPage, IntPtr lParam);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr DlgProc(IntPtr hWnd, uint uMsg, IntPtr wParam, IntPtr lParam);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint PropSheetPageProc(IntPtr hwnd, uint uMsg, IntPtr ppsp);

        [StructLayout(LayoutKind.Sequential, Pack = 2)]
        public struct DLGTEMPLATE
        {
            public uint style;
            public uint dwExtendedStyle;
            public ushort citms;
            public short x;
            public short y;
            public short cx;
            public short cy;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct PROPSHEETPAGE
        {
            public uint dwSize;
            public uint dwFlags;
            public IntPtr hInstance;
            public IntPtr pTemplate;
            public IntPtr hIcon;
            public string pszTitle;
            public IntPtr pfnDlgProc;
            public IntPtr lParam;
            public IntPtr pfnCallback;
            public IntPtr pcRefParent;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RECT
        {
            public int left;
            public int top;
            public int right;
            public int bottom;
        }

        public static class HRESULT
        {
            public const int S_OK = 0;
            public const int E_FAIL = unchecked((int)0x80004005);
            public const int E_INVALIDARG = unchecked((int)0x80070057);
            public const int E_NOTIMPL = unchecked((int)0x80004001);
        }

        private const uint WS_CHILD = 0x40000000;
        private const uint WS_VISIBLE = 0x10000000;
        private const uint DS_SETFONT = 0x40;
        private const uint DS_3DLOOK = 0x0004;

        private const uint PSP_DLGINDIRECT = 0x00000001;
        private const uint PSP_USECALLBACK = 0x00000080;
        private const uint PSP_USETITLE = 0x00000020;

        private const uint PSPCB_RELEASE = 1;

        private const uint WM_INITDIALOG = 0x0110;
        private const uint WM_SIZE = 0x0005;
        private const uint WM_DESTROY = 0x0002;
    }
}
