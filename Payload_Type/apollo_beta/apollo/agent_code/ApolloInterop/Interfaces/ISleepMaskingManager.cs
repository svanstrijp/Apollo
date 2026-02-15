using System;

namespace ApolloInterop.Interfaces
{
    public interface ISleepMaskingManager
    {
        void RegisterRegion(IntPtr hProcess, IntPtr baseAddress, int size);
        void UnregisterRegion(IntPtr baseAddress);
        void MaskAllRegions();
        void UnmaskAllRegions();
    }
}
