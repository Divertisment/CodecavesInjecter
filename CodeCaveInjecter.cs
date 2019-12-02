using System;
using System.IO;
using System.IO.Pipes;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Threading;
using System.Globalization;
using System.Windows.Forms;
using System.Security.Principal;
using System.Threading.Tasks;
using System.Collections.Concurrent;
namespace CodeCaveInjecter
{
    public class Injecter
    {
        #region DLL + Memory Declaration
        [DllImport("kernel32.dll")]
        private static extern bool ReadProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, [Out] byte[] lpBuffer, UIntPtr nSize, IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        private static extern bool ReadProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, [Out] byte[] lpBuffer, UIntPtr nSize, out ulong lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        private static extern bool ReadProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, [Out] IntPtr lpBuffer, UIntPtr nSize, out ulong lpNumberOfBytesRead);
        [DllImport("kernel32.dll")]
        public static extern int WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [In] [Out] byte[] bBuffer, uint size, out IntPtr lpNumberOfBytesWritten);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        static extern uint GetPrivateProfileString(
           string lpAppName,
           string lpKeyName,
           string lpDefault,
           StringBuilder lpReturnedString,
           uint nSize,
           string lpFileName);
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern UIntPtr VirtualAllocEx(
            IntPtr hProcess,
            UIntPtr lpAddress,
            uint dwSize,
            uint flAllocationType,
            uint flProtect);
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern bool VirtualFreeEx(
            IntPtr hProcess,
            UIntPtr lpAddress,
            UIntPtr dwSize,
            uint dwFreeType
            );
        [DllImport("kernel32.dll")]
        public static extern void VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, FreeType dwFreeType);
        [Flags]
        public enum FreeType
        {
            Decommit = 0x4000,
            Release = 0x8000,
        }
        public void Dealloc(Process Proc, IntPtr AllocatedAddress)
        {
            VirtualFreeEx(Proc.Handle, AllocatedAddress, 0, FreeType.Release);
        }
        [DllImport("kernel32.dll", EntryPoint = "VirtualQueryEx")]
        public static extern UIntPtr Native_VirtualQueryEx(IntPtr hProcess, UIntPtr lpAddress,
            out MEMORY_BASIC_INFORMATION32 lpBuffer, UIntPtr dwLength);
        [DllImport("kernel32.dll", EntryPoint = "VirtualQueryEx")]
        public static extern UIntPtr Native_VirtualQueryEx(IntPtr hProcess, UIntPtr lpAddress,
            out MEMORY_BASIC_INFORMATION64 lpBuffer, UIntPtr dwLength);
        [DllImport("kernel32.dll")]
        static extern uint GetLastError();
        [DllImport("kernel32")]
        public static extern bool IsWow64Process(IntPtr hProcess, out bool lpSystemInfo);
        [DllImport("kernel32.dll")]
        static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

        public UIntPtr VirtualQueryEx(IntPtr hProcess, UIntPtr lpAddress,
            out MEMORY_BASIC_INFORMATION lpBuffer)
        {
            UIntPtr returnVal;
            Is64Bit = Environment.Is64BitOperatingSystem && (IsWow64Process(hProcess, out bool retVal) && !retVal);
            // TODO: Need to change this to only check once.
            if (Is64Bit || IntPtr.Size == 8)
            {
                // 64 bit
                MEMORY_BASIC_INFORMATION64 tmp64 = new MEMORY_BASIC_INFORMATION64();
                returnVal = Native_VirtualQueryEx(hProcess, lpAddress, out tmp64, new UIntPtr((uint)Marshal.SizeOf(tmp64)));

                lpBuffer.BaseAddress = tmp64.BaseAddress;
                lpBuffer.AllocationBase = tmp64.AllocationBase;
                lpBuffer.AllocationProtect = tmp64.AllocationProtect;
                lpBuffer.RegionSize = (long)tmp64.RegionSize;
                lpBuffer.State = tmp64.State;
                lpBuffer.Protect = tmp64.Protect;
                lpBuffer.Type = tmp64.Type;

                return returnVal;
            }

            MEMORY_BASIC_INFORMATION32 tmp32 = new MEMORY_BASIC_INFORMATION32();

            returnVal = Native_VirtualQueryEx(hProcess, lpAddress, out tmp32, new UIntPtr((uint)Marshal.SizeOf(tmp32)));

            lpBuffer.BaseAddress = tmp32.BaseAddress;
            lpBuffer.AllocationBase = tmp32.AllocationBase;
            lpBuffer.AllocationProtect = tmp32.AllocationProtect;
            lpBuffer.RegionSize = tmp32.RegionSize;
            lpBuffer.State = tmp32.State;
            lpBuffer.Protect = tmp32.Protect;
            lpBuffer.Type = tmp32.Type;

            return returnVal;
        }
        public UIntPtr FindFreeBlockForRegion(IntPtr hProcess, UIntPtr baseAddress, uint size)
        {
            UIntPtr minAddress = UIntPtr.Subtract(baseAddress, 0x70000000);
            UIntPtr maxAddress = UIntPtr.Add(baseAddress, 0x70000000);

            UIntPtr ret = UIntPtr.Zero;
            UIntPtr tmpAddress = UIntPtr.Zero;

            GetSystemInfo(out SYSTEM_INFO si);
            Is64Bit = Environment.Is64BitOperatingSystem && (IsWow64Process(hProcess, out bool retVal) && !retVal);
            if (Is64Bit)
            {
                if ((long)minAddress > (long)si.maximumApplicationAddress ||
                    (long)minAddress < (long)si.minimumApplicationAddress)
                    minAddress = si.minimumApplicationAddress;

                if ((long)maxAddress < (long)si.minimumApplicationAddress ||
                    (long)maxAddress > (long)si.maximumApplicationAddress)
                    maxAddress = si.maximumApplicationAddress;
            }
            else
            {
                minAddress = si.minimumApplicationAddress;
                maxAddress = si.maximumApplicationAddress;
            }

            MEMORY_BASIC_INFORMATION mbi;

            UIntPtr current = minAddress;
            UIntPtr previous = current;

            while (VirtualQueryEx(hProcess, current, out mbi).ToUInt64() != 0)
            {
                if ((long)mbi.BaseAddress > (long)maxAddress)
                    return UIntPtr.Zero;  // No memory found, let windows handle

                if (mbi.State == 0x10000/*MEM_FREE*/ && mbi.RegionSize > size)
                {
                    if ((long)mbi.BaseAddress % si.allocationGranularity > 0)
                    {
                        // The whole size can not be used
                        tmpAddress = mbi.BaseAddress;
                        int offset = (int)(si.allocationGranularity -
                                           ((long)tmpAddress % si.allocationGranularity));

                        // Check if there is enough left
                        if ((mbi.RegionSize - offset) >= size)
                        {
                            // yup there is enough
                            tmpAddress = UIntPtr.Add(tmpAddress, offset);

                            if ((long)tmpAddress < (long)baseAddress)
                            {
                                tmpAddress = UIntPtr.Add(tmpAddress, (int)(mbi.RegionSize - offset - size));

                                if ((long)tmpAddress > (long)baseAddress)
                                    tmpAddress = baseAddress;

                                // decrease tmpAddress until its alligned properly
                                tmpAddress = UIntPtr.Subtract(tmpAddress, (int)((long)tmpAddress % si.allocationGranularity));
                            }

                            // if the difference is closer then use that
                            if (Math.Abs((long)tmpAddress - (long)baseAddress) < Math.Abs((long)ret - (long)baseAddress))
                                ret = tmpAddress;
                        }
                    }
                    else
                    {
                        tmpAddress = mbi.BaseAddress;

                        if ((long)tmpAddress < (long)baseAddress) // try to get it the cloest possible 
                                                                  // (so to the end of the region - size and
                                                                  // aligned by system allocation granularity)
                        {
                            tmpAddress = UIntPtr.Add(tmpAddress, (int)(mbi.RegionSize - size));

                            if ((long)tmpAddress > (long)baseAddress)
                                tmpAddress = baseAddress;

                            // decrease until aligned properly
                            tmpAddress =
                                UIntPtr.Subtract(tmpAddress, (int)((long)tmpAddress % si.allocationGranularity));
                        }

                        if (Math.Abs((long)tmpAddress - (long)baseAddress) < Math.Abs((long)ret - (long)baseAddress))
                            ret = tmpAddress;
                    }
                }

                if (mbi.RegionSize % si.allocationGranularity > 0)
                    mbi.RegionSize += si.allocationGranularity - (mbi.RegionSize % si.allocationGranularity);

                previous = current;
                current = UIntPtr.Add(mbi.BaseAddress, (int)mbi.RegionSize);

                if ((long)current > (long)maxAddress)
                    return ret;

                if ((long)previous > (long)current)
                    return ret; // Overflow
            }

            return ret;
        }
        bool Is64Bit;
        public struct SYSTEM_INFO
        {
            public ushort processorArchitecture;
            ushort reserved;
            public uint pageSize;
            public UIntPtr minimumApplicationAddress;
            public UIntPtr maximumApplicationAddress;
            public IntPtr activeProcessorMask;
            public uint numberOfProcessors;
            public uint processorType;
            public uint allocationGranularity;
            public ushort processorLevel;
            public ushort processorRevision;
        }

        public struct MEMORY_BASIC_INFORMATION32
        {
            public UIntPtr BaseAddress;
            public UIntPtr AllocationBase;
            public uint AllocationProtect;
            public uint RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        public struct MEMORY_BASIC_INFORMATION64
        {
            public UIntPtr BaseAddress;
            public UIntPtr AllocationBase;
            public uint AllocationProtect;
            public uint __alignment1;
            public ulong RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
            public uint __alignment2;
        }

        public struct MEMORY_BASIC_INFORMATION
        {
            public UIntPtr BaseAddress;
            public UIntPtr AllocationBase;
            public uint AllocationProtect;
            public long RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        public ulong getMinAddress()
        {
            SYSTEM_INFO SI;
            GetSystemInfo(out SI);
            return (ulong)SI.minimumApplicationAddress;
        }
        public byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }
        public UIntPtr getCode(Process process, string name, string path = "", int size = 8)
        {
            string theCode = "";
            Is64Bit = Environment.Is64BitOperatingSystem && (IsWow64Process(process.Handle, out bool retVal) && !retVal);
            if (Is64Bit)
            {
                //Debug.WriteLine("Changing to 64bit code...");
                if (size == 8) size = 16; //change to 64bit
                return get64bitCode(process, name, path, size); //jump over to 64bit code grab
            }

            if (path != "")
                theCode = LoadCode(name, path);
            else
                theCode = name;

            if (theCode == "")
            {
                //Debug.WriteLine("ERROR: LoadCode returned blank. NAME:" + name + " PATH:" + path);
                return UIntPtr.Zero;
            }
            else
            {
                //Debug.WriteLine("Found code=" + theCode + " NAME:" + name + " PATH:" + path);
            }

            // remove spaces
            if (theCode.Contains(" "))
                theCode.Replace(" ", String.Empty);

            if (!theCode.Contains("+") && !theCode.Contains(",")) return new UIntPtr(Convert.ToUInt32(theCode, 16));

            string newOffsets = theCode;

            if (theCode.Contains("+"))
                newOffsets = theCode.Substring(theCode.IndexOf('+') + 1);

            byte[] memoryAddress = new byte[size];

            if (newOffsets.Contains(','))
            {
                List<int> offsetsList = new List<int>();

                string[] newerOffsets = newOffsets.Split(',');
                foreach (string oldOffsets in newerOffsets)
                {
                    string test = oldOffsets;
                    if (oldOffsets.Contains("0x")) test = oldOffsets.Replace("0x", "");
                    int preParse = 0;
                    if (!oldOffsets.Contains("-"))
                        preParse = Int32.Parse(test, NumberStyles.AllowHexSpecifier);
                    else
                    {
                        test = test.Replace("-", "");
                        preParse = Int32.Parse(test, NumberStyles.AllowHexSpecifier);
                        preParse = preParse * -1;
                    }
                    offsetsList.Add(preParse);
                }
                int[] offsets = offsetsList.ToArray();

                if (theCode.Contains("base") || theCode.Contains("main"))
                    ReadProcessMemory(process.Handle, (UIntPtr)((int)process.MainModule.BaseAddress + offsets[0]), memoryAddress, (UIntPtr)size, IntPtr.Zero);
                else if (!theCode.Contains("base") && !theCode.Contains("main") && theCode.Contains("+"))
                {
                    string[] moduleName = theCode.Split('+');
                    IntPtr altModule = IntPtr.Zero;
                    if (!moduleName[0].Contains(".dll") && !moduleName[0].Contains(".exe"))
                    {
                        string theAddr = moduleName[0];
                        if (theAddr.Contains("0x")) theAddr = theAddr.Replace("0x", "");
                        altModule = (IntPtr)Int32.Parse(theAddr, NumberStyles.HexNumber);
                    }
                    else
                    {
                        try
                        {
                            altModule = modules[moduleName[0]];
                        }
                        catch
                        {
                            //Debug.WriteLine("Module " + moduleName[0] + " was not found in module list!");
                            // Debug.WriteLine("Modules: " + string.Join(",", modules));
                        }
                    }
                    ReadProcessMemory(process.Handle, (UIntPtr)((int)altModule + offsets[0]), memoryAddress, (UIntPtr)size, IntPtr.Zero);
                }
                else
                    ReadProcessMemory(process.Handle, (UIntPtr)(offsets[0]), memoryAddress, (UIntPtr)size, IntPtr.Zero);

                uint num1 = BitConverter.ToUInt32(memoryAddress, 0); //ToUInt64 causes arithmetic overflow.

                UIntPtr base1 = (UIntPtr)0;

                for (int i = 1; i < offsets.Length; i++)
                {
                    base1 = new UIntPtr(Convert.ToUInt32(num1 + offsets[i]));
                    ReadProcessMemory(process.Handle, base1, memoryAddress, (UIntPtr)size, IntPtr.Zero);
                    num1 = BitConverter.ToUInt32(memoryAddress, 0); //ToUInt64 causes arithmetic overflow.
                }
                return base1;
            }
            else // no offsets
            {
                int trueCode = Convert.ToInt32(newOffsets, 16);
                IntPtr altModule = IntPtr.Zero;
                //Debug.WriteLine("newOffsets=" + newOffsets);
                if (theCode.Contains("base") || theCode.Contains("main"))
                    altModule = process.MainModule.BaseAddress;
                else if (!theCode.Contains("base") && !theCode.Contains("main") && theCode.Contains("+"))
                {
                    string[] moduleName = theCode.Split('+');
                    if (!moduleName[0].Contains(".dll") && !moduleName[0].Contains(".exe"))
                    {
                        string theAddr = moduleName[0];
                        if (theAddr.Contains("0x")) theAddr = theAddr.Replace("0x", "");
                        altModule = (IntPtr)Int32.Parse(theAddr, NumberStyles.HexNumber);
                    }
                    else
                    {
                        try
                        {
                            altModule = modules[moduleName[0]];
                        }
                        catch
                        {
                            //Debug.WriteLine("Module " + moduleName[0] + " was not found in module list!");
                            //Debug.WriteLine("Modules: " + string.Join(",", modules));
                        }
                    }
                }
                else
                    altModule = modules[theCode.Split('+')[0]];
                return (UIntPtr)((int)altModule + trueCode);
            }
        }
        public UIntPtr get64bitCode(Process process, string name, string path = "", int size = 16)
        {
            string theCode = "";
            if (path != "")
                theCode = LoadCode(name, path);
            else
                theCode = name;

            if (theCode == "")
                return UIntPtr.Zero;

            // remove spaces
            if (theCode.Contains(" "))
                theCode.Replace(" ", String.Empty);

            string newOffsets = theCode;
            if (theCode.Contains("+"))
                newOffsets = theCode.Substring(theCode.IndexOf('+') + 1);

            byte[] memoryAddress = new byte[size];

            if (!theCode.Contains("+") && !theCode.Contains(",")) return new UIntPtr(Convert.ToUInt64(theCode, 16));

            if (newOffsets.Contains(','))
            {
                List<Int64> offsetsList = new List<Int64>();

                string[] newerOffsets = newOffsets.Split(',');
                foreach (string oldOffsets in newerOffsets)
                {
                    string test = oldOffsets;
                    if (oldOffsets.Contains("0x")) test = oldOffsets.Replace("0x", "");
                    Int64 preParse = 0;
                    if (!oldOffsets.Contains("-"))
                        preParse = Int64.Parse(test, NumberStyles.AllowHexSpecifier);
                    else
                    {
                        test = test.Replace("-", "");
                        preParse = Int64.Parse(test, NumberStyles.AllowHexSpecifier);
                        preParse = preParse * -1;
                    }
                    offsetsList.Add(preParse);
                }
                Int64[] offsets = offsetsList.ToArray();

                if (theCode.Contains("base") || theCode.Contains("main"))
                    ReadProcessMemory(process.Handle, (UIntPtr)((Int64)process.MainModule.BaseAddress + offsets[0]), memoryAddress, (UIntPtr)size, IntPtr.Zero);
                else if (!theCode.Contains("base") && !theCode.Contains("main") && theCode.Contains("+"))
                {
                    string[] moduleName = theCode.Split('+');
                    IntPtr altModule = IntPtr.Zero;
                    if (!moduleName[0].Contains(".dll") && !moduleName[0].Contains(".exe"))
                        altModule = (IntPtr)Int64.Parse(moduleName[0], System.Globalization.NumberStyles.HexNumber);
                    else
                    {
                        try
                        {
                            altModule = modules[moduleName[0]];
                        }
                        catch
                        {
                            //Debug.WriteLine("Module " + moduleName[0] + " was not found in module list!");
                            //Debug.WriteLine("Modules: " + string.Join(",", modules));
                        }
                    }
                    ReadProcessMemory(process.Handle, (UIntPtr)((Int64)altModule + offsets[0]), memoryAddress, (UIntPtr)size, IntPtr.Zero);
                }
                else // no offsets
                    ReadProcessMemory(process.Handle, (UIntPtr)(offsets[0]), memoryAddress, (UIntPtr)size, IntPtr.Zero);

                Int64 num1 = BitConverter.ToInt64(memoryAddress, 0);

                UIntPtr base1 = (UIntPtr)0;

                for (int i = 1; i < offsets.Length; i++)
                {
                    base1 = new UIntPtr(Convert.ToUInt64(num1 + offsets[i]));
                    ReadProcessMemory(process.Handle, base1, memoryAddress, (UIntPtr)size, IntPtr.Zero);
                    num1 = BitConverter.ToInt64(memoryAddress, 0);
                }
                return base1;
            }
            else
            {
                Int64 trueCode = Convert.ToInt64(newOffsets, 16);
                IntPtr altModule = IntPtr.Zero;
                if (theCode.Contains("base") || theCode.Contains("main"))
                    altModule = process.MainModule.BaseAddress;
                else if (!theCode.Contains("base") && !theCode.Contains("main") && theCode.Contains("+"))
                {
                    string[] moduleName = theCode.Split('+');
                    if (!moduleName[0].Contains(".dll") && !moduleName[0].Contains(".exe"))
                    {
                        string theAddr = moduleName[0];
                        if (theAddr.Contains("0x")) theAddr = theAddr.Replace("0x", "");
                        altModule = (IntPtr)Int64.Parse(theAddr, NumberStyles.HexNumber);
                    }
                    else
                    {
                        try
                        {
                            altModule = modules[moduleName[0]];
                        }
                        catch
                        {
                            //Debug.WriteLine("Module " + moduleName[0] + " was not found in module list!");
                            //Debug.WriteLine("Modules: " + string.Join(",", modules));
                        }
                    }
                }
                else
                    altModule = modules[theCode.Split('+')[0]];
                return (UIntPtr)((Int64)altModule + trueCode);
            }
        }
        public Task<IEnumerable<long>> AoBScan(Process process, string search, bool writable = false, bool executable = true, string file = "")
        {
            return AoBScan(process, 0, long.MaxValue, search, writable, executable, file);
        }
        public Task<IEnumerable<long>> AoBScan(Process process, long start, long end, string search, bool writable = false, bool executable = true, string file = "")
        {
            // Not including read only memory was scan behavior prior.
            return AoBScan(process, start, end, search, false, writable, executable, file);
        }
        public Task<IEnumerable<long>> AoBScan(Process process, long start, long end, string search, bool readable, bool writable, bool executable, string file = "")
        {
            return Task.Run(() =>
            {
                var memRegionList = new List<MemoryRegionResult>();

                string memCode = LoadCode(search, file);

                string[] stringByteArray = memCode.Split(' ');

                byte[] aobPattern = new byte[stringByteArray.Length];
                byte[] mask = new byte[stringByteArray.Length];

                for (var i = 0; i < stringByteArray.Length; i++)
                {
                    string ba = stringByteArray[i];

                    if (ba == "??" || (ba.Length == 1 && ba == "?"))
                    {
                        mask[i] = 0x00;
                        stringByteArray[i] = "0x00";
                    }
                    else if (Char.IsLetterOrDigit(ba[0]) && ba[1] == '?')
                    {
                        mask[i] = 0xF0;
                        stringByteArray[i] = ba[0] + "0";
                    }
                    else if (Char.IsLetterOrDigit(ba[1]) && ba[0] == '?')
                    {
                        mask[i] = 0x0F;
                        stringByteArray[i] = "0" + ba[1];
                    }
                    else
                        mask[i] = 0xFF;
                }


                for (int i = 0; i < stringByteArray.Length; i++)
                    aobPattern[i] = (byte)(Convert.ToByte(stringByteArray[i], 16) & mask[i]);

                SYSTEM_INFO sys_info = new SYSTEM_INFO();
                GetSystemInfo(out sys_info);

                UIntPtr proc_min_address = sys_info.minimumApplicationAddress;
                UIntPtr proc_max_address = sys_info.maximumApplicationAddress;

                if (start < (long)proc_min_address.ToUInt64())
                    start = (long)proc_min_address.ToUInt64();

                if (end > (long)proc_max_address.ToUInt64())
                    end = (long)proc_max_address.ToUInt64();

                UIntPtr currentBaseAddress = new UIntPtr((ulong)start);

                MEMORY_BASIC_INFORMATION memInfo = new MEMORY_BASIC_INFORMATION();


                while (VirtualQueryEx(process.Handle, currentBaseAddress, out memInfo).ToUInt64() != 0 &&
                       currentBaseAddress.ToUInt64() < (ulong)end &&
                       currentBaseAddress.ToUInt64() + (ulong)memInfo.RegionSize >
                       currentBaseAddress.ToUInt64())
                {
                    bool isValid = memInfo.State == 0x1000/*MEM_COMMIT*/;
                    isValid &= memInfo.BaseAddress.ToUInt64() < (ulong)proc_max_address.ToUInt64();
                    isValid &= ((memInfo.Protect & 0x100/*PAGE_GUARD*/) == 0);
                    isValid &= ((memInfo.Protect & 0x01/*PAGE_NOACCESS*/) == 0);
                    isValid &= (memInfo.Type == 0x20000/*MEM_PRIVATE*/) || (memInfo.Type == 0x1000000/*MEM_IMAGE*/);

                    if (isValid)
                    {
                        bool isReadable = (memInfo.Protect & 0x02/*PAGE_READONLY*/) > 0;

                        bool isWritable = ((memInfo.Protect & 0x04/*PAGE_READWRITE*/) > 0) ||
                                          ((memInfo.Protect & 0x08/*PAGE_WRITECOPY*/) > 0) ||
                                          ((memInfo.Protect & 0x40/*PAGE_EXECUTE_READWRITE*/) > 0) ||
                                          ((memInfo.Protect & 0x80/*PAGE_EXECUTE_WRITECOPY*/) > 0);

                        bool isExecutable = ((memInfo.Protect & 0x10/*PAGE_EXECUTE*/) > 0) ||
                                            ((memInfo.Protect & 0x20/*PAGE_EXECUTE_READ*/) > 0) ||
                                            ((memInfo.Protect & 0x40/*PAGE_EXECUTE_READWRITE*/) > 0) ||
                                            ((memInfo.Protect & 0x80/*PAGE_EXECUTE_WRITECOPY*/) > 0);

                        isReadable &= readable;
                        isWritable &= writable;
                        isExecutable &= executable;

                        isValid &= isReadable || isWritable || isExecutable;
                    }

                    if (!isValid)
                    {
                        currentBaseAddress = new UIntPtr(memInfo.BaseAddress.ToUInt64() + (ulong)memInfo.RegionSize);
                        continue;
                    }

                    MemoryRegionResult memRegion = new MemoryRegionResult
                    {
                        CurrentBaseAddress = currentBaseAddress,
                        RegionSize = memInfo.RegionSize,
                        RegionBase = memInfo.BaseAddress
                    };

                    currentBaseAddress = new UIntPtr(memInfo.BaseAddress.ToUInt64() + (ulong)memInfo.RegionSize);


                    if (memRegionList.Count > 0)
                    {
                        var previousRegion = memRegionList[memRegionList.Count - 1];

                        if ((long)previousRegion.RegionBase + previousRegion.RegionSize == (long)memInfo.BaseAddress)
                        {
                            memRegionList[memRegionList.Count - 1] = new MemoryRegionResult
                            {
                                CurrentBaseAddress = previousRegion.CurrentBaseAddress,
                                RegionBase = previousRegion.RegionBase,
                                RegionSize = previousRegion.RegionSize + memInfo.RegionSize
                            };

                            continue;
                        }
                    }

                    memRegionList.Add(memRegion);
                }

                ConcurrentBag<long> bagResult = new ConcurrentBag<long>();

                Parallel.ForEach(memRegionList,
                                 (item, parallelLoopState, index) =>
                                 {
                                     long[] compareResults = CompareScan(process, item, aobPattern, mask);

                                     foreach (long result in compareResults)
                                         bagResult.Add(result);
                                 });

                return bagResult.ToList().OrderBy(c => c).AsEnumerable();
            });
        }
        public async Task<long> AoBScan(Process process, string code, long end, string search, string file = "")
        {
            long start = (long)getCode(process, code, file).ToUInt64();

            return (await AoBScan(process, start, end, search, true, true, true, file)).FirstOrDefault();
        }
        private long[] CompareScan(Process process, MemoryRegionResult item, byte[] aobPattern, byte[] mask)
        {
            if (mask.Length != aobPattern.Length)
                throw new ArgumentException($"{nameof(aobPattern)}.Length != {nameof(mask)}.Length");

            IntPtr buffer = Marshal.AllocHGlobal((int)item.RegionSize);

            ReadProcessMemory(process.Handle, item.CurrentBaseAddress, buffer, (UIntPtr)item.RegionSize, out ulong bytesRead);

            int result = 0 - aobPattern.Length;
            List<long> ret = new List<long>();
            unsafe
            {
                do
                {

                    result = FindPattern((byte*)buffer.ToPointer(), (int)bytesRead, aobPattern, mask, result + aobPattern.Length);

                    if (result >= 0)
                        ret.Add((long)item.CurrentBaseAddress + result);

                } while (result != -1);
            }

            Marshal.FreeHGlobal(buffer);

            return ret.ToArray();
        }
        private int FindPattern(byte[] body, byte[] pattern, byte[] masks, int start = 0)
        {
            int foundIndex = -1;

            if (body.Length <= 0 || pattern.Length <= 0 || start > body.Length - pattern.Length ||
                pattern.Length > body.Length) return foundIndex;

            for (int index = start; index <= body.Length - pattern.Length; index++)
            {
                if (((body[index] & masks[0]) == (pattern[0] & masks[0])))
                {
                    var match = true;
                    for (int index2 = 1; index2 <= pattern.Length - 1; index2++)
                    {
                        if ((body[index + index2] & masks[index2]) == (pattern[index2] & masks[index2])) continue;
                        match = false;
                        break;

                    }

                    if (!match) continue;

                    foundIndex = index;
                    break;
                }
            }

            return foundIndex;
        }
        private unsafe int FindPattern(byte* body, int bodyLength, byte[] pattern, byte[] masks, int start = 0)
        {
            int foundIndex = -1;

            if (bodyLength <= 0 || pattern.Length <= 0 || start > bodyLength - pattern.Length ||
                pattern.Length > bodyLength) return foundIndex;

            for (int index = start; index <= bodyLength - pattern.Length; index++)
            {
                if (((body[index] & masks[0]) == (pattern[0] & masks[0])))
                {
                    var match = true;
                    for (int index2 = 1; index2 <= pattern.Length - 1; index2++)
                    {
                        if ((body[index + index2] & masks[index2]) == (pattern[index2] & masks[index2])) continue;
                        match = false;
                        break;

                    }

                    if (!match) continue;

                    foundIndex = index;
                    break;
                }
            }

            return foundIndex;
        }
        public string LoadCode(string name, string file)
        {
            StringBuilder returnCode = new StringBuilder(1024);
            uint read_ini_result;

            if (file != "")
                read_ini_result = GetPrivateProfileString("codes", name, "", returnCode, (uint)returnCode.Capacity, file);
            else
                returnCode.Append(name);

            return returnCode.ToString();
        }
        private int LoadIntCode(string name, string path)
        {
            try
            {
                int intValue = Convert.ToInt32(LoadCode(name, path), 16);
                if (intValue >= 0)
                    return intValue;
                else
                    return 0;
            }
            catch
            {
                Debug.WriteLine("ERROR: LoadIntCode function crashed!");
                return 0;
            }
        }

        public Dictionary<string, IntPtr> modules = new Dictionary<string, IntPtr>();
        struct MemoryRegionResult
        {
            public UIntPtr CurrentBaseAddress { get; set; }
            public long RegionSize { get; set; }
            public UIntPtr RegionBase { get; set; }

        }
        #endregion
        public IntPtr Inject(Process process, IntPtr Address, string[] asm_code, int NopNumbersNeeded)
        {
            UIntPtr caveAddress = UIntPtr.Zero;
            UIntPtr address = unchecked((UIntPtr)(long)(ulong)Address);
            UIntPtr prefered = address;
            IntPtr intPtr;

            #region Alloc Memory
            for (var i = 0; i < 10 && caveAddress == UIntPtr.Zero; i++)
            {
                caveAddress = VirtualAllocEx(process.Handle, FindFreeBlockForRegion(process.Handle, prefered, (uint)2048),
                                             (uint)0x10000, 0x1000/*MEM_COMMIT*/ | 0x2000/*MEM_RESERVE*/, 0x40/*PAGE_EXECUTE_READWRITE*/);

                if (caveAddress == UIntPtr.Zero)
                    prefered = UIntPtr.Add(prefered, 0x10000);
            }
            #endregion 
            #region Write Script To Cave
            IntPtr TheCaveAddress = unchecked((IntPtr)(long)(ulong)caveAddress);
            List<byte> Script = new List<byte>(GetByteCode(asm_code, TheCaveAddress));
            byte[] bAddress = BitConverter.GetBytes((int)((long)(address + NopNumbersNeeded) - (long)(TheCaveAddress + Script.ToArray().Length)));
            
            Script.Add(0xE9);
            Script.AddRange(bAddress);
            WriteProcessMemory(process.Handle, TheCaveAddress, Script.ToArray(), (uint)Script.ToArray().Length, out intPtr);
            #endregion
            #region MyAddress Jmp To Cave
            byte[] bCaveAddress = BitConverter.GetBytes((int)((long)TheCaveAddress - (long)address - 5));
            List<byte> Listjmptocodecave = new List<byte>();
            Listjmptocodecave.Add(0xE9);
            Listjmptocodecave.AddRange(bCaveAddress);
            for (int x = 0; x < NopNumbersNeeded; x++)
            {
                Listjmptocodecave.Add(0x90);
            }
            WriteProcessMemory(process.Handle, Address, Listjmptocodecave.ToArray(), (uint)Listjmptocodecave.ToArray().Length, out intPtr);
            #endregion 
            return TheCaveAddress;
        }
        private byte[] GetByteCode(string[] asm_code,IntPtr CaveAddress)
        {
            List<byte> Script = new List<byte>();
            foreach(string asm in asm_code)
            {
                string[] code = asm.Split(' ');
                foreach(string xcode in code)
                {
                    if(xcode.Contains("CaveAddress"))
                    {
                        string XVar = "";
                        if (Is64Bit) { XVar = "X16"; }
                        else { XVar = "X8"; }
                        if (xcode.Contains("+"))
                        {
                            string[] result = xcode.Split('+');
                            IntPtr newAddress = CaveAddress + int.Parse(result[1], NumberStyles.HexNumber);
                            Script.AddRange(StringToByteArray(newAddress.ToString(XVar)).Reverse().ToArray());
                        }
                        else
                        {
                            Script.AddRange(StringToByteArray(CaveAddress.ToString(XVar)).Reverse().ToArray());
                        }
                    }
                    else
                    {
                        Script.AddRange(StringToByteArray(xcode));
                    }
                }
            }
            return Script.ToArray();
        }
        
    }
}
