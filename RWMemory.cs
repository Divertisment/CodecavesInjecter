using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Collections.Generic;
namespace MemoryAPI
{
    public class MAPI
    {
        [DllImport("kernel32.dll")]
        public static extern int ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [In] [Out] byte[] bBuffer, uint size, out IntPtr lpNumberOfBytesRead);
        [DllImport("kernel32.dll")]
        public static extern int WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [In] [Out] byte[] bBuffer, uint size, out IntPtr lpNumberOfBytesWritten);
        [DllImport("kernel32.dll", EntryPoint = "CloseHandle")]
        private static extern bool _CloseHandle(IntPtr hObject);
        [DllImport("kernel32.dll")]
        public static extern int CloseHandle(IntPtr hObject);
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenThread(RWMemory.ThreadAccess dwDesiredAccess, bool bInheritHandle, int dwThreadId);
        [DllImport("kernel32.dll")]
        public static extern uint SuspendThread(IntPtr hThread);
        [DllImport("kernel32.dll")]
        public static extern int ResumeThread(IntPtr hThread);
        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtQueryInformationThread(IntPtr threadHandle, RWMemory.ThreadInfoClass threadInformationClass, IntPtr threadInformation, int threadInformationLength, IntPtr returnLengthPtr);
    }
    public class RWMemory
    {
        public Process GetmReadProcess
        {
            get
            {
                return RWMemory.mReadProcess;
            }
            set
            {
                RWMemory.mReadProcess = value;
            }
        }
        public bool OpenProcess()
        {
            RWMemory.mReadProcess = Process.GetCurrentProcess();
            if (RWMemory.mReadProcess.Handle != IntPtr.Zero)
            {
                RWMemory.hReadProcess = RWMemory.mReadProcess.Handle;
                return true;
            }
            return false;
        }
        public bool OpenProcess(string sProcessName)
        {
            Process[] processesByName = Process.GetProcessesByName(sProcessName);
            if (processesByName.Length == 0)
            {
                return false;
            }
            RWMemory.mReadProcess = processesByName[0];
            if (RWMemory.mReadProcess.Handle != IntPtr.Zero)
            {
                RWMemory.hReadProcess = RWMemory.mReadProcess.Handle;
                return true;
            }
            return false;
        }
        public bool OpenProcess(int iProcessID)
        {
            RWMemory.mReadProcess = Process.GetProcessById(iProcessID);
            if (RWMemory.mReadProcess.Handle != IntPtr.Zero)
            {
                RWMemory.hReadProcess = RWMemory.mReadProcess.Handle;
                return true;
            }
            return false;
        }
        public ProcessModule FindModule(string sModuleName)
        {
            for (int i = 0; i < RWMemory.mReadProcess.Modules.Count; i++)
            {
                if (RWMemory.mReadProcess.Modules[i].ModuleName == sModuleName)
                {
                    return RWMemory.mReadProcess.Modules[i];
                }
            }
            return null;
        }
        public ProcessModuleCollection GetModules()
        {
            return RWMemory.mReadProcess.Modules;
        }
        public string Name()
        {
            return RWMemory.mReadProcess.ProcessName;
        }
        public int PID()
        {
            return RWMemory.mReadProcess.Id;
        }
        public int SID()
        {
            return RWMemory.mReadProcess.SessionId;
        }
        public string FileVersion()
        {
            return RWMemory.mReadProcess.MainModule.FileVersionInfo.FileVersion;
        }
        public string StartTime()
        {
            return RWMemory.mReadProcess.StartTime.ToString();
        }
        public int BaseAddress()
        {
            return RWMemory.mReadProcess.MainModule.BaseAddress.ToInt32();
        }
        public int BaseAddress(string sModuleName)
        {
            return this.FindModule(sModuleName).BaseAddress.ToInt32();
        }
        public int EntryPoint()
        {
            return RWMemory.mReadProcess.MainModule.EntryPointAddress.ToInt32();
        }
        public int EntryPoint(string sModuleName)
        {
            return this.FindModule(sModuleName).EntryPointAddress.ToInt32();
        }
        public int MemorySize()
        {
            return RWMemory.mReadProcess.MainModule.ModuleMemorySize;
        }
        public int MemorySize(string sModuleName)
        {
            return this.FindModule(sModuleName).ModuleMemorySize;
        }
        #region Write_Mem
        public bool Write(int iMemoryAddress, byte bByteToWrite)
        {
            byte[] bBuffer = new byte[]
            {
                bByteToWrite
            };
            IntPtr intPtr;
            MAPI.WriteProcessMemory(RWMemory.hReadProcess, (IntPtr)iMemoryAddress, bBuffer, 1u, out intPtr);
            return intPtr.ToInt32() == 1;
        }
        public bool Write(int iMemoryAddress, short iShortToWrite)
        {
            byte[] bytes = BitConverter.GetBytes(iShortToWrite);
            IntPtr intPtr;
            MAPI.WriteProcessMemory(RWMemory.hReadProcess, (IntPtr)iMemoryAddress, bytes, 2u, out intPtr);
            return intPtr.ToInt32() == 2;
        }
        public bool Write(int iMemoryAddress, int iIntToWrite)
        {
            byte[] bytes = BitConverter.GetBytes(iIntToWrite);
            IntPtr intPtr;
            MAPI.WriteProcessMemory(RWMemory.hReadProcess, (IntPtr)iMemoryAddress, bytes, 4u, out intPtr);
            return intPtr.ToInt32() == 4;
        }
        public bool Write(int iMemoryAddress, long iLongToWrite)
        {
            byte[] bytes = BitConverter.GetBytes(iLongToWrite);
            IntPtr intPtr;
            MAPI.WriteProcessMemory(RWMemory.hReadProcess, (IntPtr)iMemoryAddress, bytes, 8u, out intPtr);
            return intPtr.ToInt32() == 8;
        }
        public bool Write(int iMemoryAddress, float iFloatToWrite)
        {
            byte[] bytes = BitConverter.GetBytes(iFloatToWrite);
            IntPtr intPtr;
            MAPI.WriteProcessMemory(RWMemory.hReadProcess, (IntPtr)iMemoryAddress, bytes, 4u, out intPtr);
            return intPtr.ToInt32() == 4;
        }
        public bool Write(int iMemoryAddress, double iDoubleToWrite)
        {
            byte[] bytes = BitConverter.GetBytes(iDoubleToWrite);
            IntPtr intPtr;
            MAPI.WriteProcessMemory(RWMemory.hReadProcess, (IntPtr)iMemoryAddress, bytes, 8u, out intPtr);
            return intPtr.ToInt32() == 8;
        }
        public bool Write(int iMemoryAddress, string sStringToWrite,int TextMode = 0, int iMode = 0)
        {
            byte[] array = new byte[1];
            if (iMode == 0)
            {
                array = CreateAOBText(sStringToWrite, TextMode);
            }
            else if (iMode == 1)
            {
                array = ReverseBytes(CreateAOBString(sStringToWrite));
            }
            //Clear Last Text
            string LastText = ReadText(iMemoryAddress, 100,TextMode, iMode);
            int newaddress = iMemoryAddress;
            byte none = 0;
            for (int x = 0; x < LastText.Length * 2; x++)
            {
                Write(newaddress, none);
                newaddress += 0x1;
            }
            //
            IntPtr intPtr;
            MAPI.WriteProcessMemory(RWMemory.hReadProcess, (IntPtr)iMemoryAddress, array, (uint)array.Length, out intPtr);
            return intPtr.ToInt32() == array.Length;
        }
        public bool Write(int iMemoryAddress, byte[] bBytesToWrite)
        {
            IntPtr intPtr;
            MAPI.WriteProcessMemory(RWMemory.hReadProcess, (IntPtr)iMemoryAddress, bBytesToWrite, (uint)bBytesToWrite.Length, out intPtr);
            return intPtr.ToInt32() == bBytesToWrite.Length;
        }
        public bool NOP(int iMemoryAddress, int iLength)
        {
            byte[] array = new byte[iLength];
            for (int i = 0; i < iLength; i++)
            {
                array[i] = 144;
            }
            IntPtr intPtr;
            MAPI.WriteProcessMemory(RWMemory.hReadProcess, (IntPtr)iMemoryAddress, array, (uint)iLength, out intPtr);
            return intPtr.ToInt32() == iLength;
        }
        //Pointers
        public bool Write(int iMemoryAddress, int[] iOffsets, byte bByteToWrite)
        {
            int value = this.CalculatePointer(iMemoryAddress, iOffsets);
            byte[] bBuffer = new byte[]
            {
                bByteToWrite
            };
            IntPtr intPtr;
            MAPI.WriteProcessMemory(RWMemory.hReadProcess, (IntPtr)value, bBuffer, 1u, out intPtr);
            return intPtr.ToInt32() == 1;
        }
        public bool Write(int iMemoryAddress, int[] iOffsets, short iShortToWrite)
        {
            int value = this.CalculatePointer(iMemoryAddress, iOffsets);
            byte[] bytes = BitConverter.GetBytes(iShortToWrite);
            IntPtr intPtr;
            MAPI.WriteProcessMemory(RWMemory.hReadProcess, (IntPtr)value, bytes, 2u, out intPtr);
            return intPtr.ToInt32() == 2;
        }
        public bool Write(int iMemoryAddress, int[] iOffsets, int iIntToWrite)
        {
            int value = this.CalculatePointer(iMemoryAddress, iOffsets);
            byte[] bytes = BitConverter.GetBytes(iIntToWrite);
            IntPtr intPtr;
            MAPI.WriteProcessMemory(RWMemory.hReadProcess, (IntPtr)value, bytes, 4u, out intPtr);
            return intPtr.ToInt32() == 4;
        }
        public bool Write(int iMemoryAddress, int[] iOffsets, long iLongToWrite)
        {
            int value = this.CalculatePointer(iMemoryAddress, iOffsets);
            byte[] bytes = BitConverter.GetBytes(iLongToWrite);
            IntPtr intPtr;
            MAPI.WriteProcessMemory(RWMemory.hReadProcess, (IntPtr)value, bytes, 8u, out intPtr);
            return intPtr.ToInt32() == 8;
        }
        public bool Write(int iMemoryAddress, int[] iOffsets, float iFloatToWrite)
        {
            int value = this.CalculatePointer(iMemoryAddress, iOffsets);
            byte[] bytes = BitConverter.GetBytes(iFloatToWrite);
            IntPtr intPtr;
            MAPI.WriteProcessMemory(RWMemory.hReadProcess, (IntPtr)value, bytes, 4u, out intPtr);
            return intPtr.ToInt32() == 4;
        }
        public bool Write(int iMemoryAddress, int[] iOffsets, double iDoubleToWrite)
        {
            int value = this.CalculatePointer(iMemoryAddress, iOffsets);
            byte[] bytes = BitConverter.GetBytes(iDoubleToWrite);
            IntPtr intPtr;
            MAPI.WriteProcessMemory(RWMemory.hReadProcess, (IntPtr)value, bytes, 8u, out intPtr);
            return intPtr.ToInt32() == 8;
        }
        public bool Write(int iMemoryAddress, int[] iOffsets, string sStringToWrite,int TextMode, int iMode = 0)
        {
            int value = CalculatePointer(iMemoryAddress, iOffsets);
            byte[] array = new byte[1];
            byte[] bBuffer = new byte[1];
            if (iMode == 0)
            {
                array = CreateAOBText(sStringToWrite,TextMode);
            }     
            else if (iMode == 1)
            {
                bBuffer = ReverseBytes(CreateAOBString(sStringToWrite));
            }

            //Clear Last Text
            string LastText = ReadText(iMemoryAddress, iOffsets, 100,TextMode, iMode);
            int newaddress = iMemoryAddress;
            byte none = 0;
            for (int x = 0; x < LastText.Length * 2; x++)
            {
                Write(newaddress, none);
                newaddress += 0x1;
            }
            //
            IntPtr intPtr;
            MAPI.WriteProcessMemory(RWMemory.hReadProcess, (IntPtr)value, bBuffer, (uint)sStringToWrite.Length, out intPtr);
            return intPtr.ToInt32() == sStringToWrite.Length;
        }
        public bool Write(int iMemoryAddress, int[] iOffsets, byte[] bBytesToWrite)
        {
            int value = this.CalculatePointer(iMemoryAddress, iOffsets);
            IntPtr intPtr;
            MAPI.WriteProcessMemory(RWMemory.hReadProcess, (IntPtr)value, bBytesToWrite, (uint)bBytesToWrite.Length, out intPtr);
            return intPtr.ToInt32() == bBytesToWrite.Length;
        }
        public bool NOP(int iMemoryAddress, int[] iOffsets, int iLength)
        {
            int value = this.CalculatePointer(iMemoryAddress, iOffsets);
            byte[] array = new byte[iLength];
            for (int i = 0; i < iLength; i++)
            {
                array[i] = 144;
            }
            IntPtr intPtr;
            MAPI.WriteProcessMemory(RWMemory.hReadProcess, (IntPtr)value, array, (uint)iLength, out intPtr);
            return intPtr.ToInt32() == array.Length;
        }
        #endregion
        #region Read_Mem
        public byte ReadByte(int iMemoryAddress)
        {
            byte[] array = new byte[1];
            IntPtr intPtr;
            if (MAPI.ReadProcessMemory(RWMemory.hReadProcess, (IntPtr)iMemoryAddress, array, 1u, out intPtr) == 0)
            {
                return 0;
            }
            return array[0];
        }
        public ushort ReadShort(int iMemoryAddress)
        {
            byte[] array = new byte[2];
            IntPtr intPtr;
            if (MAPI.ReadProcessMemory(RWMemory.hReadProcess, (IntPtr)iMemoryAddress, array, 2u, out intPtr) == 0)
            {
                return 0;
            }
            return BitConverter.ToUInt16(array, 0);
        }
        public uint ReadInt(int iMemoryAddress)
        {
            byte[] array = new byte[4];
            IntPtr intPtr;
            if (MAPI.ReadProcessMemory(RWMemory.hReadProcess, (IntPtr)iMemoryAddress, array, 4u, out intPtr) == 0)
            {
                return 0u;
            }
            return BitConverter.ToUInt32(array, 0);
        }
        public long ReadLong(int iMemoryAddress)
        {
            byte[] array = new byte[8];
            IntPtr intPtr;
            if (MAPI.ReadProcessMemory(RWMemory.hReadProcess, (IntPtr)iMemoryAddress, array, 8u, out intPtr) == 0)
            {
                return 0L;
            }
            return BitConverter.ToInt64(array, 0);
        }
        public float ReadFloat(int iMemoryAddress)
        {
            byte[] array = new byte[4];
            IntPtr intPtr;
            if (MAPI.ReadProcessMemory(RWMemory.hReadProcess, (IntPtr)iMemoryAddress, array, 4u, out intPtr) == 0)
            {
                return 0f;
            }
            return BitConverter.ToSingle(array, 0);
        }
        public double ReadDouble(int iMemoryAddress)
        {
            byte[] array = new byte[8];
            IntPtr intPtr;
            if (MAPI.ReadProcessMemory(RWMemory.hReadProcess, (IntPtr)iMemoryAddress, array, 8u, out intPtr) == 0)
            {
                return 0.0;
            }
            return BitConverter.ToDouble(array, 0);
        }
        public string ReadText(int iMemoryAddress, uint iTextLength, int TextMode, int iMode)
        {
            byte[] array = new byte[iTextLength];
            IntPtr intPtr;
            MAPI.ReadProcessMemory(RWMemory.hReadProcess, (IntPtr)iMemoryAddress, array, iTextLength, out intPtr);
            int index;
            string Text = "";
            if (iMode == 0)
            {
                if (TextMode == 0) 
                {
                    Text = Encoding.UTF8.GetString(array);
                    index = Text.IndexOf("\0");
                    Text = Text.Substring(0, index); 
                }
                else if (TextMode == 1) 
                {
                    Text = Encoding.ASCII.GetString(array);
                    index = Text.IndexOf("\0");
                    Text = Text.Substring(0, index);
                }
                else if (TextMode == 2) 
                {
                    Text = Encoding.Unicode.GetString(array);
                    index = Text.IndexOf("\0");
                    Text = Text.Substring(0, index);
                }
                
            }
            if (iMode == 1)
            {
                return BitConverter.ToString(array).Replace("-", "");
            }
            return Text;
        }
        public byte[] ReadAOB(int iMemoryAddress, uint iBytesToRead)
        {
            byte[] array = new byte[iBytesToRead];
            IntPtr intPtr;
            MAPI.ReadProcessMemory(RWMemory.hReadProcess, (IntPtr)iMemoryAddress, array, iBytesToRead, out intPtr);
            return array;
        }        
        //Pointers
        public byte ReadByte(int iMemoryAddress, int[] iOffsets)
        {
            int value = this.CalculatePointer(iMemoryAddress, iOffsets);
            byte[] array = new byte[1];
            IntPtr intPtr;
            MAPI.ReadProcessMemory(RWMemory.hReadProcess, (IntPtr)value, array, 1u, out intPtr);
            return array[0];
        }       
        public ushort ReadShort(int iMemoryAddress, int[] iOffsets)
        {
            int value = this.CalculatePointer(iMemoryAddress, iOffsets);
            byte[] array = new byte[2];
            IntPtr intPtr;
            MAPI.ReadProcessMemory(RWMemory.hReadProcess, (IntPtr)value, array, 2u, out intPtr);
            return BitConverter.ToUInt16(array, 0);
        }
        public uint ReadInt(int iMemoryAddress, int[] iOffsets)
        {
            int value = this.CalculatePointer(iMemoryAddress, iOffsets);
            byte[] array = new byte[4];
            IntPtr intPtr;
            MAPI.ReadProcessMemory(RWMemory.hReadProcess, (IntPtr)value, array, 4u, out intPtr);
            return BitConverter.ToUInt32(array, 0);
        }
        public long ReadLong(int iMemoryAddress, int[] iOffsets)
        {
            int value = this.CalculatePointer(iMemoryAddress, iOffsets);
            byte[] array = new byte[8];
            IntPtr intPtr;
            MAPI.ReadProcessMemory(RWMemory.hReadProcess, (IntPtr)value, array, 8u, out intPtr);
            return BitConverter.ToInt64(array, 0);
        }
        public float ReadFloat(int iMemoryAddress, int[] iOffsets)
        {
            int value = this.CalculatePointer(iMemoryAddress, iOffsets);
            byte[] array = new byte[4];
            IntPtr intPtr;
            MAPI.ReadProcessMemory(RWMemory.hReadProcess, (IntPtr)value, array, 4u, out intPtr);
            return BitConverter.ToSingle(array, 0);
        }
        public double ReadDouble(int iMemoryAddress, int[] iOffsets)
        {
            int value = this.CalculatePointer(iMemoryAddress, iOffsets);
            byte[] array = new byte[8];
            IntPtr intPtr;
            MAPI.ReadProcessMemory(RWMemory.hReadProcess, (IntPtr)value, array, 8u, out intPtr);
            return BitConverter.ToDouble(array, 0);
        }
        public string ReadText(int iMemoryAddress, int[] iOffsets, uint iTextLength, int TextMode, int iMode = 0)
        {
            int value = this.CalculatePointer(iMemoryAddress, iOffsets);
            byte[] array = new byte[1];
            IntPtr intPtr;
            MAPI.ReadProcessMemory(RWMemory.hReadProcess, (IntPtr)value, array, iTextLength, out intPtr);

            int index;
            string Text = "";
            if (iMode == 0)
            {
                if (TextMode == 0)
                {
                    Text = Encoding.UTF8.GetString(array);
                    index = Text.IndexOf("\0");
                    Text = Text.Substring(0, index);
                }
                else if (TextMode == 1)
                {
                    Text = Encoding.ASCII.GetString(array); 
                    index = Text.IndexOf("\0");
                    Text = Text.Substring(0, index);
                }
                else if (TextMode == 2)
                {
                    Text = Encoding.Unicode.GetString(array);
                    index = Text.IndexOf("\0");
                    Text = Text.Substring(0, index);
                }
            }
            if (iMode == 1)
            {
                return BitConverter.ToString(array).Replace("-", "");
            }
            return Text;
        }
        public byte[] ReadAOB(int iMemoryAddress, int[] iOffsets, uint iBytesToRead)
        {
            int value = this.CalculatePointer(iMemoryAddress, iOffsets);
            byte[] array = new byte[1];
            IntPtr intPtr;
            MAPI.ReadProcessMemory(RWMemory.hReadProcess, (IntPtr)value, array, iBytesToRead, out intPtr);
            return array;
        }
        #endregion
        #region Conversion
        public int Dec(int iHex)
        {
            return int.Parse(iHex.ToString(), NumberStyles.HexNumber);
        }
        public int Dec(string sHex)
        {
            return int.Parse(sHex, NumberStyles.HexNumber);
        }
        public string Hex(int iDec)
        {
            return iDec.ToString("X");
        }
        public string Hex(string sDec)
        {
            if (this.IsNumeric(sDec))
            {
                return int.Parse(sDec).ToString("X");
            }
            return "0";
        }
        #endregion
        #region Miscelanious
        public bool BytesEqual(byte[] bBytes_1, byte[] bBytes_2)
        {
            return BitConverter.ToString(bBytes_1) == BitConverter.ToString(bBytes_2);
        }
        public bool IsNumeric(string sNumber)
        {
            return new Regex("^\\d+$").IsMatch(sNumber);
        }
        public byte[] ReverseBytes(byte[] bOriginalBytes)
        {
            int num = bOriginalBytes.Length;
            byte[] array = new byte[num];
            for (int i = 0; i < num; i++)
            {
                array[num - i - 1] = bOriginalBytes[i];
            }
            return array;
        }
        private byte[] CreateAOBText(string sBytes,int TextMode)
        {
            if (TextMode == 0) { return Encoding.UTF8.GetBytes(sBytes); }
            else if (TextMode == 1) { return Encoding.ASCII.GetBytes(sBytes); }
            else if (TextMode == 2) { return Encoding.Unicode.GetBytes(sBytes); }
            else { return null; }
        }
        private byte[] CreateAOBString(string sBytes)
        {
            return BitConverter.GetBytes(this.Dec(sBytes));
        }
        private string CreateAddress(byte[] bBytes)
        {
            string text = "";
            for (int i = 0; i < bBytes.Length; i++)
            {
                if (Convert.ToInt16(bBytes[i]) < 10)
                {
                    text = "0" + bBytes[i].ToString("X") + text;
                }
                else
                {
                    text = bBytes[i].ToString("X") + text;
                }
            }
            return text;
        }
        private int CalculatePointer(int iMemoryAddress, int[] iOffsets)
        {
            int num = iOffsets.Length - 1;
            byte[] array = new byte[4];
            int value = 0;
            if (num == 0)
            {
                value = iMemoryAddress;
            }
            for (int i = 0; i <= num; i++)
            {
                if (i == num)
                {
                    IntPtr intPtr;
                    MAPI.ReadProcessMemory(RWMemory.hReadProcess, (IntPtr)value, array, 4u, out intPtr);
                    return this.Dec(this.CreateAddress(array)) + iOffsets[i];
                }
                if (i == 0)
                {
                    IntPtr intPtr;
                    MAPI.ReadProcessMemory(RWMemory.hReadProcess, (IntPtr)iMemoryAddress, array, 4u, out intPtr);
                    value = this.Dec(this.CreateAddress(array)) + iOffsets[0];
                }
                else
                {
                    IntPtr intPtr;
                    MAPI.ReadProcessMemory(RWMemory.hReadProcess, (IntPtr)value, array, 4u, out intPtr);
                    value = this.Dec(this.CreateAddress(array)) + iOffsets[i];
                }
            }
            return 0;
        }
        public int CalculateStaticAddress(string sStaticOffset)
        {
            return this.BaseAddress() + this.Dec(sStaticOffset);
        }
        public int CalculateStaticAddress(int iStaticOffset)
        {
            return this.BaseAddress() + iStaticOffset;
        }
        public int CalculateStaticAddress(string sStaticOffset, string sModuleName)
        {
            return this.BaseAddress(sModuleName) + this.Dec(sStaticOffset);
        }
        public int CalculateStaticAddress(int iStaticOffset, string sModuleName)
        {
            return this.BaseAddress(sModuleName) + iStaticOffset;
        }

        public int GetAddress(int BaseAddress, int[] Offsets)
        {
            int address = BaseAddress;
            foreach(int offset in Offsets)
            {
                address = (int)ReadInt(address + offset);
            }
            return address;
        }
        public byte[] GetBytes(int BaseAddress, int[] Offsets)
        {
            byte[] array = new byte[4];
            IntPtr intPtr;
            MAPI.ReadProcessMemory(RWMemory.hReadProcess, (IntPtr)BaseAddress, array, (uint)array.Length, out intPtr);
            int num = BitConverter.ToInt32(array, 0);
            int value = num + Offsets[0];
            MAPI.ReadProcessMemory(RWMemory.hReadProcess, (IntPtr)value, array, (uint)array.Length, out intPtr);
            num = BitConverter.ToInt32(array, 0);
            for (int i = 1; i < Offsets.Length; i++)
            {
                value = num + Offsets[i];
                MAPI.ReadProcessMemory(RWMemory.hReadProcess, (IntPtr)value, array, (uint)array.Length, out intPtr);
                num = BitConverter.ToInt32(array, 0);
            }
            MAPI.ReadProcessMemory(RWMemory.hReadProcess, (IntPtr)num, array, (uint)array.Length, out intPtr);
            return BitConverter.GetBytes(num).ToArray<byte>();
        }
        public void SuspendThread(int pid, int ThreadEntry)
        {
            Process processById = Process.GetProcessById(pid);
            if (processById.ProcessName == string.Empty)
            {
                return;
            }
            foreach (object obj in processById.Threads)
            {
                ProcessThread processThread = (ProcessThread)obj;
                if ((int)RWMemory.GetThreadStartAddress(processThread.Id) == ThreadEntry)
                {
                    IntPtr intPtr = MAPI.OpenThread(RWMemory.ThreadAccess.SUSPEND_RESUME, false, processThread.Id);
                    if (!(intPtr == IntPtr.Zero))
                    {
                        MAPI.SuspendThread(intPtr);
                        MAPI.CloseHandle(intPtr);
                    }
                }
            }
        }
        public void SuspendProcess(int pid)
        {
            Process processById = Process.GetProcessById(pid);
            if (processById.ProcessName == string.Empty)
            {
                return;
            }
            foreach (object obj in processById.Threads)
            {
                ProcessThread processThread = (ProcessThread)obj;
                IntPtr intPtr = MAPI.OpenThread(RWMemory.ThreadAccess.SUSPEND_RESUME, false, processThread.Id);
                if (!(intPtr == IntPtr.Zero))
                {
                    MAPI.SuspendThread(intPtr);
                    MAPI.CloseHandle(intPtr);
                }
            }
        }
        public void ResumeThread(int pid, int Thread)
        {
            if (Process.GetProcessById(pid).ProcessName == string.Empty)
            {
                return;
            }
            IntPtr intPtr = MAPI.OpenThread(RWMemory.ThreadAccess.SUSPEND_RESUME, false, Thread);
            intPtr = IntPtr.Zero;
            int num;
            do
            {
                num = MAPI.ResumeThread(intPtr);
            }
            while (num > 0);
            MAPI.CloseHandle(intPtr);
        }
        public void ResumeProcess(int pid)
        {
            Process processById = Process.GetProcessById(pid);
            if (processById.ProcessName == string.Empty)
            {
                return;
            }
            foreach (object obj in processById.Threads)
            {
                ProcessThread processThread = (ProcessThread)obj;
                IntPtr intPtr = MAPI.OpenThread(RWMemory.ThreadAccess.SUSPEND_RESUME, false, processThread.Id);
                if (!(intPtr == IntPtr.Zero))
                {
                    int num;
                    do
                    {
                        num = MAPI.ResumeThread(intPtr);
                    }
                    while (num > 0);
                    MAPI.CloseHandle(intPtr);
                }
            }
        }
        #endregion
        #region Others
        public static IntPtr GetThreadStartAddress(int threadId)
        {
            IntPtr intPtr = MAPI.OpenThread(RWMemory.ThreadAccess.QUERY_INFORMATION, false, threadId);
            if (intPtr == IntPtr.Zero)
            {
                throw new Win32Exception();
            }
            IntPtr intPtr2 = Marshal.AllocHGlobal(IntPtr.Size);
            IntPtr result;
            try
            {
                int num = MAPI.NtQueryInformationThread(intPtr, RWMemory.ThreadInfoClass.ThreadQuerySetWin32StartAddress, intPtr2, IntPtr.Size, IntPtr.Zero);
                if (num != 0)
                {
                    throw new Win32Exception(string.Format("NtQueryInformationThread failed; NTSTATUS = {0:X8}", num));
                }
                result = Marshal.ReadIntPtr(intPtr2);
            }
            finally
            {
                MAPI.CloseHandle(intPtr);
                Marshal.FreeHGlobal(intPtr2);
            }
            return result;
        }
        public static Process mReadProcess = null;
        private static IntPtr hReadProcess = IntPtr.Zero;
        [Flags]
        public enum ThreadAccess
        {
            // Token: 0x0400008A RID: 138
            TERMINATE = 1,
            // Token: 0x0400008B RID: 139
            SUSPEND_RESUME = 2,
            // Token: 0x0400008C RID: 140
            GET_CONTEXT = 8,
            // Token: 0x0400008D RID: 141
            SET_CONTEXT = 16,
            // Token: 0x0400008E RID: 142
            SET_INFORMATION = 32,
            // Token: 0x0400008F RID: 143
            QUERY_INFORMATION = 64,
            // Token: 0x04000090 RID: 144
            SET_THREAD_TOKEN = 128,
            // Token: 0x04000091 RID: 145
            IMPERSONATE = 256,
            // Token: 0x04000092 RID: 146
            DIRECT_IMPERSONATION = 512
        }
        public enum ThreadInfoClass
        {
            // Token: 0x04000094 RID: 148
            ThreadQuerySetWin32StartAddress = 9
        }
        #endregion
    }
}
