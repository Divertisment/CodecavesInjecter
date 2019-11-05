using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RequiemHackTester
{
    public partial class Game
    {
        public List<sEntity> Entity = new List<sEntity>();
        public struct sEntity
        {
            public int BaseAddress;

            public string Name { get; set; }
            public int Level { get; set; }
            public int Health { get; set; }
            public int HealthMax { get; set; }
            public int Mana { get; set; }
            public int ManaMax { get; set; }
            public float PosX { get; set; }
            public float PosY { get; set; }
            public float PosZ { get; set; }
        }

        public void SetEntitys()
        {
            Console.Clear();
            for(int index = 0; index < Entity.Count(); index++)
            {
                sEntity TheEntity = Entity[index];
                //Name
                TheEntity.Name = Form1.memory.ReadText(Form1.memory.GetAddress(TheEntity.BaseAddress, new int[] { 0x11C, 0x8 }), 100, 1, 0);
                if (Entity[index].Name == "") { TheEntity.Name = Form1.memory.ReadText(Form1.memory.GetAddress(TheEntity.BaseAddress, new int[] { 0x530 }) + 0x60, 100, 1, 0); }
                //Level
                TheEntity.Level = (int)Form1.memory.ReadInt(Form1.memory.GetAddress(TheEntity.BaseAddress, new int[] { 0x530 }) + 0x78);
                //Health
                TheEntity.Health = (int)Form1.memory.ReadInt(Form1.memory.GetAddress(TheEntity.BaseAddress, new int[] { 0x530 }) + 0xA4);
                TheEntity.HealthMax = (int)Form1.memory.ReadInt(Form1.memory.GetAddress(TheEntity.BaseAddress, new int[] { 0x530 }) + 0xA8);
                //Mana
                TheEntity.Mana = (int)Form1.memory.ReadInt(Form1.memory.GetAddress(TheEntity.BaseAddress, new int[] { 0x530 }) + 0xAC);
                TheEntity.ManaMax = (int)Form1.memory.ReadInt(Form1.memory.GetAddress(TheEntity.BaseAddress, new int[] { 0x530 }) + 0xB0);
                //Pos
                TheEntity.PosX = Form1.memory.ReadFloat(Entity[index].BaseAddress + 0x274);
                TheEntity.PosY = Form1.memory.ReadFloat(Entity[index].BaseAddress + 0x278);
                TheEntity.PosZ = Form1.memory.ReadFloat(Entity[index].BaseAddress + 0x27C);

                Entity[index] = TheEntity;
                Console.WriteLine(Entity[index].BaseAddress.ToString("X"));
            }
        }
    }
}
