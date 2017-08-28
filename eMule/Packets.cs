using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace eMule
{
    public class Packet
    {
        public struct Header_Struct
        {
            public byte eDonkeyID;
            public uint packetlength;
            public byte command;
        }

        public struct UDP_Header_Struct
        {
            public byte eDonkeyID;
            public byte command;
        }

        public byte[] pBuffer;
        public uint size;
        public byte opcode;
        public byte prot;
        protected bool m_bSplitted;
        protected bool m_bLastSplitted;
        protected bool m_bPacked;
        protected bool m_bFromPF;
        protected byte[] completebuffer;
        protected byte[] tempbuffer;
        protected byte[] head = new byte[6];

        public Packet(byte protocol = Opcodes.OP_EDONKEYPROT)
        {
            m_bSplitted = false;
            m_bLastSplitted = false;
            m_bFromPF = false;
            size = 0;
            pBuffer = null;
            completebuffer = null;
            tempbuffer = null;
            opcode = 0x00;
            prot = protocol;
            m_bPacked = false;
        }

        public Packet(byte[] header)
        {
            m_bSplitted = false;
            m_bPacked = false;
            m_bLastSplitted = false;
            m_bFromPF = false;
            tempbuffer = null;
            pBuffer = null;
            completebuffer = null;
            Header_Struct head = (Header_Struct)header;
            size = head.packetlength - 1;
            opcode = head.command;
            prot = head.eDonkeyID;
        }

        public Packet(byte[] pPacketPart, uint nSize, bool bLast, bool bFromPartFile = true)
        {// only used for splitted packets!
            m_bFromPF = bFromPartFile;
            m_bSplitted = true;
            m_bPacked = false;
            m_bLastSplitted = bLast;
            tempbuffer = null;
            pBuffer = null;
            completebuffer = pPacketPart;
            size = nSize - 6;
            opcode = 0x00;
            prot = 0x00;
        }

        public Packet(byte in_opcode, uint in_size, byte protocol = Opcodes.OP_EDONKEYPROT, bool bFromPartFile = true)
        {
            m_bFromPF = bFromPartFile;
            m_bSplitted = false;
            m_bPacked = false;
            m_bLastSplitted = false;
            tempbuffer = null;
            if (in_size > 0)
            {
                completebuffer = new byte[in_size + 10];
                completebuffer.CopyTo(pBuffer, 6);

                memset(completebuffer, 0, in_size + 10);
            }
            else
            {
                pBuffer = null;
                completebuffer = null;
            }
            opcode = in_opcode;
            size = in_size;
            prot = protocol;
        }

        public Packet(MemFile datafile, byte protocol = Opcodes.OP_EDONKEYPROT, byte ucOpcode = 0x00)
        {
            m_bSplitted = false;
            m_bPacked = false;
            m_bLastSplitted = false;
            m_bFromPF = false;
            size = (uint)datafile.GetLength();
            completebuffer = new char[(uint)datafile.GetLength() + 10];
            pBuffer = completebuffer + 6;
            byte[] tmp = datafile.Detach();

            memcpy(pBuffer, tmp, size);

            free(tmp);
            tempbuffer = null;
            opcode = ucOpcode;
            prot = protocol;
        }

        public Packet(string str, byte ucProtocol, byte ucOpcode)
        {
            m_bSplitted = false;
            m_bPacked = false;
            m_bLastSplitted = false;
            m_bFromPF = false;
            size = (uint)str.Length;
            completebuffer = new byte[size + 10];
            pBuffer = completebuffer + 6;

            memcpy(pBuffer, str, size);
            tempbuffer = null;
            opcode = ucOpcode;
            prot = ucProtocol;
        }

        public byte[] GetPacket()
        {
            if (completebuffer != null)
            {
                if (!m_bSplitted)
                    memcpy(completebuffer, GetHeader(), 6);
                return completebuffer;
            }
            else
            {
                tempbuffer = null; // 'new' may throw an exception
                tempbuffer = new byte[size + 10];
                memcpy(tempbuffer, GetHeader(), 6);
                memcpy(tempbuffer + 6, pBuffer, size);
                return tempbuffer;
            }
        }

        public byte[] DetachPacket()
        {
            if (completebuffer != null)
            {
                if (!m_bSplitted)
                    memcpy(completebuffer, GetHeader(), 6);
                byte[] result = completebuffer;
                completebuffer = null;
                pBuffer = null;
                return result;
            }
            else
            {
                tempbuffer = null; // 'new' may throw an exception
                tempbuffer = new byte[size + 10];
                memcpy(tempbuffer, GetHeader(), 6);
                memcpy(tempbuffer + 6, pBuffer, size);
                byte[] result = tempbuffer;
                tempbuffer = null;
                return result;
            }
        }

        public byte[] GetHeader()
        {
            Debug.Assert(!m_bSplitted);
            Header_Struct header = (Header_Struct)head;
            header.command = opcode;
            header.eDonkeyID = prot;
            header.packetlength = size + 1;
            return head;
        }

        public byte[] GetUDPHeader()
        {
            Debug.Assert(!m_bSplitted);
            UDP_Header_Struct header = (UDP_Header_Struct)head;
            header.command = opcode;
            header.eDonkeyID = prot;
            return head;
        }

        public void PackPacket()
        {
            //Debug.Assert(!m_bSplitted);
            //uLongf newsize = size + 300;
            //byte[] output = new byte[newsize];
            //uint result = compress2(output, &newsize, (BYTE*)pBuffer, size, Z_BEST_COMPRESSION);
            //if (result != Z_OK || size <= newsize)
            //{
            //    return;
            //}

            //if (prot == Opcodes.OP_KADEMLIAHEADER)
            //    prot = Opcodes.OP_KADEMLIAPACKEDPROT;
            //else
            //    prot = Opcodes.OP_PACKEDPROT;

            //memcpy(pBuffer, output, newsize);
            //size = newsize;
            //delete[] output;
            //m_bPacked = true;
        }

        public bool UnPackPacket(uint uMaxDecompressedSize)
        {
            Debug.Assert(prot == Opcodes.OP_PACKEDPROT || prot == Opcodes.OP_KADEMLIAPACKEDPROT);
            uint nNewSize = size * 10 + 300;
            if (nNewSize > uMaxDecompressedSize)
            {
                //ASSERT(0);
                nNewSize = uMaxDecompressedSize;
            }
            byte[] unpack = null;
            uLongf unpackedsize = 0;
            uint result = 0;
            do
            {
                delete[] unpack;
                unpack = new BYTE[nNewSize];
                unpackedsize = nNewSize;
                result = uncompress(unpack, &unpackedsize, (BYTE*)pBuffer, size);
                nNewSize *= 2; // size for the next try if needed
            } while (result == Z_BUF_ERROR && nNewSize < uMaxDecompressedSize);

            if (result == Z_OK)
            {
                Debug.Assert(completebuffer == null);
                Debug.Assert(pBuffer != null);
                size = unpackedsize;
                delete[] pBuffer;
                pBuffer = (byte[])unpack;
                if (prot == Opcodes.OP_KADEMLIAPACKEDPROT)
                    prot = Opcodes.OP_KADEMLIAHEADER;
                else
                    prot = Opcodes.OP_EMULEPROT;
                return true;
            }
            delete[] unpack;
            return false;
        }
    }
}
