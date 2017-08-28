//this file is part of eMule
//Copyright (C)2002-2008 Merkur ( strEmail.Format("%s@%s", "devteam", "emule-project.net") / http://www.emule-project.net )
//
//This program is free software; you can redistribute it and/or
//modify it under the terms of the GNU General Public License
//as published by the Free Software Foundation; either
//version 2 of the License, or (at your option) any later version.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License
//along with this program; if not, write to the Free Software
//Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

using System.Diagnostics;

namespace Kademlia
{
    public class KadUDPKey
    {
        private uint m_dwKey;
        private uint m_dwIP;

        public KadUDPKey(uint uZero = 0)
        {
            Debug.Assert(uZero == 0);
            m_dwKey = uZero;
            m_dwIP = 0;
        }

        public KadUDPKey(uint dwKey, uint dwIP)
        {
            m_dwKey = dwKey;
            m_dwIP = dwIP;
        }

        //public KadUDPKey(CFileDataIO file)
        //{
        //    ReadFromFile(file);
        //}

        ////    public CKadUDPKey& operator=(const CKadUDPKey& k1)								{m_dwKey = k1.m_dwKey; m_dwIP = k1.m_dwIP; return *this; }
        ////public CKadUDPKey& operator=(const uint32 uZero) { ASSERT(uZero == 0); m_dwKey = uZero; m_dwIP = 0; return *this; }
        ////public bool operator ==(const CKadUDPKey& k1,const CKadUDPKey& k2) { return k1.GetKeyValue(k1.m_dwIP) == k2.GetKeyValue(k2.m_dwIP); }

        public uint GetKeyValue(uint dwMyIP)
        {
            return (dwMyIP == m_dwIP) ? m_dwKey : 0;
        }

        public bool IsEmpty()
        {
            return (m_dwKey == 0) || (m_dwIP == 0);
        }

        //public void StoreToFile(CFileDataIO& file)
        //{
        //    file.WriteUInt32(m_dwKey);
        //    file.WriteUInt32(m_dwIP);
        //}

        //public void ReadFromFile(CFileDataIO& file)
        //{
        //    m_dwKey = file.ReadUInt32();
        //    m_dwIP = file.ReadUInt32();
        //}
    }
}