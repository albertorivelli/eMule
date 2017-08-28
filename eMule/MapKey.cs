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
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License
//along with this program; if not, write to the Free Software
//Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.


namespace eMule
{
    // use this class if the hash is stored somehwere else (and stays valid as long as this object exists)
    public class CKey
    {
        byte[] m_key;

        public CKey(byte[] key = null)
        {
            m_key = key;
        }

        public CKey(CKey k1)
        {
            m_key = k1.m_key;
        }

        //    CKey& operator=(const CCKey& k1) { m_key = k1.m_key; return *this; }

        public static bool operator ==(CKey k1, CKey k2)
        {
            return (k1.m_key[0] == k2.m_key[0] &&
                k1.m_key[1] == k2.m_key[1] &&
                k1.m_key[2] == k2.m_key[2] &&
                k1.m_key[3] == k2.m_key[3]);
        }

        public static bool operator !=(CKey k1, CKey k2)
        {
            return (k1.m_key[0] != k2.m_key[0] ||
                k1.m_key[1] != k2.m_key[1] ||
                k1.m_key[2] != k2.m_key[2] ||
                k1.m_key[3] != k2.m_key[3]);
        }

        public override bool Equals(object o)
        {
            try
            {
                return (bool)(this == (CKey)o);
            }
            catch
            {
                return false;
            }
        }

        public override int GetHashCode()
        {
            return m_key[0];
        }
    }

    //template<> inline UINT AFXAPI HashKey(const CCKey& key)
    //{
    //    uint32 hash = 1;
    //    for (int i = 0; i != 16; i++)
    //        hash += (key.m_key[i] + 1) * ((i * i) + 1);
    //    return hash;
    //}

    // use this class if the hash is stored somehwere inside the key (in any case safer but needs more memory)
    public class SKey
    {
        byte[] m_key = new byte[16];

        public SKey(byte[] key)
        {
            if (key != null)
            {
                m_key[0] = key[0];
                m_key[1] = key[1];
                m_key[2] = key[2];
                m_key[3] = key[3];
            }
            else
            {
                m_key[0] = m_key[1] = m_key[2] = m_key[3] = 0;
            }
        }

        public SKey(SKey k1)
        {
            m_key[0] = k1.m_key[0];
            m_key[1] = k1.m_key[1];
            m_key[2] = k1.m_key[2];
            m_key[3] = k1.m_key[3];
        }

        //CSKey& operator=(const CSKey& k1) { md4cpy(m_key, k1.m_key); return *this; }

        public static bool operator ==(SKey k1, SKey k2)
        {
            return (k1.m_key[0] == k2.m_key[0] && 
                k1.m_key[1] == k2.m_key[1] && 
                k1.m_key[2] == k2.m_key[2] && 
                k1.m_key[3] == k2.m_key[3]);
        }

        public static bool operator !=(SKey k1, SKey k2)
        {
            return (k1.m_key[0] != k2.m_key[0] ||
                k1.m_key[1] != k2.m_key[1] ||
                k1.m_key[2] != k2.m_key[2] ||
                k1.m_key[3] != k2.m_key[3]);
        }

        public override bool Equals(object o)
        {
            try
            {
                return (bool)(this == (SKey)o);
            }
            catch
            {
                return false;
            }
        }

        public override int GetHashCode()
        {
            return m_key[0];
        }
    }

    //template<> inline UINT AFXAPI HashKey(const CSKey& key)
    //{
    //    uint32 hash = 1;
    //    for (int i = 0; i != 16; i++)
    //        hash += (key.m_key[i] + 1) * ((i * i) + 1);
    //    return hash;
    //};
}

