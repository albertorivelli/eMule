using eMule;
using System;
using System.Diagnostics;

namespace Kademlia
{
    public class Contact
    {
        private UInt128 m_uClientID;
        private UInt128 m_uDistance;
        private uint m_uIp;
        private uint m_uInUse;
        private byte m_byType;
        private DateTime m_tLastTypeSet;
        private DateTime m_tCreated;

        public Contact()
        {
            m_uClientID = UInt128.Zero;
            m_uIp = 0;
            UDPPort = 0;
            TCPPort = 0;
            Version = 0;
            UDPKey = new KadUDPKey(0, 0);
            IsIpVerified = false;

            InitContact();
        }

        public Contact(UInt128 uClientID, uint uIp, ushort uUdpPort, ushort uTcpPort, byte uVersion, KadUDPKey cUDPKey, bool bIPVerified)
        {

            m_uClientID = uClientID;
            Kademlia.GetPrefs().GetKadID(ref m_uDistance);
            m_uDistance.Xor(uClientID);
            m_uIp = uIp;
            UDPPort = uUdpPort;
            TCPPort = uTcpPort;
            Version = uVersion;
            UDPKey = cUDPKey;
            IsIpVerified = bIPVerified;

            InitContact();
        }

        public Contact(UInt128 uClientID, uint uIp, ushort uUdpPort, ushort uTcpPort, UInt128 uTarget, byte uVersion, KadUDPKey cUDPKey, bool bIPVerified)
        {
            m_uClientID = uClientID;
            m_uDistance = new UInt128(uTarget.High, uTarget.Low);
            m_uDistance.Xor(uClientID);
            m_uIp = uIp;
            UDPPort = uUdpPort;
            TCPPort = uTcpPort;
            Version = uVersion;
            UDPKey = cUDPKey;
            IsIpVerified = bIPVerified;

            InitContact();
        }

        private void InitContact()
        {
            m_byType = 3;
            ExpireTime = DateTime.MinValue;
            m_tLastTypeSet = DateTime.Now;
            GuiRefs = false;
            m_uInUse = 0;
            m_tCreated = DateTime.Now;
            ReceivedHelloPacket = false;
        }

        private Contact Clone()
        {
            Debug.Assert(GuiRefs == false); // don't do this, if this is needed at some point, the code has to be adjusted before
            Contact copy = new Contact();
            copy.ClientID = ClientID;
            copy.m_uDistance = Distance;
            copy.IPAddress = IPAddress;
            copy.TCPPort = TCPPort;
            copy.UDPPort = UDPPort;
            copy.m_uInUse = m_uInUse;
            copy.m_tLastTypeSet = LastTypeSet;
            copy.ExpireTime = ExpireTime;
            copy.m_tCreated = CreatedTime;
            copy.m_byType = m_byType;
            copy.Version = Version;
            copy.GuiRefs = false;
            copy.IsIpVerified = IsIpVerified;
            copy.UDPKey = UDPKey;
            copy.ReceivedHelloPacket = ReceivedHelloPacket;
            return copy;
        }

        public UInt128 ClientID
        {
            get
            {
                return m_uClientID;
            }
            set
            {
                m_uClientID = value;
                Kademlia.GetPrefs().GetKadID(m_uDistance);
                m_uDistance.Xor(value);
            }
        }

        public UInt128 Distance
        {
            get
            {
                return m_uDistance;
            }
        }

        public uint IPAddress
        {
            get
            {
                return m_uIp;
            }
            set
            {
                if (m_uIp != value)
                {
                    IsIpVerified = false; // clear the verified flag since it is no longer valid for a different IP
                    m_uIp = value;
                }
            }
        }

        public ushort TCPPort { get; set; }

        public ushort UDPPort { get; set; }

        public byte Type
        {
            get
            {
                return m_byType;
            }
        }

        public void CheckingType()
        {
            if ((DateTime.Now - LastTypeSet).Ticks < 10 || m_byType == 4)
                return;

            m_tLastTypeSet = DateTime.Now;

            ExpireTime = DateTime.Now.AddMilliseconds(Opcodes.MIN2S(2));
            m_byType++;
            //theApp.emuledlg->kademliawnd->ContactRef(this);
        }

        public void UpdateType()
        {
            int uHours = (DateTime.Now - CreatedTime).Milliseconds / 3600;
            switch (uHours)
            {
                case 0:
                    m_byType = 2;
                    ExpireTime = DateTime.Now.AddHours(1);
                    break;
                case 1:
                    m_byType = 1;
                    ExpireTime = DateTime.Now.AddHours(1.5);
                    break;
                default:
                    m_byType = 0;
                    ExpireTime = DateTime.Now.AddHours(2);
                    break;
            }
            //theApp.emuledlg->kademliawnd->ContactRef(this);
        }

        public bool GuiRefs { get; set; }

        public byte Version { get; set; }

        public KadUDPKey UDPKey { get; set; }

        public bool IsIpVerified { get; set; }

        public bool InUse()
        {
            return (m_uInUse > 0);
        }

        public void IncUse()
        {
            m_uInUse++;
        }

        public void DecUse()
        {
            if (m_uInUse > 0)
                m_uInUse--;
            else
                Debug.Assert(false);
        }

        public bool ReceivedHelloPacket { get; set; }

        public DateTime GetLastSeen()
        {
            // calculating back from expire time, so we don't need an additional field.
            // might result in wrong values if doing CheckingType() for example, so don't use for important timing stuff
            if (ExpireTime != DateTime.MinValue)
            {
                switch (m_byType)
                {
                    case 2: return ExpireTime.AddHours(-1);
                    case 1: return ExpireTime.AddHours(-1.5);
                    case 0: return ExpireTime.AddHours(-2);
                }
            }
            return DateTime.MinValue;
        }

        public DateTime CreatedTime
        {
            get
            {
                return m_tCreated;
            }
        }

        public DateTime ExpireTime { get; set; }

        public DateTime LastTypeSet
        {
            get
            {
                return m_tLastTypeSet;
            }
        }
    }
}
