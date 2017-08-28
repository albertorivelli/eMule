/*
Copyright (C)2003 Barry Dunne (http://www.emule-project.net)
 
This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either
version 2 of the License, or (at your option) any later version.
 
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
 
You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

// Note To Mods //
/*
Please do not change anything here and release it..
There is going to be a new forum created just for the Kademlia side of the client..
If you feel there is an error or a way to improve something, please
post it in the forum first and let us look at it.. If it is a real improvement,
it will be added to the offical client.. Changing something without knowing
what all it does can cause great harm to the network if released in mass form..
Any mod that changes anything within the Kademlia side will not be allowed to advertise
there client on the eMule forum..
*/

using eMule;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Windows.Storage;
using Windows.Storage.Streams;

namespace Kademlia
{
    public class Prefs
    {
        private const int EXTERNAL_PORT_ASKIPS = 3;

        private uint m_uIP;
        private uint m_uIPLast;
        private uint m_uRecheckip;
        private uint m_uFirewalled;
        private bool m_bLastFirewallState;
        private bool m_bUseExternKadPort;
        private ushort m_nExternKadPort;
        private List<uint> m_anExternPortIPs;
        private List<ushort> m_anExternPorts;

        public Prefs()
        {
            string sFilename = "preferencesKad.dat";

            Init(sFilename);
        }

        ~Prefs()
        {
            if (Filename.Length > 0)
                WriteFile();
        }

        private void Init(string szFilename)
        {
            KadID = UInt128.Random();
            m_tLastContact = 0;
            TotalFile = 0;
            TotalStoreSrc = 0;
            TotalStoreKey = 0;
            TotalSource = 0;
            TotalNotes = 0;
            TotalStoreNotes = 0;
            Publish = false;
            ClientHash = thePrefs.GetUserHash();
            m_uIP = 0;
            m_uIPLast = 0;
            m_uRecheckip = 0;
            m_uFirewalled = 0;
            FindBuddy = false;
            KademliaUsers = 0;
            m_uKademliaFiles = 0;
            Filename = szFilename;
            m_bLastFirewallState = true;
            m_nExternKadPort = 0;
            m_bUseExternKadPort = true;
            m_nStatsUDPOpenNodes = 0;
            m_nStatsUDPFirewalledNodes = 0;
            m_nStatsTCPOpenNodes = 0;
            m_nStatsTCPFirewalledNodes = 0;
            KadV8RatioLastChecked = DateTime.MinValue;
            m_fKadV8Ratio = 0;
            ReadFile();
        }

        private async Task ReadFile()
        {
            try
            {
                StorageFile file;
                file = await Windows.Storage.ApplicationData.Current.LocalFolder.GetFileAsync(Filename);
                var buff = await file.OpenSequentialReadAsync();

                using (DataReader dataReader = new DataReader(buff))
                {
                    m_uIP = dataReader.ReadUInt32();
                    dataReader.ReadUInt16();
                    byte[] arr = new byte[16];
                    dataReader.ReadBytes(arr);
                    KadID = new UInt128(BitConverter.ToUInt64(arr, 0), BitConverter.ToUInt64(arr, 8));

                    // get rid of invalid kad IDs which may have been stored by older versions
                    if (KadID.Equals(UInt128.Zero))
                        KadID = UInt128.Random();
                }
            }
            catch (Exception ex)
            {
                //TRACE("Exception in readFile\n");
            }
        }

        private async Task WriteFile()
        {
            try
            {
                StorageFile file;
                file = await Windows.Storage.StorageFile.GetFileFromPathAsync(Filename);
                var buff = await file.OpenAsync(FileAccessMode.ReadWrite);

                using (DataWriter dataWriter = new DataWriter(buff))
                {
                    dataWriter.WriteUInt32(m_uIP);
                    dataWriter.WriteUInt16(0); //This is no longer used.
                    dataWriter.WriteBytes(BitConverter.GetBytes(KadID.High));
                    dataWriter.WriteBytes(BitConverter.GetBytes(KadID.Low));
                    dataWriter.WriteByte(0); //This is to tell older clients there are no tags..
                }
            }
            catch (Exception ex)
            {
                //TRACE("Exception in readFile\n");
            }
        }

        public string Filename { get; set; }

        public UInt128 KadID { get; set; }

        public UInt128 ClientHash { get; set; }

        private long m_tLastContact;
        public long LastContact
        {
            get
            {
                return m_tLastContact;
            }
            set
            {
                m_tLastContact = DateTime.Now.Millisecond;
            }
        }

        public bool HasLostConnection()
        {
            if (m_tLastContact > 0)
                return !((DateTime.Now.Millisecond - m_tLastContact) < Opcodes.KADEMLIADISCONNECTDELAY);
            return false;
        }

        public bool HasHadContact()
        {
            if (m_tLastContact > 0)
                return ((DateTime.Now.Millisecond - m_tLastContact) < Opcodes.KADEMLIADISCONNECTDELAY);
            return false;
        }

        private bool m_bFindBuddy;
        public bool FindBuddy
        {
            get
            {
                if (m_bFindBuddy)
                {
                    m_bFindBuddy = false;
                    return true;
                }
                return false;
            }
            set
            {
                m_bFindBuddy = value;
            }
        }

        public bool Publish { get; set; }

        public byte TotalFile { get; set; }

        public byte TotalStoreSrc { get; set; }

        public byte TotalStoreKey { get; set; }

        public byte TotalSource { get; set; }

        public byte TotalNotes { get; set; }

        public byte TotalStoreNotes { get; set; }

        public uint KademliaUsers { get; set; }

        public uint IPAddress
        {
            get
            {
                return m_uIP;
            }
            set
            {
                //This is our first check on connect, init our IP..
                if (value > 0 || m_uIPLast > 0)
                {
                    m_uIP = value;
                    m_uIPLast = value;
                }
                //If the last check matches this one, reset our current IP.
                //If the last check does not match, wait for our next incoming IP.
                //This happens for two reasons.. We just changed our IP, or a client responsed with a bad IP.
                if (value == m_uIPLast)
                    m_uIP = value;
                else
                    m_uIPLast = value;
            }
        }

        public bool GetRecheckIP()
        {
            return (m_uRecheckip < Opcodes.KADEMLIAFIREWALLCHECKS);
        }

        public void SetRecheckIP()
        {
            m_uRecheckip = 0;
            SetFirewalled();
        }

        public void IncRecheckIP()
        {
            m_uRecheckip++;
        }

        public bool GetFirewalled()
        {
            if (m_uFirewalled < 2)
            {
                //Not enough people have told us we are open but we may be doing a recheck
                //at the moment which will give a false lowID.. Therefore we check to see
                //if we are still rechecking and will report our last known state..
                if (GetRecheckIP())
                    return m_bLastFirewallState;
                return true;
            }
            //We had enough tell us we are not firewalled..
            return false;
        }

        public void SetFirewalled()
        {
            //Are are checking our firewall state.. Let keep a snapshot of our
            //current state to prevent false reports during the recheck..
            m_bLastFirewallState = (m_uFirewalled < 2);
            m_uFirewalled = 0;
            //theApp.emuledlg->ShowConnectionState();
        }

        public void IncFirewalled()
        {
            m_uFirewalled++;
            //theApp.emuledlg->ShowConnectionState();
        }

        private uint m_uKademliaFiles;
        public uint GetKademliaFiles()
        {
            return m_uKademliaFiles;
        }

        void SetKademliaFiles()
        {
            //There is no real way to know how many files are in the Kad network..
            //So we first try to see how many files per user are in the ED2K network..
            //If that fails, we use a set value based on previous tests..
            uint nServerAverage = 0;
            //theApp.serverlist->GetAvgFile( nServerAverage );
            uint nKadAverage = Kademlia.GetIndexed().GetFileKeyCount();

#if DEBUG
            string method;
#endif

            if (nServerAverage > nKadAverage)
            {
#if DEBUG
                method = $"Kad file estimate used Server avg({nServerAverage})";
#endif
                nKadAverage = nServerAverage;
            }
#if DEBUG
            else
            {
                method = $"Kad file estimate used Kad avg({nKadAverage})";
            }
#endif
            if (nKadAverage < 108)
            {
#if DEBUG
                method = "Kad file estimate used default avg(108)";
#endif
                nKadAverage = 108;
            }
#if DEBUG
            //AddDebugLogLine(DLP_VERYLOW, false, method);
#endif

            m_uKademliaFiles = nKadAverage * KademliaUsers;
        }

        public uint GetUDPVerifyKey(uint dwTargetIP)
        {
            ulong ui64Buffer = thePrefs.GetKadUDPKey();
            ui64Buffer <<= 32;
            ui64Buffer |= dwTargetIP;
            MD5Sum md5 = new MD5Sum((uchar*)&ui64Buffer, 8);
            return ((uint)(PeekUInt32(md5.GetRawHash() + 0) ^ PeekUInt32(md5.GetRawHash() + 4) ^ PeekUInt32(md5.GetRawHash() + 8) ^ PeekUInt32(md5.GetRawHash() + 12)) % 0xFFFFFFFE) + 1;
        }

        public bool UseExternKadPort
        {
            get
            {
                return m_bUseExternKadPort && !Kademlia.IsRunningInLANMode();
            }
            set
            {
                m_bUseExternKadPort = value;
            }
        }

        public ushort GetExternalKadPort()
        {
            return m_nExternKadPort;
        }

        public void SetExternKadPort(ushort uVal, uint uFromIP)
        {
            if (FindExternKadPort(false))
            {
                for (int i = 0; i < m_anExternPortIPs.Count; i++)
                {
                    if (m_anExternPortIPs[i] == uFromIP)
                        return;
                }
                m_anExternPortIPs.Add(uFromIP);
                //DebugLog(_T("Received possible external Kad Port %u from %s"), uVal, ipstr(ntohl(uFromIP)));
                // if 2 out of 3 tries result in the same external port its fine, otherwise consider it as unreliable
                for (int i = 0; i < m_anExternPorts.Count; i++)
                {
                    if (m_anExternPorts[i] == uVal)
                    {
                        m_nExternKadPort = uVal;
                        //DebugLog(_T("Set external Kad Port to %u"), uVal);
                        while (m_anExternPortIPs.Count < EXTERNAL_PORT_ASKIPS)
                            m_anExternPortIPs.Add(0); // add empty entries so we know the check has finished even if we asked less than max IPs
                        return;
                    }
                }
                m_anExternPorts.Add(uVal);
                if (!FindExternKadPort(false))
                {
                    //DebugLog(_T("Our external port seems unreliable, not using it for firewallchecks"), uVal);
                    m_nExternKadPort = 0;
                }
            }
        }

        public ushort GetInternKadPort()
        {
            return thePrefs.GetUDPPort();
        }

        public bool FindExternKadPort(bool bReset)
        {
            if (!bReset)
                return m_anExternPortIPs.Count < EXTERNAL_PORT_ASKIPS && !Kademlia.IsRunningInLANMode();
            else
            {
                m_anExternPortIPs.Clear();
                m_anExternPorts.Clear();
                return true;
            }
        }

        public ushort GetMyConnectOptions(bool bEncryption, bool bCallback)
        {
            return OtherFunctions.GetMyConnectOptions(bEncryption, bCallback);
        }

        private uint m_nStatsUDPOpenNodes;
        private uint m_nStatsUDPFirewalledNodes;
        private uint m_nStatsTCPOpenNodes;
        private uint m_nStatsTCPFirewalledNodes;
        public float StatsGetFirewalledRatio(bool bUDP)
        {
            // gives an estimated percentage of TCP firewalled clients in the network
            // will only work once enough > 0.49b nodes have spread and only if we are not UDP firewalled ourself
            if (bUDP)
            {
                if (m_nStatsUDPFirewalledNodes > 0 && m_nStatsUDPOpenNodes > 10)
                    return ((float)m_nStatsUDPFirewalledNodes / (float)(m_nStatsUDPFirewalledNodes + m_nStatsUDPOpenNodes));
                else
                    return 0;
            }
            else
            {
                if (m_nStatsTCPFirewalledNodes > 0 && m_nStatsTCPOpenNodes > 10)
                    return ((float)m_nStatsTCPFirewalledNodes / (float)(m_nStatsTCPFirewalledNodes + m_nStatsTCPOpenNodes));
                else
                    return 0;
            }
        }

        void StatsIncUDPFirewalledNodes(bool bFirewalled)
        {
            if (bFirewalled)
                m_nStatsUDPFirewalledNodes++;
            else
                m_nStatsUDPOpenNodes++;
        }

        public void StatsIncTCPFirewalledNodes(bool bFirewalled)
        {
            if (bFirewalled)
                m_nStatsTCPFirewalledNodes++;
            else
                m_nStatsTCPOpenNodes++;
        }

        public DateTime KadV8RatioLastChecked { get; set; }

        private float m_fKadV8Ratio;
        public float KadV8Ratio
        {
            get
            {
                // this function is basically just a buffer, so we don't recount all nodes everytime we need the result
                if (KadV8RatioLastChecked.AddMilliseconds(60) < DateTime.Now)
                {
                    KadV8RatioLastChecked = DateTime.Now;
                    uint nV8Contacts = 0;
                    uint nNonV8Contacts = 0;
                    Kademlia.GetRoutingZone().GetNumContacts(ref nV8Contacts, ref nNonV8Contacts, Opcodes.KADEMLIA_VERSION8_49b);
                    //DEBUG_ONLY( AddDebugLogLine(DLP_LOW, false, _T("Counted Kad V8 Contacts: %u out of %u in routing table. FirewalledRatios: UDP - %.02f%% | TCP - %.02f%%")
                    //	, nV8Contacts, nNonV8Contacts + nV8Contacts, StatsGetFirewalledRatio(true) * 100, StatsGetFirewalledRatio(false) * 100) );
                    if (nV8Contacts > 0)
                        m_fKadV8Ratio = ((float)nV8Contacts / (float)(nV8Contacts + nNonV8Contacts));
                    else
                        m_fKadV8Ratio = 0;
                }

                return m_fKadV8Ratio;
            }
        }
    }
}
