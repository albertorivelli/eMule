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
using System.Diagnostics;
using System.Linq;
using System.Net;

namespace Kademlia
{
    public class Kademlia
    {
        private static Kademlia m_pInstance;
        private Dictionary<RoutingZone, RoutingZone> m_mapEvents;
        public static List<Contact> s_liBootstapList = new List<Contact>();
        private static DateTime m_tNextSearchJumpStart;
        private static DateTime m_tNextSelfLookup;
        private static DateTime m_tNextFirewallCheck;
        private static DateTime m_tNextUPnPCheck;
        private static DateTime m_tNextFindBuddy;
        private static DateTime m_tStatusUpdate;
        private static DateTime m_tBigTimer;
        private static DateTime m_tBootstrap;
        private static DateTime m_tConsolidate;
        private static DateTime m_tExternPortLookup;
        private static DateTime m_tLANModeCheck;
        private static bool m_bRunning;
        private List<uint> m_liStatsEstUsersProbes;
        private static bool m_bLANMode;
        private Prefs m_pPrefs;
        private RoutingZone m_pRoutingZone;
        private KademliaUDPListener m_pUDPListener;
        private Indexed m_pIndexed;

        public Kademlia()
        {
        }

        public static void Start()
        {
            // Create a new default pref object.
            Start(new Prefs());
        }

        public static void Start(Prefs pPrefs)
        {
            try
            {
                // If we already have a instance, something is wrong. 
                if (m_pInstance != null)
                {
                    Debug.Assert(m_pInstance.m_bRunning);
                    Debug.Assert(m_pInstance.m_pPrefs != null);
                    return;
                }

                // Make sure a prefs was passed in..
                if (pPrefs == null)
                    return;

                //AddDebugLogLine(false, "Starting Kademlia");

                // Init jump start timer.
                m_tNextSearchJumpStart = DateTime.Now;
                // Force a FindNodeComplete within the first 3 minutes.
                m_tNextSelfLookup = DateTime.Now.AddMinutes(3);
                // Init status timer.
                m_tStatusUpdate = DateTime.Now;
                // Init big timer for Zones
                m_tBigTimer = DateTime.Now;
                // First Firewall check is done on connect, init next check.
                m_tNextFirewallCheck = DateTime.Now.AddHours(1);
                m_tNextUPnPCheck = m_tNextFirewallCheck.AddMinutes(-1);
                // Find a buddy after the first 5mins of starting the client.
                // We wait just in case it takes a bit for the client to determine firewall status..
                m_tNextFindBuddy = DateTime.Now.AddMinutes(5);
                // Init contact consolidate timer;
                m_tConsolidate = DateTime.Now.AddMinutes(45);
                // Looking up our extern port
                m_tExternPortLookup = DateTime.Now;
                // Init bootstrap time.
                m_tBootstrap = DateTime.MinValue;
                // Init our random seed.
                srand((uint)DateTime.Now.Millisecond);
                // Create our Kad objects.
                m_pInstance = new Kademlia();
                m_pInstance.m_pPrefs = pPrefs;
                m_pInstance.m_pUDPListener = null;
                m_pInstance.m_pRoutingZone = null;
                m_pInstance.m_pIndexed = new Indexed();
                m_pInstance.m_pRoutingZone = new RoutingZone();
                m_pInstance.m_pUDPListener = new KademliaUDPListener();
                // Mark Kad as running state.
                m_bRunning = true;
            }
            catch (Exception e)
            {
                // Although this has never been an issue, maybe some just in case code
                // needs to be created here just in case things go real bad.. But if things
                // went real bad, the entire client most like is in bad shape, so this may
                // not be something to worry about as the client most likely will crap out anyway.
                //AddDebugLogLine(false, "%s", e.Message);
            }
        }

        public static void Stop()
        {
            // Make sure we are running to begin with.
            if (!m_bRunning)
                return;

            //AddDebugLogLine(false, "Stopping Kademlia");

            // Mark Kad as being in the stop state to make sure nothing else is used.
            m_bRunning = false;

            // Reset Firewallstate
            //UDPFirewallTester.Reset();

            // Remove all active searches.
            //SearchManager.StopAllSearches();

            // Delete all Kad Objects.
            m_pInstance.m_pUDPListener = null;

            m_pInstance.m_pRoutingZone = null;

            m_pInstance.m_pIndexed = null;

            m_pInstance.m_pPrefs = null;

            m_pInstance = null;

            while (!s_liBootstapList.IsEmpty())
                delete s_liBootstapList.RemoveHead();

            // Make sure all zones are removed.
            m_mapEvents.Clear();
        }

        public static void Process()
        {
            if (m_pInstance == null || !m_bRunning)
                return;
            bool bUpdateUserFile = false;
            uint uMaxUsers = 0;
            uint uTempUsers = 0;
            uint uLastContact = 0;
            DateTime tNow = DateTime.Now;
            Debug.Assert(m_pInstance.m_pPrefs != null);
            uLastContact = m_pInstance.m_pPrefs.GetLastContact();
            SearchManager.UpdateStats();
            if (m_tStatusUpdate <= tNow)
            {
                bUpdateUserFile = true;
                m_tStatusUpdate = tNow.AddMinutes(1);
            }
            if (m_tNextFirewallCheck <= tNow)
                RecheckFirewalled();
            if (m_tNextUPnPCheck != DateTime.MinValue && m_tNextUPnPCheck <= tNow)
            {
                theApp.emuledlg.RefreshUPnP();
                m_tNextUPnPCheck = DateTime.MinValue; // will be reset on firewallcheck
            }

            if (m_tNextSelfLookup <= tNow)
            {
                SearchManager.FindNode(m_pInstance.m_pPrefs.GetKadID(), true);
                m_tNextSelfLookup = tNow.AddHours(4);
            }
            if (m_tNextFindBuddy <= tNow)
            {
                m_pInstance.m_pPrefs.SetFindBuddy();
                m_tNextFindBuddy = tNow.AddMinutes(20);
            }
            if (m_tExternPortLookup <= tNow && UDPFirewallTester.IsFWCheckUDPRunning() && GetPrefs().FindExternKadPort(false))
            {
                // if our UDP firewallcheck is running and we don't know our external port, we send a request every 15 seconds
                Contact pContact = GetRoutingZone().GetRandomContact(3, Opcodes.KADEMLIA_VERSION6_49aBETA);
                if (pContact != null)
                {
                    //DEBUG_ONLY(DebugLog("Requesting our external port from %s", IPAddress.Parse(IPAddress.NetworkToHostOrder(pContact.IPAddress).ToString()).ToString()));
                    GetUDPListener().SendNullPacket(Opcodes.KADEMLIA2_PING, pContact.IPAddress, pContact.UDPPort, pContact.UDPKey, &pContact.ClientID);
                }
                else
                    DEBUG_ONLY(DebugLogWarning("No valid client for requesting external port available"));
                m_tExternPortLookup = tNow.AddMilliseconds(15);
            }
            foreach (RoutingZone pZone in m_mapEvents.Values)
            {
                if (bUpdateUserFile)
                {
                    // The EstimateCount function is not made for really small networks, if we are in LAN mode, it is actually
                    // better to assume that all users of the network are in our routingtable and use the real count function
                    if (IsRunningInLANMode())
                        uTempUsers = pZone.GetNumContacts();
                    else
                        uTempUsers = pZone.EstimateCount();
                    if (uMaxUsers < uTempUsers)
                        uMaxUsers = uTempUsers;
                }
                if (m_tBigTimer <= tNow)
                {
                    if (pZone.m_tNextBigTimer <= tNow)
                    {
                        if (pZone.OnBigTimer())
                        {
                            pZone.m_tNextBigTimer = tNow.AddHours(1);
                            m_tBigTimer = tNow.AddSeconds(10);
                        }
                    }
                    else
                    {
                        if (uLastContact && ((tNow - uLastContact) > (Opcodes.KADEMLIADISCONNECTDELAY - Opcodes.MIN2S(5))))
                        {
                            if (pZone.OnBigTimer())
                            {
                                pZone.m_tNextBigTimer = tNow.AddHours(1);
                                m_tBigTimer = tNow.AddSeconds(10);
                            }
                        }
                    }
                }
                if (pZone.m_tNextSmallTimer <= tNow)
                {
                    pZone.OnSmallTimer();
                    pZone.m_tNextSmallTimer = tNow.AddMinutes(1);
                }
            }

            // This is a convenient place to add this, although not related to routing
            if (m_tNextSearchJumpStart <= tNow)
            {
                SearchManager.JumpStart();
                m_tNextSearchJumpStart = tNow.AddMilliseconds(Defines.SEARCH_JUMPSTART);
            }

            // Try to consolidate any zones that are close to empty.
            if (m_tConsolidate <= tNow)
            {
                uint uMergedCount = m_pInstance.m_pRoutingZone.Consolidate();
                if (uMergedCount > 0)
                    AddDebugLogLine(false, "Kad merged %u Zones", uMergedCount);
                m_tConsolidate = tNow.AddMinutes(45);
            }

            //Update user count only if changed.
            if (bUpdateUserFile)
            {
                if (uMaxUsers != m_pInstance.m_pPrefs.GetKademliaUsers())
                {
                    m_pInstance.m_pPrefs.SetKademliaUsers(uMaxUsers);
                    m_pInstance.m_pPrefs.SetKademliaFiles();
                    theApp.emuledlg.ShowUserCount();
                }
            }

            if (!IsConnected() && !s_liBootstapList.IsEmpty()
                && ((tNow - m_tBootstrap).Milliseconds > 15 || (GetRoutingZone().GetNumContacts() == 0 && (tNow - m_tBootstrap).Milliseconds >= 2)))
            {
                Contact pContact = s_liBootstapList.RemoveHead();
                m_tBootstrap = tNow;
                //DebugLog("Trying to Bootstrap Kad from %s, Distance: %s, Version: %u, %u Contacts left", ipstr(ntohl(pContact->GetIPAddress())), pContact->GetDistance().ToHexString(), pContact->GetVersion(), s_liBootstapList.GetCount());
                m_pInstance.m_pUDPListener.Bootstrap(pContact.IPAddress, pContact.UDPPort, pContact.Version, pContact.ClientID);
            }

            if (GetUDPListener() != null)
                GetUDPListener().ExpireClientSearch(); // function does only one compare in most cases, so no real need for a timer
        }

        public static void AddEvent(RoutingZone pZone)
        {
            m_mapEvents[pZone] = pZone;
        }

        public static void RemoveEvent(RoutingZone pZone)
        {
            m_mapEvents.Remove(pZone);
        }

        public static bool IsConnected()
        {
            if (m_pInstance != null && m_pInstance.m_pPrefs != null)
                return m_pInstance.m_pPrefs.HasHadContact();
            return false;
        }

        public static bool IsFirewalled()
        {
            if (m_pInstance != null && m_pInstance.m_pPrefs != null)
                return m_pInstance.m_pPrefs.GetFirewalled() && !IsRunningInLANMode();
            return true;
        }

        public static uint GetKademliaUsers(bool bNewMethod)
        {
            if (m_pInstance != null && m_pInstance.m_pPrefs != null)
            {
                if (bNewMethod)
                    return CalculateKadUsersNew();
                else
                    return m_pInstance.m_pPrefs.GetKademliaUsers();
            }
            return 0;
        }

        public static uint GetKademliaFiles()
        {
            if (m_pInstance != null && m_pInstance.m_pPrefs != null)
                return m_pInstance.m_pPrefs.GetKademliaFiles();
            return 0;
        }

        public static uint GetTotalStoreKey()
        {
            if (m_pInstance != null && m_pInstance.m_pPrefs != null)
                return m_pInstance.m_pPrefs.GetTotalStoreKey();
            return 0;
        }

        public static uint GetTotalStoreSrc()
        {
            if (m_pInstance != null && m_pInstance.m_pPrefs != null)
                return m_pInstance.m_pPrefs.GetTotalStoreSrc();
            return 0;
        }

        public static uint GetTotalStoreNotes()
        {
            if (m_pInstance != null && m_pInstance.m_pPrefs != null)
                return m_pInstance.m_pPrefs.GetTotalStoreNotes();
            return 0;
        }

        public static uint GetTotalFile()
        {
            if (m_pInstance != null && m_pInstance.m_pPrefs != null)
                return m_pInstance.m_pPrefs.GetTotalFile();
            return 0;
        }

        public static uint GetIPAddress()
        {
            if (m_pInstance != null && m_pInstance.m_pPrefs != null)
                return m_pInstance.m_pPrefs.GetIPAddress();
            return 0;
        }

        public static void ProcessPacket(byte pbyData, uint uLenData, uint uIP, ushort uPort, bool bValidReceiverKey, KadUDPKey senderUDPKey)
        {
            if (m_pInstance != null && m_pInstance.m_pUDPListener != null)
                m_pInstance.m_pUDPListener.ProcessPacket(pbyData, uLenData, uIP, uPort, bValidReceiverKey, senderUDPKey);
        }

        public static bool GetPublish()
        {
            if (m_pInstance != null && m_pInstance.m_pPrefs != null)
                return m_pInstance.m_pPrefs.GetPublish();
            return false;
        }

        public static void Bootstrap(string szHost, ushort uPort)
        {
            if (m_pInstance != null && m_pInstance.m_pUDPListener != null && !IsConnected() && ((DateTime.Now - m_tBootstrap).Milliseconds > 10))
            {
                m_tBootstrap = DateTime.Now;
                m_pInstance.m_pUDPListener.Bootstrap(szHost, uPort);
            }
        }

        public static void Bootstrap(uint uIP, ushort uPort)
        {
            if (m_pInstance != null && m_pInstance.m_pUDPListener != null && !IsConnected() && ((DateTime.Now - m_tBootstrap).Milliseconds > 10))
            {
                m_tBootstrap = DateTime.Now;
                m_pInstance.m_pUDPListener.Bootstrap(uIP, uPort);
            }
        }

        public static void RecheckFirewalled()
        {
            if (m_pInstance != null && m_pInstance.GetPrefs() != null && !IsRunningInLANMode())
            {
                // Something is forcing a new firewall check
                // Stop any new buddy requests, and tell the client
                // to recheck it's IP which in turns rechecks firewall.
                m_pInstance.m_pPrefs.SetFindBuddy(false);
                m_pInstance.m_pPrefs.SetRecheckIP();
                // also UDP check
                UDPFirewallTester.ReCheckFirewallUDP(false);

                DateTime tNow = DateTime.Now;
                // Delay the next buddy search to at least 5 minutes after our firewallcheck so we are sure to be still firewalled
                m_tNextFindBuddy = (m_tNextFindBuddy < tNow.AddMinutes(5)) ? (tNow.AddMinutes(5)) : m_tNextFindBuddy;
                m_tNextFirewallCheck = tNow.AddHours(1);
                m_tNextUPnPCheck = m_tNextFirewallCheck.AddMinutes(-1);
            }
        }

        public static Prefs GetPrefs()
        {
            if (m_pInstance == null || m_pInstance.m_pPrefs == null)
            {
                Debug.Assert(false);
                return null;
            }
            return m_pInstance.m_pPrefs;
        }

        public static KademliaUDPListener GetUDPListener()
        {
            if (m_pInstance == null || m_pInstance.m_pUDPListener == null)
            {
                Debug.Assert(false);
                return null;
            }
            return m_pInstance.m_pUDPListener;
        }

        public static RoutingZone GetRoutingZone()
        {
            if (m_pInstance == null || m_pInstance.m_pRoutingZone == null)
            {
                Debug.Assert(false);
                return null;
            }
            return m_pInstance.m_pRoutingZone;
        }

        public static Indexed GetIndexed()
        {
            if (m_pInstance == null || m_pInstance.m_pIndexed == null)
            {
                Debug.Assert(false);
                return null;
            }
            return m_pInstance.m_pIndexed;
        }

        public static bool IsRunning()
        {
            return m_bRunning;
        }

        public static bool FindNodeIDByIP(KadClientSearcher rRequester, uint dwIP, ushort nTCPPort, ushort nUDPPort)
        {
            if (!IsRunning() || m_pInstance == null || GetUDPListener() == null || GetRoutingZone() == null)
            {
                Debug.Assert(false);
                return false;
            }
            // first search our known contacts if we can deliver a result without asking, otherwise forward the request
            Contact pContact;
            if ((pContact = GetRoutingZone().GetContact(ntohl(dwIP), nTCPPort, true)) != null)
            {
                byte[] uchID = new byte[16];
                pContact.ClientID.ToByteArray(uchID);
                rRequester.KadSearchNodeIDByIPResult(EKadClientSearchRes.KCSR_SUCCEEDED, uchID);
                return true;
            }
            else
                return GetUDPListener().FindNodeIDByIP(rRequester, ntohl(dwIP), nTCPPort, nUDPPort);
        }

        public static bool FindIPByNodeID(KadClientSearcher rRequester, byte pachNodeID)
        {
            if (!IsRunning() || m_pInstance == null || GetUDPListener() == null)
            {
                Debug.Assert(false);
                return false;
            }
            // first search our known contacts if we can deliver a result without asking, otherwise forward the request
            Contact pContact;
            if ((pContact = GetRoutingZone().GetContact(new UInt128(pachNodeID))) != null)
            {
                // make sure that this entry is not too old, otherwise just do a search to be sure
                if (pContact.GetLastSeen() != DateTime.MinValue && ((DateTime.Now - pContact.GetLastSeen()).Milliseconds < 1800))
                {
                    rRequester.KadSearchIPByNodeIDResult(EKadClientSearchRes.KCSR_SUCCEEDED, ntohl(pContact.IPAddress), pContact.TCPPort);
                    return true;
                }
            }
            return SearchManager.FindNodeSpecial(new UInt128(pachNodeID), rRequester);
        }

        public static void CancelClientSearch(KadClientSearcher rFromRequester)
        {
            if (m_pInstance == null || GetUDPListener() == null)
            {
                Debug.Assert(false);
                return;
            }
            GetUDPListener().ExpireClientSearch(rFromRequester);
            SearchManager.CancelNodeSpecial(rFromRequester);
        }

        public static void KadGetKeywordHash(string rstrKeywordA, UInt128 pKadID)
        {
            MD4 md4;
            md4.Add(rstrKeywordA.ToCharArray(), rstrKeywordA.Length);
            md4.Finish();
            pKadID.SetValueBE(md4.GetHash());
        }

        public static string KadGetKeywordBytes(KadTagValueString rstrKeywordW)
        {
            return string(wc2utf8(rstrKeywordW));
        }

        public static void KadGetKeywordHash(KadTagValueString rstrKeywordW, UInt128 pKadID)
        {
            KadGetKeywordHash(KadGetKeywordBytes(rstrKeywordW), pKadID);
        }

        public static void StatsAddClosestDistance(UInt128 uDist)
        {
            if (uDist.Get32BitChunk(0) > 0)
            {
                uint nToAdd = (0xFFFFFFFF / uDist.Get32BitChunk(0)) / 2;
                if (m_liStatsEstUsersProbes.Where(n => n == nToAdd) == null)
                    m_liStatsEstUsersProbes.Insert(0, nToAdd);
            }
            if (m_liStatsEstUsersProbes.Count > 100)
                m_liStatsEstUsersProbes.RemoveAt(m_liStatsEstUsersProbes.Count - 1);
        }

        private static uint CalculateKadUsersNew()
        {
            // the idea of calculating the user count with this method is simple:
            // whenever we do search for any NodeID (except in certain cases were the result is not usable),
            // we remember the distance of the closest node we found. Because we assume all NodeIDs are distributed
            // equally, we can calcualte based on this distance how "filled" the possible NodesID room is and by this
            // calculate how many users there are. Of course this only works if we have enough samples, because
            // each single sample will be wrong, but the average of them should produce a usable number. To avoid
            // drifts caused by a a single (or more) really close or really far away hits, we do use median-average instead through

            // doesnt works well if we have no files to index and nothing to download and the numbers seems to be a bit too low
            // compared to out other method. So lets stay with the old one for now, but keeps this here as alternative

            if (m_liStatsEstUsersProbes.Count < 10)
                return 0;
            uint nMedian = 0;

            List<uint> liMedian;
            foreach (uint nProbe in m_liStatsEstUsersProbes)
            {
                bool bInserted = false;
                for (POSITION pos2 = liMedian.GetHeadPosition(); pos2 != null; liMedian.GetNext(pos2))
                {
                    if (liMedian[pos2] > nProbe)
                    {
                        liMedian.InsertBefore(pos2, nProbe);
                        bInserted = true;
                        break;
                    }
                }
                if (!bInserted)
                    liMedian.AddTail(nProbe);
            }
            // cut away 1/3 of the values - 1/6 of the top and 1/6 of the bottom  to avoid spikes having too much influence, build the average of the rest 
            sint32 nCut = liMedian.Count / 6;
            for (int i = 0; i != nCut; i++)
            {
                liMedian.RemoveHead();
                liMedian.RemoveTail();
            }
            ulong nAverage = 0;
            for (POSITION pos1 = liMedian.GetHeadPosition(); pos1 != NULL;)
                nAverage += liMedian.GetNext(pos1);
            nMedian = (uint)(nAverage / liMedian.GetCount());

            // LowIDModififier
            // Modify count by assuming 20% of the users are firewalled and can't be a contact for < 0.49b nodes
            // Modify count by actual statistics of Firewalled ratio for >= 0.49b if we are not firewalled ourself
            // Modify count by 40% for >= 0.49b if we are firewalled outself (the actual Firewalled count at this date on kad is 35-55%)
            const float fFirewalledModifyOld = 1.20F;
            float fFirewalledModifyNew = 0;
            if (UDPFirewallTester.IsFirewalledUDP(true))
                fFirewalledModifyNew = 1.40F; // we are firewalled and get get the real statistic, assume 40% firewalled >=0.49b nodes
            else if (GetPrefs().StatsGetFirewalledRatio(true) > 0)
            {
                fFirewalledModifyNew = 1.0F + (GetPrefs().StatsGetFirewalledRatio(true)); // apply the firewalled ratio to the modify
                Debug.Assert(fFirewalledModifyNew > 1.0F && fFirewalledModifyNew < 1.90F);
            }
            float fNewRatio = GetPrefs().KadV8Ratio;
            float fFirewalledModifyTotal = 0;
            if (fNewRatio > 0 && fFirewalledModifyNew > 0) // weigth the old and the new modifier based on how many new contacts we have
                fFirewalledModifyTotal = (fNewRatio * fFirewalledModifyNew) + ((1 - fNewRatio) * fFirewalledModifyOld);
            else
                fFirewalledModifyTotal = fFirewalledModifyOld;
            Debug.Assert(fFirewalledModifyTotal > 1.0F && fFirewalledModifyTotal < 1.90F);

            return (uint)((float)nMedian * fFirewalledModifyTotal);
        }

        public static bool IsRunningInLANMode()
        {
            if (thePrefs.FilterLANIPs() || !IsRunning())
                return false;

            if (m_tLANModeCheck.AddMilliseconds(10) <= DateTime.Now)
            {
                m_tLANModeCheck = DateTime.Now;
                uint nCount = GetRoutingZone().GetNumContacts();
                // Limit to 256 nodes, if we have more we don't want to use the LAN mode which is assuming we use a small home LAN
                // (otherwise we might need to do firewallcheck, external port requests etc after all)
                if (nCount == 0 || nCount > 256)
                    m_bLANMode = false;
                else
                {
                    if (GetRoutingZone().HasOnlyLANNodes())
                    {
                        if (!m_bLANMode)
                        {
                            m_bLANMode = true;
                            theApp.emuledlg.ShowConnectionState();
                            DebugLog("Kademlia: Activating LAN Mode");
                        }
                    }
                    else if (m_bLANMode)
                    {
                        m_bLANMode = false;
                        theApp.emuledlg.ShowConnectionState();
                    }
                }
            }
            return m_bLANMode;
        }
    }
}


