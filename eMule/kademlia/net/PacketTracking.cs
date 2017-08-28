using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using eMule;
using System.Net;

namespace Kademlia
{
    public struct TrackPackets_Struct
    {
        public uint dwIP;
        public uint dwInserted;
        public byte byOpcode;
    }

    public struct TrackChallenge_Struct
    {
        public uint uIP;
        public uint dwInserted;
        public byte byOpcode;
        public UInt128 uContactID;
        public UInt128 uChallenge;
    }

    public struct TrackPacketsIn_Struct
    {
        public struct TrackedRequestIn_Struct
        {
            public uint m_nCount;
            public uint m_dwFirstAdded;
            public byte m_byOpcode;
            public bool m_bDbgLogged;
        }

        public uint m_uIP;
        public uint m_dwLastExpire;
        public List<TrackedRequestIn_Struct> m_aTrackedRequests;
    };

    public class PacketTracking
    {
        List<TrackPackets_Struct> listTrackedRequests;
        List<TrackChallenge_Struct> listChallengeRequests;
        List<TrackPacketsIn_Struct> m_liTrackPacketsIn;
        Dictionary<uint, TrackPacketsIn_Struct> m_mapTrackPacketsIn;
        uint dwLastTrackInCleanup;

        public PacketTracking()
        {
            dwLastTrackInCleanup = 0;
        }

        ~PacketTracking()
        {
            m_mapTrackPacketsIn.Clear();
            m_liTrackPacketsIn.Clear();
        }

        protected void AddTrackedOutPacket(uint dwIP, byte byOpcode)
        {
            // this tracklist tacks _outgoing_ request packets, to make sure incoming answer packets were requested
            // only track packets which we actually check for later
            if (!IsTrackedOutListRequestPacket(byOpcode))
                return;
            TrackPackets_Struct sTrack = new TrackPackets_Struct { dwIP = dwIP, dwInserted = (uint)Environment.TickCount, byOpcode = byOpcode };
            listTrackedRequests.Insert(0, sTrack);
            while (listTrackedRequests.Count > 0)
            {
                if (Environment.TickCount - listTrackedRequests[listTrackedRequests.Count - 1].dwInserted > Opcodes.SEC2MS(180))
                    listTrackedRequests.RemoveAt(listTrackedRequests.Count - 1);
                else
                    break;
            }
        }

        private bool IsTrackedOutListRequestPacket(byte byOpcode)
        {
            switch (byOpcode)
            {
                case Opcodes.KADEMLIA2_BOOTSTRAP_REQ:
                case Opcodes.KADEMLIA2_HELLO_REQ:
                case Opcodes.KADEMLIA2_HELLO_RES:
                case Opcodes.KADEMLIA2_REQ:
                case Opcodes.KADEMLIA_SEARCH_NOTES_REQ:
                case Opcodes.KADEMLIA2_SEARCH_NOTES_REQ:
                case Opcodes.KADEMLIA_PUBLISH_REQ:
                case Opcodes.KADEMLIA2_PUBLISH_KEY_REQ:
                case Opcodes.KADEMLIA2_PUBLISH_SOURCE_REQ:
                case Opcodes.KADEMLIA2_PUBLISH_NOTES_REQ:
                case Opcodes.KADEMLIA_FINDBUDDY_REQ:
                case Opcodes.KADEMLIA_CALLBACK_REQ:
                case Opcodes.KADEMLIA2_PING:
                    return true;
                    break;
                default:
                    return false;
            }
        }

        protected bool IsOnOutTrackList(uint dwIP, byte byOpcode, bool bDontRemove)
        {
#if DEBUG
            if (!IsTrackedOutListRequestPacket(byOpcode))
                Debug.Assert(false); // code error / bug
#endif
            for (int pos = 0;pos < listTrackedRequests.Count; pos++)
            {
                var trackedRequest = listTrackedRequests[pos];
                if (trackedRequest.dwIP == dwIP && trackedRequest.byOpcode == byOpcode && ((Environment.TickCount - trackedRequest.dwInserted) < Opcodes.SEC2MS(180)))
                {
                    if (!bDontRemove)
                        listTrackedRequests.RemoveAt(pos);
                    return true;
                }
            }
            return false;
        }

        protected bool InTrackListIsAllowedPacket(uint uIP, byte byOpcode, bool bValidSenderkey)
        {
            // this tracklist tacks _incoming_ request packets and acts as a general flood protection by dropping
            // too frequent requests from a single IP, avoiding response floods, processing time DOS attacks and slowing down
            // other possible attacks/behavior (scanning indexed files, fake publish floods, etc)

            // first figure out if this is a request packet to be tracked and its timelimits
            // timelimits are choosed by estimating the max. frequency of such packets on normal operation (+ buffer)
            // (those limits are not meant be fine to be used by normal usage, but only supposed to be a flood detection)
            uint iAllowedPacketsPerMinute;
            byte byDbgOrgOpcode = byOpcode;
            switch (byOpcode)
            {
                case Opcodes.KADEMLIA2_BOOTSTRAP_REQ:
                    iAllowedPacketsPerMinute = 2;
                    break;
                case Opcodes.KADEMLIA2_HELLO_REQ:
                    iAllowedPacketsPerMinute = 3;
                    break;
                case Opcodes.KADEMLIA2_REQ:
                    iAllowedPacketsPerMinute = 10;
                    break;
                case Opcodes.KADEMLIA2_SEARCH_NOTES_REQ:
                    iAllowedPacketsPerMinute = 3;
                    break;
                case Opcodes.KADEMLIA2_SEARCH_KEY_REQ:
                    iAllowedPacketsPerMinute = 3;
                    break;
                case Opcodes.KADEMLIA2_SEARCH_SOURCE_REQ:
                    iAllowedPacketsPerMinute = 3;
                    break;
                case Opcodes.KADEMLIA2_PUBLISH_KEY_REQ:
                    iAllowedPacketsPerMinute = 3;
                    break;
                case Opcodes.KADEMLIA2_PUBLISH_SOURCE_REQ:
                    iAllowedPacketsPerMinute = 2;
                    break;
                case Opcodes.KADEMLIA2_PUBLISH_NOTES_REQ:
                    iAllowedPacketsPerMinute = 2;
                    break;
                case Opcodes.KADEMLIA_FIREWALLED2_REQ:
                    byOpcode = Opcodes.KADEMLIA_FIREWALLED_REQ;
                    iAllowedPacketsPerMinute = 2;
                    break;
                case Opcodes.KADEMLIA_FIREWALLED_REQ:
                    iAllowedPacketsPerMinute = 2;
                    break;
                case Opcodes.KADEMLIA_FINDBUDDY_REQ:
                    iAllowedPacketsPerMinute = 2;
                    break;
                case Opcodes.KADEMLIA_CALLBACK_REQ:
                    iAllowedPacketsPerMinute = 1;
                    break;
                case Opcodes.KADEMLIA2_PING:
                    iAllowedPacketsPerMinute = 2;
                    break;
                default:
                    // not any request packets, so its a response packet - no further checks on this point
                    return true;
            }
            uint iSecondsPerPacket = 60 / iAllowedPacketsPerMinute;
            uint dwCurrentTick = (uint)Environment.TickCount;
            // time for cleaning up?
            if (dwCurrentTick - dwLastTrackInCleanup > Opcodes.MIN2MS(12))
                InTrackListCleanup();

            // check for existing entries
            TrackPacketsIn_Struct pTrackEntry;
            if (!m_mapTrackPacketsIn.ContainsKey(uIP))
            {
                pTrackEntry = new TrackPacketsIn_Struct();
                pTrackEntry.m_uIP = uIP;
                m_mapTrackPacketsIn[uIP] = pTrackEntry;
                m_liTrackPacketsIn.Insert(0, pTrackEntry);
            }
            else
            {
                pTrackEntry = m_mapTrackPacketsIn[uIP];
            }

            // search specific request tracks
            for (int i = 0; i < pTrackEntry.m_aTrackedRequests.Count; i++)
            {
                if (pTrackEntry.m_aTrackedRequests[i].m_byOpcode == byOpcode)
                {
                    // already tracked requests with theis opcode, remove already expired request counts
                    TrackPacketsIn_Struct.TrackedRequestIn_Struct rCurTrackedRequest = pTrackEntry.m_aTrackedRequests[i];
                    if (rCurTrackedRequest.m_nCount > 0 && dwCurrentTick - rCurTrackedRequest.m_dwFirstAdded > Opcodes.SEC2MS(iSecondsPerPacket))
                    {
                        uint nRemoveCount = (dwCurrentTick - rCurTrackedRequest.m_dwFirstAdded) / Opcodes.SEC2MS(iSecondsPerPacket);
                        if (nRemoveCount > rCurTrackedRequest.m_nCount)
                        {
                            rCurTrackedRequest.m_nCount = 0;
                            rCurTrackedRequest.m_dwFirstAdded = dwCurrentTick; // for the packet we just process
                        }
                        else
                        {
                            rCurTrackedRequest.m_nCount -= nRemoveCount;
                            rCurTrackedRequest.m_dwFirstAdded += Opcodes.SEC2MS(iSecondsPerPacket) * nRemoveCount;
                        }
                    }
                    // we increase the counter in any case, even if we drop the packet later
                    rCurTrackedRequest.m_nCount++;
                    // remember only for easier cleanup
                    pTrackEntry.m_dwLastExpire = Math.Max(pTrackEntry.m_dwLastExpire, rCurTrackedRequest.m_dwFirstAdded + Opcodes.SEC2MS(iSecondsPerPacket) * rCurTrackedRequest.m_nCount);

                    if (Kademlia.IsRunningInLANMode() && OtherFunctions.IsLANIP((uint)IPAddress.NetworkToHostOrder(uIP))) // no flood detection in LanMode
                        return true;

                    // now the actualy check if this request is allowed
                    if (rCurTrackedRequest.m_nCount > iAllowedPacketsPerMinute * 5)
                    {
                        // this is so far above the limit that it has to be an intentional flood / misuse in any case
                        // so we take the next higher punishment and ban the IP
                        //DebugLogWarning("Kad: Massive request flood detected for opcode 0x%X (0x%X) from IP %s - Banning IP", byOpcode, byDbgOrgOpcode, ipstr(ntohl(uIP)));
                        //theApp.clientlist.AddBannedClient(IPAddress.NetworkToHostOrder(uIP));
                        return false; // drop packet
                    }
                    else if (rCurTrackedRequest.m_nCount > iAllowedPacketsPerMinute)
                    {
                        // over the limit, drop the packet but do nothing else
                        if (!rCurTrackedRequest.m_bDbgLogged)
                        {
                            rCurTrackedRequest.m_bDbgLogged = true;
                            //DebugLog("Kad: Request flood detected for opcode 0x%X (0x%X) from IP %s - Droping packets with this opcode", byOpcode, byDbgOrgOpcode, ipstr(ntohl(uIP)));
                        }
                        return false; // drop packet
                    }
                    else
                        rCurTrackedRequest.m_bDbgLogged = false;
                    return true;
                }
            }

            // add a new entry for this request, no checks needed since 1 is always ok
            TrackPacketsIn_Struct.TrackedRequestIn_Struct curTrackedRequest;
            curTrackedRequest.m_byOpcode = byOpcode;
            curTrackedRequest.m_bDbgLogged = false;
            curTrackedRequest.m_dwFirstAdded = dwCurrentTick;
            curTrackedRequest.m_nCount = 1;
            // remember only for easier cleanup
            pTrackEntry.m_dwLastExpire = Math.Max(pTrackEntry.m_dwLastExpire, dwCurrentTick + Opcodes.SEC2MS(iSecondsPerPacket));
            pTrackEntry.m_aTrackedRequests.Add(curTrackedRequest);
            return true;
        }

        protected void InTrackListCleanup()
        {
            uint dwCurrentTick = (uint)Environment.TickCount;
            int dbgOldSize = m_liTrackPacketsIn.Count;
            dwLastTrackInCleanup = dwCurrentTick;
            int pos1, pos2;
            for (pos1 = 0; pos1 < m_liTrackPacketsIn.Count; pos1++)
            {
                m_liTrackPacketsIn.GetNext(pos1);
                TrackPacketsIn_Struct curEntry = m_liTrackPacketsIn[pos2];
                if (curEntry.m_dwLastExpire < dwCurrentTick)
                {
                    VERIFY(m_mapTrackPacketsIn.Remove(curEntry.m_uIP));
                    m_liTrackPacketsIn.RemoveAt(pos2);
                }
            }
            //DebugLog("Cleaned up Kad Incoming Requests Tracklist, entries before: %u, after %u", dbgOldSize, m_liTrackPacketsIn.Count);
        }

        protected void AddLegacyChallenge(UInt128 uContactID, UInt128 uChallengeID, uint uIP, byte byOpcode)
        {
            TrackChallenge_Struct sTrack = new TrackChallenge_Struct { uIP = uIP, dwInserted = (uint)Environment.TickCount, byOpcode = byOpcode, uContactID = uContactID, uChallenge = uChallengeID };
            listChallengeRequests.Insert(0, sTrack);
            while (listChallengeRequests.Count > 0)
            {
                if (Environment.TickCount - listChallengeRequests[listChallengeRequests.Count - 1].dwInserted > Opcodes.SEC2MS(180))
                {
                    //DEBUG_ONLY(DebugLog("Challenge timed out, client not verified - %s", ipstr(ntohl(listChallengeRequests.GetTail().uIP))));
                    listChallengeRequests.RemoveAt(listChallengeRequests.Count - 1);
                }
                else
                    break;
            }
        }

        protected bool IsLegacyChallenge(UInt128 uChallengeID, uint uIP, byte byOpcode, ref UInt128 ruContactID)
        {
            bool bDbgWarning = false;
            for (int pos = 0; pos < listChallengeRequests.Count; pos++)
            {
                var challengeRequest = listChallengeRequests[pos];
                if (challengeRequest.uIP == uIP && challengeRequest.byOpcode == byOpcode
                    && ((Environment.TickCount - challengeRequest.dwInserted) < Opcodes.SEC2MS(180)))
                {
                    Debug.Assert(challengeRequest.uChallenge != 0 || byOpcode == Opcodes.KADEMLIA2_PING);
                    if (challengeRequest.uChallenge == 0 || challengeRequest.uChallenge == uChallengeID)
                    {
                        ruContactID = challengeRequest.uContactID;
                        listChallengeRequests.RemoveAt(pos);
                        return true;
                    }
                    else
                        bDbgWarning = true;
                }
            }
            //if (bDbgWarning)
            //    DebugLogWarning("Kad: IsLegacyChallenge: Wrong challenge answer received, client not verified (%s)", ipstr(ntohl(uIP)));
            return false;
        }

        protected bool HasActiveLegacyChallenge(uint uIP)
        {
            foreach (var challengeRequest in listChallengeRequests)
            {
                if (challengeRequest.uIP == uIP && ((Environment.TickCount - challengeRequest.dwInserted) < Opcodes.SEC2MS(180)))
                    return true;
            }
            return false;
        }
    }
}
