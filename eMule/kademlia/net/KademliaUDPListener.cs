using eMule;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Kademlia
{
    struct FetchNodeID_Struct
    {
        uint dwIP;
        uint dwTCPPort;
        uint dwExpire;
        KadClientSearcher pRequester;
    }

    public class KademliaUDPListener : PacketTracking
    {
        private List<FetchNodeID_Struct> listFetchNodeIDRequests;
        private uint m_nOpenHellos;
        private uint m_nFirewalledHellos;

        ~KademliaUDPListener()
        {
            // report timeout to all pending FetchNodeIDRequests
            for (POSITION pos = listFetchNodeIDRequests.GetHeadPosition(); pos != null; listFetchNodeIDRequests.GetNext(pos))
                listFetchNodeIDRequests.GetAt(pos).pRequester->KadSearchNodeIDByIPResult(KCSR_TIMEOUT, null);
        }

        // Used by Kad1.0 and Kad 2.0
        public void Bootstrap(string szHost, ushort uUDPPort)
        {
            uint uRetVal = 0;
            if (char.IsLetter(szHost[0]))
            {
                //hostent* php = gethostbyname(CT2CA(szHost));
                //if (php == NULL)
                //    return;
                //memcpy(&uRetVal, php->h_addr, sizeof(uRetVal));
            }
            else
            {
                uRetVal = BitConverter.ToUInt32(IPAddress.Parse(szHost).GetAddressBytes(), 0);
            }

            Bootstrap((uint)IPAddress.NetworkToHostOrder(uRetVal), uUDPPort);
        }

        // Used by Kad1.0 and Kad 2.0
        public void Bootstrap(uint uIP, ushort uUDPPort, byte byKadVersion = 0, UInt128 uCryptTargetID = null)
        {
            if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                DebugSend("KADEMLIA2_BOOTSTRAP_REQ", uIP, uUDPPort);
            CSafeMemFile fileIO(0);
            if (byKadVersion >= Opcodes.KADEMLIA_VERSION6_49aBETA)
                SendPacket(&fileIO, Opcodes.KADEMLIA2_BOOTSTRAP_REQ, uIP, uUDPPort, 0, uCryptTargetID);
            else
                SendPacket(&fileIO, Opcodes.KADEMLIA2_BOOTSTRAP_REQ, uIP, uUDPPort, 0, null);
        }

        // Used by Kad1.0 and Kad 2.0
        public void SendMyDetails(byte byOpcode, uint uIP, ushort uUDPPort, byte byKadVersion, KadUDPKey targetUDPKey, UInt128 uCryptTargetID, bool bRequestAckPackage)
        {
            if (byKadVersion > 1)
            {
                byte[] byPacket = new byte[1024];
                CByteIO byteIOResponse(byPacket, sizeof(byPacket));
                byteIOResponse.WriteByte(Opcodes.OP_KADEMLIAHEADER);
                byteIOResponse.WriteByte(byOpcode);
                byteIOResponse.WriteUInt128(Kademlia.GetPrefs().GetKadID());
                byteIOResponse.WriteUInt16(thePrefs.GetPort());
                byteIOResponse.WriteUInt8(Opcodes.KADEMLIA_VERSION);

                // Tag Count.
                byte byTagCount = 0;
                if (!Kademlia.GetPrefs().GetUseExternKadPort())
                    byTagCount++;
                if (byKadVersion >= Opcodes.KADEMLIA_VERSION8_49b
                    && (bRequestAckPackage || Kademlia.GetPrefs().GetFirewalled() || UDPFirewallTester.IsFirewalledUDP(true)))
                {
                    byTagCount++;
                }
                byteIOResponse.WriteUInt8(byTagCount);
                if (!Kademlia.GetPrefs().GetUseExternKadPort())
                    byteIOResponse.WriteTag(&KadTagUInt16(Opcodes.TAG_SOURCEUPORT, Kademlia.GetPrefs().GetInternKadPort()));
                if (byKadVersion >= Opcodes.KADEMLIA_VERSION8_49b
                    && (bRequestAckPackage || Kademlia.GetPrefs().GetFirewalled() || UDPFirewallTester.IsFirewalledUDP(true)))
                {
                    // if we are firewalled we sent this tag, so the other client doesn't adds us to his routing table (if UDP firewalled) and for statistics reasons (TCP firewalled)
                    // 5 - reserved (!)
                    // 1 - Requesting HELLO_RES_ACK
                    // 1 - TCP firewalled
                    // 1 - UDP firewalled
                    byte uUDPFirewalled = UDPFirewallTester.IsFirewalledUDP(true) ? (byte)1 : (byte)0;
                    byte uTCPFirewalled = Kademlia.GetPrefs().GetFirewalled() ? (byte)1 : (byte)0;
                    byte uRequestACK = bRequestAckPackage ? (byte)1 : (byte)0;
                    byte byMiscOptions = (uRequestACK << 2) | (uTCPFirewalled << 1) | (uUDPFirewalled << 0);
                    byteIOResponse.WriteTag(CKadTagUInt8(TAG_KADMISCOPTIONS, byMiscOptions));
                }
                //byteIOResponse.WriteTag(&CKadTagUInt(TAG_USER_COUNT, CKademlia::GetPrefs()->GetKademliaUsers()));
                //byteIOResponse.WriteTag(&CKadTagUInt(TAG_FILE_COUNT, CKademlia::GetPrefs()->GetKademliaFiles()));

                uint uLen = sizeof(byPacket) - byteIOResponse.GetAvailable();
                if (byKadVersion >= KADEMLIA_VERSION6_49aBETA)
                {
                    if (isnulmd4(uCryptTargetID.GetDataPtr()))
                    {
                        DebugLogWarning("Sending hello response to crypt enabled Kad Node which provided an empty NodeID: %s (%u)", ipstr(ntohl(uIP)), byKadVersion);
                        SendPacket(byPacket, uLen, uIP, uUDPPort, targetUDPKey, null);
                    }
                    else
                        SendPacket(byPacket, uLen, uIP, uUDPPort, targetUDPKey, uCryptTargetID);
                }
                else
                {
                    SendPacket(byPacket, uLen, uIP, uUDPPort, 0, null);
                    Debug.Assert(targetUDPKey.IsEmpty());
                }
            }
            else
            {
                Debug.Assert(false);
            }
        }

        // Kad1.0 & Kad2.0 currently.
        public void FirewalledCheck(uint uIP, ushort uUDPPort, KadUDPKey senderUDPKey, byte byKadVersion)
        {
            if (byKadVersion > Opcodes.KADEMLIA_VERSION6_49aBETA)
            {
                // new Opcode since 0.49a with extended informations to support obfuscated connections properly
                CSafeMemFile fileIO(19);
                fileIO.WriteUInt16(thePrefs.GetPort());
                fileIO.WriteUInt128(Kademlia.GetPrefs().GetClientHash());
                fileIO.WriteUInt8(Kademlia.GetPrefs().GetMyConnectOptions(true, false));
                if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                    DebugSend("KADEMLIA_FIREWALLED2_REQ", uIP, uUDPPort);
                SendPacket(&fileIO, Opcodes.KADEMLIA_FIREWALLED2_REQ, uIP, uUDPPort, senderUDPKey, null);
            }
            else
            {
                CSafeMemFile fileIO(2);
                fileIO.WriteUInt16(thePrefs.GetPort());
                if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                    DebugSend("KADEMLIA_FIREWALLED_REQ", uIP, uUDPPort);
                SendPacket(&fileIO, Opcodes.KADEMLIA_FIREWALLED_REQ, uIP, uUDPPort, senderUDPKey, null);
            }
            theApp.clientlist.AddKadFirewallRequest(ntohl(uIP));
        }

        public void SendNullPacket(byte byOpcode, uint uIP, ushort uUDPPort, KadUDPKey targetUDPKey, UInt128 uCryptTargetID)
        {
            CSafeMemFile fileIO(0);
            SendPacket(&fileIO, byOpcode, uIP, uUDPPort, targetUDPKey, uCryptTargetID);
        }

        public void SendPublishSourcePacket(Contact pContact, UInt128 &uTargetID, UInt128 &uContactID, TagList& tags)
        {
            //We need to get the tag lists working with CSafeMemFiles..
            byte[] byPacket = new byte[1024];
            CByteIO byteIO(byPacket, sizeof(byPacket));
            byteIO.WriteByte(Opcodes.OP_KADEMLIAHEADER);
            if (pContact.Version >= 4/*47c*/)
            {
                byteIO.WriteByte(Opcodes.KADEMLIA2_PUBLISH_SOURCE_REQ);
                byteIO.WriteUInt128(uTargetID);
                byteIO.WriteUInt128(uContactID);
                byteIO.WriteTagList(tags);
                if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                {
                    DebugSend("KADEMLIA2_PUBLISH_SOURCE_REQ", pContact.IPAddress, pContact.UDPPort);
                }
            }
            else
            {
                byteIO.WriteByte(Opcodes.KADEMLIA_PUBLISH_REQ);
                byteIO.WriteUInt128(uTargetID);
                //We only use this for publishing sources now.. So we always send one here..
                byteIO.WriteUInt16(1);
                byteIO.WriteUInt128(uContactID);
                byteIO.WriteTagList(tags);
                if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                {
                    DebugSend("KADEMLIA_PUBLISH_REQ", pContact.IPAddress, pContact.UDPPort);
                }
            }
            uint uLen = sizeof(byPacket) - byteIO.GetAvailable();
            if (pContact.Version >= 6/*>48b*/) // obfuscated?
            {
                UInt128 uClientID = pContact.ClientID;
                SendPacket(byPacket, uLen, pContact.IPAddress, pContact.UDPPort, pContact.UDPKey, uClientID);
            }
            else
                SendPacket(byPacket, uLen, pContact.IPAddress, pContact.UDPPort, 0, null);
        }

        void ProcessPacket(byte[] pbyData, uint uLenData, uint uIP, ushort uUDPPort, bool bValidReceiverKey, KadUDPKey senderUDPKey)
        {
            // we do not accept (<= 0.48a) unencrypted incoming packages from port 53 (DNS) to avoid attacks based on DNS protocol confusion
            if (uUDPPort == 53 && senderUDPKey.IsEmpty())
            {
                DEBUG_ONLY(DebugLog("Droping incoming unencrypted packet on port 53 (DNS), IP: %s", ipstr(ntohl(uIP))));
                return;
            }

            //Update connection state only when it changes.
            bool bCurCon = Kademlia.GetPrefs().HasHadContact();
            Kademlia.GetPrefs().SetLastContact();
            UDPFirewallTester.Connected();
            if (bCurCon != Kademlia.GetPrefs().HasHadContact())
                theApp.emuledlg.ShowConnectionState();

            byte byOpcode = pbyData[1];
            byte[] pbyPacketData = pbyData + 2;
            uint uLenPacket = uLenData - 2;

            if (!InTrackListIsAllowedPacket(uIP, byOpcode, bValidReceiverKey))
                return;

            //	AddDebugLogLine( false, _T("Processing UDP Packet from %s port %ld : opcode length %ld", ipstr(senderAddress->sin_addr), ntohs(senderAddress->sin_port), uLenPacket);
            //	CMiscUtils::debugHexDump(pbyPacketData, uLenPacket);

            switch (byOpcode)
            {
                case Opcodes.KADEMLIA2_BOOTSTRAP_REQ:
                    if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                        DebugRecv("KADEMLIA2_BOOTSTRAP_REQ", uIP, uUDPPort);
                    Process_KADEMLIA2_BOOTSTRAP_REQ(uIP, uUDPPort, senderUDPKey);
                    break;
                case Opcodes.KADEMLIA2_BOOTSTRAP_RES:
                    if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                        DebugRecv("KADEMLIA2_BOOTSTRAP_RES", uIP, uUDPPort);
                    Process_KADEMLIA2_BOOTSTRAP_RES(pbyPacketData, uLenPacket, uIP, uUDPPort, senderUDPKey, bValidReceiverKey);
                    break;
                case Opcodes.KADEMLIA2_HELLO_REQ:
                    if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                        DebugRecv("KADEMLIA2_HELLO_REQ", uIP, uUDPPort);
                    Process_KADEMLIA2_HELLO_REQ(pbyPacketData, uLenPacket, uIP, uUDPPort, senderUDPKey, bValidReceiverKey);
                    break;
                case Opcodes.KADEMLIA2_HELLO_RES:
                    if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                        DebugRecv("KADEMLIA2_HELLO_RES", uIP, uUDPPort);
                    Process_KADEMLIA2_HELLO_RES(pbyPacketData, uLenPacket, uIP, uUDPPort, senderUDPKey, bValidReceiverKey);
                    break;
                case Opcodes.KADEMLIA2_HELLO_RES_ACK:
                    if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                        DebugRecv("KADEMLIA2_HELLO_RES_ACK", uIP, uUDPPort);
                    Process_KADEMLIA2_HELLO_RES_ACK(pbyPacketData, uLenPacket, uIP, bValidReceiverKey);
                    break;
                case Opcodes.KADEMLIA2_REQ:
                    if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                        DebugRecv("KADEMLIA2_REQ", uIP, uUDPPort);
                    Process_KADEMLIA2_REQ(pbyPacketData, uLenPacket, uIP, uUDPPort, senderUDPKey);
                    break;
                case Opcodes.KADEMLIA2_RES:
                    if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                        DebugRecv("KADEMLIA2_RES", uIP, uUDPPort);
                    Process_KADEMLIA2_RES(pbyPacketData, uLenPacket, uIP, uUDPPort, senderUDPKey);
                    break;
                case Opcodes.KADEMLIA2_SEARCH_NOTES_REQ:
                    if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                        DebugRecv("KADEMLIA2_SEARCH_NOTES_REQ", uIP, uUDPPort);
                    Process_KADEMLIA2_SEARCH_NOTES_REQ(pbyPacketData, uLenPacket, uIP, uUDPPort, senderUDPKey);
                    break;
                case Opcodes.KADEMLIA2_SEARCH_KEY_REQ:
                    if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                        DebugRecv("KADEMLIA2_SEARCH_KEY_REQ", uIP, uUDPPort);
                    Process_KADEMLIA2_SEARCH_KEY_REQ(pbyPacketData, uLenPacket, uIP, uUDPPort, senderUDPKey);
                    break;
                case Opcodes.KADEMLIA2_SEARCH_SOURCE_REQ:
                    if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                        DebugRecv("KADEMLIA2_SEARCH_SOURCE_REQ", uIP, uUDPPort);
                    Process_KADEMLIA2_SEARCH_SOURCE_REQ(pbyPacketData, uLenPacket, uIP, uUDPPort, senderUDPKey);
                    break;
                case Opcodes.KADEMLIA_SEARCH_RES:
                    if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                        DebugRecv("KADEMLIA_SEARCH_RES", uIP, uUDPPort);
                    Process_KADEMLIA_SEARCH_RES(pbyPacketData, uLenPacket, uIP, uUDPPort);
                    break;
                case Opcodes.KADEMLIA_SEARCH_NOTES_RES:
                    if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                        DebugRecv("KADEMLIA_SEARCH_NOTES_RES", uIP, uUDPPort);
                    Process_KADEMLIA_SEARCH_NOTES_RES(pbyPacketData, uLenPacket, uIP, uUDPPort);
                    break;
                case Opcodes.KADEMLIA2_SEARCH_RES:
                    if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                        DebugRecv("KADEMLIA2_SEARCH_RES", uIP, uUDPPort);
                    Process_KADEMLIA2_SEARCH_RES(pbyPacketData, uLenPacket, senderUDPKey, uIP, uUDPPort);
                    break;
                case Opcodes.KADEMLIA2_PUBLISH_KEY_REQ:
                    if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                        DebugRecv("KADEMLIA2_PUBLISH_KEY_REQ", uIP, uUDPPort);
                    Process_KADEMLIA2_PUBLISH_KEY_REQ(pbyPacketData, uLenPacket, uIP, uUDPPort, senderUDPKey);
                    break;
                case Opcodes.KADEMLIA2_PUBLISH_SOURCE_REQ:
                    if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                        DebugRecv("KADEMLIA2_PUBLISH_SOURCE_REQ", uIP, uUDPPort);
                    Process_KADEMLIA2_PUBLISH_SOURCE_REQ(pbyPacketData, uLenPacket, uIP, uUDPPort, senderUDPKey);
                    break;
                case Opcodes.KADEMLIA2_PUBLISH_NOTES_REQ:
                    if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                        DebugRecv("KADEMLIA2_PUBLISH_NOTES_REQ", uIP, uUDPPort);
                    Process_KADEMLIA2_PUBLISH_NOTES_REQ(pbyPacketData, uLenPacket, uIP, uUDPPort, senderUDPKey);
                    break;
                case Opcodes.KADEMLIA_PUBLISH_RES:
                    if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                        DebugRecv("KADEMLIA_PUBLISH_RES", uIP, uUDPPort);
                    Process_KADEMLIA_PUBLISH_RES(pbyPacketData, uLenPacket, uIP);
                    break;
                case Opcodes.KADEMLIA2_PUBLISH_RES:
                    if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                        DebugRecv("KADEMLIA2_PUBLISH_RES", uIP, uUDPPort);
                    Process_KADEMLIA2_PUBLISH_RES(pbyPacketData, uLenPacket, uIP, uUDPPort, senderUDPKey);
                    break;
                case Opcodes.KADEMLIA_FIREWALLED_REQ:
                    if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                        DebugRecv("KADEMLIA_FIREWALLED_REQ", uIP, uUDPPort);
                    Process_KADEMLIA_FIREWALLED_REQ(pbyPacketData, uLenPacket, uIP, uUDPPort, senderUDPKey);
                    break;
                case Opcodes.KADEMLIA_FIREWALLED2_REQ:
                    if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                        DebugRecv("KADEMLIA_FIREWALLED2_REQ", uIP, uUDPPort);
                    Process_KADEMLIA_FIREWALLED2_REQ(pbyPacketData, uLenPacket, uIP, uUDPPort, senderUDPKey);
                    break;
                case Opcodes.KADEMLIA_FIREWALLED_RES:
                    if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                        DebugRecv("KADEMLIA_FIREWALLED_RES", uIP, uUDPPort);
                    Process_KADEMLIA_FIREWALLED_RES(pbyPacketData, uLenPacket, uIP, senderUDPKey);
                    break;
                case Opcodes.KADEMLIA_FIREWALLED_ACK_RES:
                    if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                        DebugRecv("KADEMLIA_FIREWALLED_ACK_RES", uIP, uUDPPort);
                    Process_KADEMLIA_FIREWALLED_ACK_RES(uLenPacket);
                    break;
                case Opcodes.KADEMLIA_FINDBUDDY_REQ:
                    if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                        DebugRecv("KADEMLIA_FINDBUDDY_REQ", uIP, uUDPPort);
                    Process_KADEMLIA_FINDBUDDY_REQ(pbyPacketData, uLenPacket, uIP, uUDPPort, senderUDPKey);
                    break;
                case Opcodes.KADEMLIA_FINDBUDDY_RES:
                    if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                        DebugRecv("KADEMLIA_FINDBUDDY_RES", uIP, uUDPPort);
                    Process_KADEMLIA_FINDBUDDY_RES(pbyPacketData, uLenPacket, uIP, uUDPPort, senderUDPKey);
                    break;
                case Opcodes.KADEMLIA_CALLBACK_REQ:
                    if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                        DebugRecv("KADEMLIA_CALLBACK_REQ", uIP, uUDPPort);
                    Process_KADEMLIA_CALLBACK_REQ(pbyPacketData, uLenPacket, uIP, senderUDPKey);
                    break;
                case Opcodes.KADEMLIA2_PING:
                    if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                        DebugRecv("KADEMLIA2_PING", uIP, uUDPPort);
                    Process_KADEMLIA2_PING(uIP, uUDPPort, senderUDPKey);
                    break;
                case Opcodes.KADEMLIA2_PONG:
                    if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                        DebugRecv("KADEMLIA2_PONG", uIP, uUDPPort);
                    Process_KADEMLIA2_PONG(pbyPacketData, uLenPacket, uIP, uUDPPort, senderUDPKey);
                    break;
                case Opcodes.KADEMLIA2_FIREWALLUDP:
                    if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                        DebugRecv("KADEMLIA2_FIREWALLUDP", uIP, uUDPPort);
                    Process_KADEMLIA2_FIREWALLUDP(pbyPacketData, uLenPacket, uIP, senderUDPKey);
                    break;

                // old Kad1 opcodes which we don't handle anymore
                case Opcodes.KADEMLIA_BOOTSTRAP_REQ_DEPRECATED:
                case Opcodes.KADEMLIA_BOOTSTRAP_RES_DEPRECATED:
                case Opcodes.KADEMLIA_HELLO_REQ_DEPRECATED:
                case Opcodes.KADEMLIA_HELLO_RES_DEPRECATED:
                case Opcodes.KADEMLIA_REQ_DEPRECATED:
                case Opcodes.KADEMLIA_RES_DEPRECATED:
                case Opcodes.KADEMLIA_PUBLISH_NOTES_REQ_DEPRECATED:
                case Opcodes.KADEMLIA_PUBLISH_NOTES_RES_DEPRECATED:
                case Opcodes.KADEMLIA_SEARCH_REQ:
                case Opcodes.KADEMLIA_PUBLISH_REQ:
                case Opcodes.KADEMLIA_SEARCH_NOTES_REQ:
                    break;
                default:
                    string strError = $"Unknown opcode {byOpcode}";
                    throw new Exception(strError);
            }
        }

        // Used only for Kad2.0
        private bool AddContact_KADEMLIA2(byte[] pbyData, uint uLenData, uint uIP, ushort uUDPPort, byte[] pnOutVersion, KadUDPKey cUDPKey, ref bool rbIPVerified, bool bUpdate, bool bFromHelloReq, bool pbOutRequestsACK, UInt128 puOutContactID)
        {
            if (pbOutRequestsACK != null)
                pbOutRequestsACK = false;

            CByteIO byteIO(pbyData, uLenData);
            UInt128 uID;
            byteIO.ReadUInt128(&uID);
            if (puOutContactID != null)
                puOutContactID = uID;
            ushort uTCPPort = byteIO.ReadUInt16();
            byte uVersion = byteIO.ReadByte();
            if (pnOutVersion != null)
                pnOutVersion = uVersion;

            bool bUDPFirewalled = false;
            bool bTCPFirewalled = false;
            byte uTags = byteIO.ReadByte();
            while (uTags)
            {
                KadTag pTag = byteIO.ReadTag();

                if (!pTag->m_name.Compare(TAG_SOURCEUPORT))
                {
                    if (pTag->IsInt() && (ushort)pTag->GetInt() > 0)
                        uUDPPort = (ushort)pTag->GetInt();
                    else
                        Debug.Assert(false);
                }

                if (!pTag->m_name.Compare(TAG_KADMISCOPTIONS))
                {
                    if (pTag->IsInt() && (ushort)pTag->GetInt() > 0)
                    {
                        bUDPFirewalled = (pTag->GetInt() & 0x01) > 0;
                        bTCPFirewalled = (pTag->GetInt() & 0x02) > 0;
                        if ((pTag->GetInt() & 0x04) > 0)
                        {
                            if (pbOutRequestsACK != null && uVersion >= KADEMLIA_VERSION8_49b)
                                *pbOutRequestsACK = true;
                            else
                                Debug.Assert(false);
                        }
                    }
                    else
                        Debug.Assert(false);
                }

                delete pTag;
                --uTags;
            }
            // check if we are waiting for informations (nodeid) about this client and if so inform the requester
            for (POSITION pos = listFetchNodeIDRequests.GetHeadPosition(); pos != null; listFetchNodeIDRequests.GetNext(pos))
            {
                if (listFetchNodeIDRequests.GetAt(pos).dwIP == uIP && listFetchNodeIDRequests.GetAt(pos).dwTCPPort == uTCPPort)
                {
                    CString strID;
                    uID.ToHexString(&strID);
                    DebugLog(_T("Result Addcontact: %s"), strID);
                    uchar uchID[16];
                    uID.ToByteArray(uchID);
                    listFetchNodeIDRequests.GetAt(pos).pRequester->KadSearchNodeIDByIPResult(KCSR_SUCCEEDED, uchID);
                    listFetchNodeIDRequests.RemoveAt(pos);
                    break;
                }
            }

            if (bFromHelloReq && uVersion >= KADEMLIA_VERSION8_49b)
            {
                // this is just for statistic calculations. We try to determine the ratio of (UDP) firewalled users,
                // by counting how many of all nodes which have us in their routing table (our own routing table is supposed
                // to have no UDP firewalled nodes at all) and support the firewalled tag are firewalled themself.
                // Obviously this only works if we are not firewalled ourself
                CKademlia::GetPrefs()->StatsIncUDPFirewalledNodes(bUDPFirewalled);
                CKademlia::GetPrefs()->StatsIncTCPFirewalledNodes(bTCPFirewalled);
            }

            if (!bUDPFirewalled) // do not add (or update) UDP firewalled sources to our routing table
                return CKademlia::GetRoutingZone()->Add(uID, uIP, uUDPPort, uTCPPort, uVersion, cUDPKey, rbIPVerified, bUpdate, false, true);
            else
            {
                //DEBUG_ONLY( AddDebugLogLine(DLP_LOW, false, _T("Kad: Not adding firewalled client to routing table (%s)"), ipstr(ntohl(uIP))) );
                return false;
            }
        }

        // Used only for Kad2.0
        private void Process_KADEMLIA2_BOOTSTRAP_REQ(uint uIP, ushort uUDPPort, KadUDPKey senderUDPKey)
        {
            // Get some contacts to return
            ContactList contacts;
            ushort uNumContacts = (ushort)CKademlia::GetRoutingZone()->GetBootstrapContacts(&contacts, 20);

            // Create response packet
            //We only collect a max of 20 contacts here.. Max size is 527.
            //2 + 25(20) + 19
            CSafeMemFile fileIO(521);

            fileIO.WriteUInt128(&CKademlia::GetPrefs()->GetKadID());
            fileIO.WriteUInt16(thePrefs.GetPort());
            fileIO.WriteUInt8(KADEMLIA_VERSION);

            // Write packet info
            fileIO.WriteUInt16(uNumContacts);
            for (ContactList::const_iterator iContactList = contacts.begin(); iContactList != contacts.end(); ++iContactList)
            {
                CContact* pContact = *iContactList;
                fileIO.WriteUInt128(&pContact->GetClientID());
                fileIO.WriteUInt32(pContact->GetIPAddress());
                fileIO.WriteUInt16(pContact->GetUDPPort());
                fileIO.WriteUInt16(pContact->GetTCPPort());
                fileIO.WriteUInt8(pContact->GetVersion());
            }

            // Send response
            if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                DebugSend("KADEMLIA2_BOOTSTRAP_RES", uIP, uUDPPort);

            SendPacket(&fileIO, KADEMLIA2_BOOTSTRAP_RES, uIP, uUDPPort, senderUDPKey, null);
        }

        // Used only for Kad2.0
        private void Process_KADEMLIA2_BOOTSTRAP_RES(byte[] pbyPacketData, uint uLenPacket, uint uIP, ushort uUDPPort, KadUDPKey senderUDPKey, bool bValidReceiverKey)
        {
            if (!IsOnOutTrackList(uIP, KADEMLIA2_BOOTSTRAP_REQ))
            {
                CString strError;
                strError.Format(_T("***NOTE: Received unrequested response packet, size (%u) in %hs"), uLenPacket, __FUNCTION__);
                throw strError;
            }
            CRoutingZone* pRoutingZone = CKademlia::GetRoutingZone();

            // How many contacts were given
            CSafeMemFile fileIO(pbyPacketData, uLenPacket);
            UInt128 uContactID;
            fileIO.ReadUInt128(&uContactID);
            ushort uTCPPort = fileIO.ReadUInt16();
            uint8 uVersion = fileIO.ReadUInt8();
            // If we don't know any Contacts yet and try to Bootstrap, we assume that all contacts are verified,
            // in order to speed up the connecting process. The attackvectors to exploit this are very small with no
            // major effects, so thats a good trade
            bool bAssumeVerified = CKademlia::GetRoutingZone()->GetNumContacts() == 0;

            if (CKademlia::s_liBootstapList.IsEmpty())
                pRoutingZone->Add(uContactID, uIP, uUDPPort, uTCPPort, uVersion, senderUDPKey, bValidReceiverKey, true, false, false);

            DEBUG_ONLY(AddDebugLogLine(DLP_LOW, false, _T("Inc Kad2 Bootstrap Packet from %s"), ipstr(ntohl(uIP))));

            ushort uNumContacts = fileIO.ReadUInt16();
            while (uNumContacts)
            {
                fileIO.ReadUInt128(&uContactID);
                uint uIP = fileIO.ReadUInt32();
                ushort uUDPPort = fileIO.ReadUInt16();
                ushort uTCPPort = fileIO.ReadUInt16();
                uint8 uVersion = fileIO.ReadUInt8();
                bool bVerified = bAssumeVerified;
                pRoutingZone->Add(uContactID, uIP, uUDPPort, uTCPPort, uVersion, 0, bVerified, false, false, false);
                uNumContacts--;
            }
        }

        // Used in Kad2.0 only
        private void Process_KADEMLIA2_HELLO_REQ(byte[] pbyPacketData, uint uLenPacket, uint uIP, ushort uUDPPort, KadUDPKey senderUDPKey, bool bValidReceiverKey)
        {
            //ushort dbgOldUDPPort = uUDPPort;
            uint8 byContactVersion = 0;
            UInt128 uContactID;
            bool bAddedOrUpdated = AddContact_KADEMLIA2(pbyPacketData, uLenPacket, uIP, uUDPPort, &byContactVersion, senderUDPKey, bValidReceiverKey, true, true, null, &uContactID); // might change uUDPPort, bValidReceiverKey
            Debug.Assert(byContactVersion >= 2);
            //if (dbgOldUDPPort != uUDPPort)
            //	DEBUG_ONLY( DebugLog(_T("KadContact %s uses his internal (%u) instead external (%u) UDP Port"), ipstr(ntohl(uIP)), uUDPPort, dbgOldUDPPort) ); 

            if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                DebugSend("KADEMLIA2_HELLO_RES", uIP, uUDPPort);
            // if this contact was added or updated (so with other words not filtered or invalid) to our routing table and did not already sent a valid
            // receiver key or is already verified in the routing table, we request an additional ACK package to complete a three-way-handshake and
            // verify the remotes IP
            SendMyDetails(KADEMLIA2_HELLO_RES, uIP, uUDPPort, byContactVersion, senderUDPKey, &uContactID, bAddedOrUpdated && !bValidReceiverKey);

            if (bAddedOrUpdated && !bValidReceiverKey && byContactVersion == KADEMLIA_VERSION7_49a && !HasActiveLegacyChallenge(uIP))
            {
                // Kad Version 7 doesnt supports HELLO_RES_ACK, but sender/receiver keys, so send a ping to validate
                AddLegacyChallenge(uContactID, (ULONG)0, uIP, KADEMLIA2_PING);
                SendNullPacket(KADEMLIA2_PING, uIP, uUDPPort, senderUDPKey, null);
# ifdef _DEBUG
                CContact* pContact = CKademlia::GetRoutingZone()->GetContact(uContactID);
                if (pContact != null)
                {
                    if (pContact->GetType() < 2)
                        DebugLogWarning(_T("Process_KADEMLIA2_HELLO_REQ: Sending (ping) challenge to a long known contact (should be verified already) - %s"), ipstr(ntohl(uIP)));
                }
                else
                    Debug.Assert(false);
#endif
            }
            else if (CKademlia::GetPrefs()->FindExternKadPort(false) && byContactVersion > KADEMLIA_VERSION5_48a) // do we need to find out our extern port?
                SendNullPacket(KADEMLIA2_PING, uIP, uUDPPort, senderUDPKey, null);

            if (bAddedOrUpdated && !bValidReceiverKey && byContactVersion < KADEMLIA_VERSION7_49a && !HasActiveLegacyChallenge(uIP))
            {
                // we need to verify this contact but it doesn'T support HELLO_RES_ACK nor Keys, do a little work arround
                SendLegacyChallenge(uIP, uUDPPort, uContactID);
            }

            // Check if firewalled
            if (CKademlia::GetPrefs()->GetRecheckIP())
                FirewalledCheck(uIP, uUDPPort, senderUDPKey, byContactVersion);
        }

        // Used in Kad2.0 only
        private void Process_KADEMLIA2_HELLO_RES_ACK(byte[] pbyPacketData, uint uLenPacket, uint uIP, bool bValidReceiverKey)
        {
            if (uLenPacket < 17)
            {
                CString strError;
                strError.Format(_T("***NOTE: Received wrong size (%u) packet in %hs"), uLenPacket, __FUNCTION__);
                throw strError;
            }
            else if (!IsOnOutTrackList(uIP, KADEMLIA2_HELLO_RES))
            {
                CString strError;
                strError.Format(_T("***NOTE: Received unrequested response packet, size (%u) in %hs"), uLenPacket, __FUNCTION__);
                throw strError;
            }
            else if (!bValidReceiverKey)
            {
                DebugLogWarning(_T("Kad: Process_KADEMLIA2_HELLO_RES_ACK: Receiver key is invalid! (sender: %s)"), ipstr(ntohl(uIP)));
                return;
            }
            // additional packet to complete a three-way-handshake, makeing sure the remote contact is not using a spoofed IP
            CSafeMemFile fileIO(pbyPacketData, uLenPacket);
            UInt128 uRemoteID;
            fileIO.ReadUInt128(&uRemoteID);
            if (!CKademlia::GetRoutingZone()->VerifyContact(uRemoteID, uIP))
            {
                DebugLogWarning(_T("Kad: Process_KADEMLIA2_HELLO_RES_ACK: Unable to find valid sender in routing table (sender: %s)"), ipstr(ntohl(uIP)));
            }
            //else
            //	DEBUG_ONLY( AddDebugLogLine(DLP_LOW, false, _T("Verified contact (%s) by HELLO_RES_ACK"), ipstr(ntohl(uIP))) ); 
        }

        // Used in Kad2.0 only
        private void Process_KADEMLIA2_HELLO_RES(byte[] pbyPacketData, uint uLenPacket, uint uIP, ushort uUDPPort, KadUDPKey senderUDPKey, bool bValidReceiverKey)
        {
            if (!IsOnOutTrackList(uIP, KADEMLIA2_HELLO_REQ))
            {
                CString strError;
                strError.Format(_T("***NOTE: Received unrequested response packet, size (%u) in %hs"), uLenPacket, __FUNCTION__);
                throw strError;
            }

            // Add or Update contact.
            uint8 byContactVersion;
            UInt128 uContactID;
            bool bSendACK = false;
            bool bAddedOrUpdated = AddContact_KADEMLIA2(pbyPacketData, uLenPacket, uIP, uUDPPort, &byContactVersion, senderUDPKey, bValidReceiverKey, true, false, &bSendACK, &uContactID);

            if (bSendACK)
            {
                // the client requested us to send an ACK package, which proves that we are not a spoofed fake contact
                // fullfill his wish
                if (senderUDPKey.IsEmpty())
                {
                    // but we don't have a valid senderkey - there is no point to reply in this case
                    // most likely a bug in the remote client:
                    DebugLogWarning(_T("Kad: Process_KADEMLIA2_HELLO_RES: Remote clients demands ACK, but didn't sent any Senderkey! (%s)"), ipstr(ntohl(uIP)));
                }
                else
                {
                    CSafeMemFile fileIO(17);
                    UInt128 uID(CKademlia::GetPrefs()->GetKadID());
                    fileIO.WriteUInt128(&uID);
                    fileIO.WriteUInt8(0); // na tags at this time
                    if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                        DebugSend("KADEMLIA2_HELLO_RES_ACK", uIP, uUDPPort);
                    SendPacket(&fileIO, KADEMLIA2_HELLO_RES_ACK, uIP, uUDPPort, senderUDPKey, null);
                    //DEBUG_ONLY( AddDebugLogLine(DLP_LOW, false, _T("Sent HELLO_RES_ACK to %s"), ipstr(ntohl(uIP))) ); 
                }
            }
            else if (bAddedOrUpdated && !bValidReceiverKey && byContactVersion < KADEMLIA_VERSION7_49a)
            {
                // even through this is supposly an answer to a request from us, there are still possibilities to spoof
                // it, as long as the attacker knows that we would send a HELLO_REQ (which is this case quite often),
                // so for old Kad Version which don't support keys, we need
                SendLegacyChallenge(uIP, uUDPPort, uContactID);
            }

            // dw we need to find out our extern port?
            if (CKademlia::GetPrefs()->FindExternKadPort(false) && byContactVersion > KADEMLIA_VERSION5_48a)
                SendNullPacket(KADEMLIA2_PING, uIP, uUDPPort, senderUDPKey, null);

            // Check if firewalled
            if (CKademlia::GetPrefs()->GetRecheckIP())
                FirewalledCheck(uIP, uUDPPort, senderUDPKey, byContactVersion);
        }

        // Used in Kad2.0 only
        private void Process_KADEMLIA2_REQ(byte[] pbyPacketData, uint uLenPacket, uint uIP, ushort uUDPPort, KadUDPKey senderUDPKey)
        {
            // Get target and type
            CSafeMemFile fileIO(pbyPacketData, uLenPacket);
            byte byType = fileIO.ReadUInt8();
            byType = byType & 0x1F;
            if (byType == 0)
            {
                CString strError;
                strError.Format(_T("***NOTE: Received wrong type (0x%02x) in %hs"), byType, __FUNCTION__);
                throw strError;
            }

            //This is the target node trying to be found.
            UInt128 uTarget;
            fileIO.ReadUInt128(&uTarget);
            //Convert Target to Distance as this is how we store contacts.
            UInt128 uDistance(CKademlia::GetPrefs()->GetKadID());
            uDistance.Xor(uTarget);

            //This makes sure we are not mistaken identify. Some client may have fresh installed and have a new KadID.
            UInt128 uCheck;
            fileIO.ReadUInt128(&uCheck);
            if (CKademlia::GetPrefs()->GetKadID() == uCheck)
            {
                // Get required number closest to target
                ContactMap results;
                CKademlia::GetRoutingZone()->GetClosestTo(2, uTarget, uDistance, (uint)byType, &results);
                uint8 uCount = (uint8)results.size();

                // Write response
                // Max count is 32. size 817..
                // 16 + 1 + 25(32)
                CSafeMemFile fileIO2(817);
                fileIO2.WriteUInt128(&uTarget);
                fileIO2.WriteUInt8(uCount);
                UInt128 uID;
                for (ContactMap::const_iterator itContactMap = results.begin(); itContactMap != results.end(); ++itContactMap)
                {
                    CContact* pContact = itContactMap->second;
                    pContact->GetClientID(&uID);
                    fileIO2.WriteUInt128(&uID);
                    fileIO2.WriteUInt32(pContact->GetIPAddress());
                    fileIO2.WriteUInt16(pContact->GetUDPPort());
                    fileIO2.WriteUInt16(pContact->GetTCPPort());
                    fileIO2.WriteUInt8(pContact->GetVersion()); //<- Kad Version inserted to allow backward compatability.
                }

                if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                    DebugSendF("KADEMLIA2_RES", uIP, uUDPPort, _T("Count=%u"), uCount);

                SendPacket(&fileIO2, KADEMLIA2_RES, uIP, uUDPPort, senderUDPKey, null);
            }
        }

        // Used in Kad2.0 only
        private void Process_KADEMLIA2_RES(byte[] pbyPacketData, uint uLenPacket, uint uIP, ushort uUDPPort, KadUDPKey senderUDPKey)
        {
            if (!IsOnOutTrackList(uIP, KADEMLIA2_REQ))
            {
                CString strError;
                strError.Format(_T("***NOTE: Received unrequested response packet, size (%u) in %hs"), uLenPacket, __FUNCTION__);
                throw strError;
            }

            //Used Pointers
            CRoutingZone* pRoutingZone = CKademlia::GetRoutingZone();

            // don't do firewallchecks on this opcode anymore, since we need the contacts kad version - hello opcodes are good enough
            /*if(CKademlia::GetPrefs()->GetRecheckIP())
            {	
                FirewalledCheck(uIP, uUDPPort, senderUDPKey);
                if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                    DebugSend("KADEMLIA2_HELLO_REQ", uIP, uUDPPort);
                SendMyDetails(KADEMLIA2_HELLO_REQ, uIP, uUDPPort, true, senderUDPKey, null);
            }*/

            // What search does this relate to
            CSafeMemFile fileIO(pbyPacketData, uLenPacket);
            UInt128 uTarget;
            fileIO.ReadUInt128(&uTarget);
            uint8 uNumContacts = fileIO.ReadUInt8();

            // is this one of our legacy challenge packets?
            UInt128 uContactID;
            if (IsLegacyChallenge(uTarget, uIP, KADEMLIA2_REQ, uContactID))
            {
                // yup it is, set the contact as verified
                if (!CKademlia::GetRoutingZone()->VerifyContact(uContactID, uIP))
                {
                    DebugLogWarning(_T("Kad: KADEMLIA2_RES: Unable to find valid sender in routing table (sender: %s)"), ipstr(ntohl(uIP)));
                }
                else
                    DEBUG_ONLY(AddDebugLogLine(DLP_VERYLOW, false, _T("Verified contact with legacy challenge (KADEMLIA2_REQ) - %s"), ipstr(ntohl(uIP))));
                return; // we do not actually care for its other content
            }

            // Verify packet is expected size
            if (uLenPacket != (UINT)(16 + 1 + (16 + 4 + 2 + 2 + 1) * uNumContacts))
            {
                CString strError;
                strError.Format(_T("***NOTE: Received wrong size (%u) packet in %hs"), uLenPacket, __FUNCTION__);
                throw strError;
            }

            // is this a search for firewallcheck ips?
            bool bIsFirewallUDPCheckSearch = false;
            if (CUDPFirewallTester::IsFWCheckUDPRunning() && CSearchManager::IsFWCheckUDPSearch(uTarget))
                bIsFirewallUDPCheckSearch = true;

            uint nIgnoredCount = 0;
            ContactList* pResults = new ContactList;
            UInt128 uIDResult;
            try
            {
                for (uint8 iIndex = 0; iIndex < uNumContacts; iIndex++)
                {
                    fileIO.ReadUInt128(&uIDResult);
                    uint uIPResult = fileIO.ReadUInt32();
                    ushort uUDPPortResult = fileIO.ReadUInt16();
                    ushort uTCPPortResult = fileIO.ReadUInt16();
                    uint8 uVersion = fileIO.ReadUInt8();
                    uint uhostIPResult = ntohl(uIPResult);
                    if (uVersion > 1) // Kad1 nodes are no longer accepted and ignored
                    {
                        if (::IsGoodIPPort(uhostIPResult, uUDPPortResult))
                        {
                            if (!::theApp.ipfilter->IsFiltered(uhostIPResult) && !(uUDPPortResult == 53 && uVersion <= KADEMLIA_VERSION5_48a)  /*No DNS Port without encryption*/)
                            {
                                if (bIsFirewallUDPCheckSearch)
                                {
                                    // UDP FirewallCheck searches are special. The point is we need an IP which we didn't sent an UDP message yet
                                    // (or in the near future), so we do not try to add those contacts to our routingzone and we also don't
                                    // deliver them back to the searchmanager (because he would UDP-ask them for further results), but only report
                                    // them to to FirewallChecker - this will of course cripple the search but thats not the point, since we only 
                                    // care for IPs and not the radom set target
                                    CUDPFirewallTester::AddPossibleTestContact(uIDResult, uIPResult, uUDPPortResult, uTCPPortResult, uTarget, uVersion, 0, false);
                                }
                                else
                                {
                                    bool bVerified = false;
                                    bool bWasAdded = pRoutingZone->AddUnfiltered(uIDResult, uIPResult, uUDPPortResult, uTCPPortResult, uVersion, 0, bVerified, false, false, false);
                                    CContact* pTemp = new CContact(uIDResult, uIPResult, uUDPPortResult, uTCPPortResult, uTarget, uVersion, 0, false);
                                    if (bWasAdded || pRoutingZone->IsAcceptableContact(pTemp))
                                        pResults->push_back(pTemp);
                                    else
                                    {
                                        nIgnoredCount++;
                                        delete pTemp;
                                    }
                                }
                            }
                            else if (!(uUDPPortResult == 53 && uVersion <= KADEMLIA_VERSION5_48a) && ::thePrefs.GetLogFilteredIPs())
                                AddDebugLogLine(false, _T("Ignored kad contact (IP=%s:%u) - IP filter (%s)"), ipstr(uhostIPResult), uUDPPortResult,::theApp.ipfilter->GetLastHit());
                            else if (::thePrefs.GetLogFilteredIPs())
                                AddDebugLogLine(false, _T("Ignored kad contact (IP=%s:%u) - Bad port (Kad2_Res)"), ipstr(uhostIPResult), uUDPPortResult);
                        }
                        else if (::thePrefs.GetLogFilteredIPs())
                            AddDebugLogLine(false, _T("Ignored kad contact (IP=%s) - Bad IP"), ipstr(uhostIPResult));
                    }
                }
            }
            catch (...)
	{
                for (ContactList::const_iterator it = pResults->begin(); it != pResults->end(); ++it)
                    delete* it;
                delete pResults;
                throw;
            }
            if (nIgnoredCount > 0)
                DebugLogWarning(_T("Ignored %u bad contacts in routing answer from %s"), nIgnoredCount, ipstr(ntohl(uIP)));
            SearchManager.ProcessResponse(uTarget, uIP, uUDPPort, pResults);
            }

        private static void Free(SSearchTerm pSearchTerms)
        {
            if (pSearchTerms)
            {
                if (pSearchTerms->m_pLeft)
                    Free(pSearchTerms->m_pLeft);
                if (pSearchTerms->m_pRight)
                    Free(pSearchTerms->m_pRight);
                delete pSearchTerms;
            }
        }

        static void TokenizeOptQuotedSearchTerm(string pszString, string[] lst)
        {
            LPCTSTR pch = pszString;
            while (*pch != _T('\0'))
            {
                if (*pch == _T('\"'))
                {
                    // Start of quoted string found. If there is no terminating quote character found,
                    // the start quote character is just skipped. If the quoted string is empty, no
                    // new entry is added to 'list'.
                    //
                    pch++;
                    LPCTSTR pchNextQuote = _tcschr(pch, _T('\"'));
                    if (pchNextQuote)
                    {
                        size_t nLenQuoted = pchNextQuote - pch;
                        if (nLenQuoted)
                            lst->Add(CString(pch, nLenQuoted));
                        pch = pchNextQuote + 1;
                    }
                }
                else
                {
                    // Search for next delimiter or quote character
                    //
                    size_t nNextDelimiter = _tcscspn(pch, _T(INV_KAD_KEYWORD_CHARS) _T("\""));
                    if (nNextDelimiter)
                    {
                        lst->Add(CString(pch, nNextDelimiter));
                        pch += nNextDelimiter;
                        if (*pch == _T('\0'))
                            break;
                        if (*pch == _T('\"'))
                            continue;
                    }
                    pch++;
                }
            }
        }

        static string s_pstrDbgSearchExpr;

        private SSearchTerm CreateSearchExpressionTree(CSafeMemFile fileIO, int iLevel)
        {
            // the max. depth has to match our own limit for creating the search expression
            // (see also 'ParsedSearchExpression' and 'GetSearchPacket')
            if (iLevel >= 24)
            {
                AddDebugLogLine(false, "***NOTE: Search expression tree exceeds depth limit!");
                return null;
            }
            iLevel++;

            byte uOp = fileIO.ReadUInt8();
            if (uOp == 0x00)
            {
                byte uBoolOp = fileIO.ReadUInt8();
                if (uBoolOp == 0x00) // AND
                {
                    SSearchTerm pSearchTerm = new SSearchTerm();
                    pSearchTerm->m_type = SSearchTerm::AND;
                    if (s_pstrDbgSearchExpr)
                        s_pstrDbgSearchExpr->Append(" AND");
                    if ((pSearchTerm->m_pLeft = CreateSearchExpressionTree(fileIO, iLevel)) == null)
                    {
                        Debug.Assert(false);
                        delete pSearchTerm;
                        return null;
                    }
                    if ((pSearchTerm->m_pRight = CreateSearchExpressionTree(fileIO, iLevel)) == null)
                    {
                        Debug.Assert(false);
                        Free(pSearchTerm->m_pLeft);
                        delete pSearchTerm;
                        return null;
                    }
                    return pSearchTerm;
                }
                else if (uBoolOp == 0x01) // OR
                {
                    SSearchTerm pSearchTerm = new SSearchTerm();
                    pSearchTerm->m_type = SSearchTerm::OR;
                    if (s_pstrDbgSearchExpr)
                        s_pstrDbgSearchExpr->Append(" OR");
                    if ((pSearchTerm->m_pLeft = CreateSearchExpressionTree(fileIO, iLevel)) == null)
                    {
                        Debug.Assert(false);
                        delete pSearchTerm;
                        return null;
                    }
                    if ((pSearchTerm->m_pRight = CreateSearchExpressionTree(fileIO, iLevel)) == null)
                    {
                        Debug.Assert(false);
                        Free(pSearchTerm->m_pLeft);
                        delete pSearchTerm;
                        return null;
                    }
                    return pSearchTerm;
                }
                else if (uBoolOp == 0x02) // NOT
                {
                    SSearchTerm pSearchTerm = new SSearchTerm; ()
                    pSearchTerm->m_type = SSearchTerm::NOT;
                    if (s_pstrDbgSearchExpr)
                        s_pstrDbgSearchExpr->Append(" NOT");
                    if ((pSearchTerm->m_pLeft = CreateSearchExpressionTree(fileIO, iLevel)) == null)
                    {
                        Debug.Assert(false);
                        delete pSearchTerm;
                        return null;
                    }
                    if ((pSearchTerm->m_pRight = CreateSearchExpressionTree(fileIO, iLevel)) == null)
                    {
                        Debug.Assert(false);
                        Free(pSearchTerm->m_pLeft);
                        delete pSearchTerm;
                        return null;
                    }
                    return pSearchTerm;
                }
                else
                {
                    AddDebugLogLine(false, _T("*** Unknown boolean search operator 0x%02x (CreateSearchExpressionTree)"), uBoolOp);
                    return null;
                }
            }
            else if (uOp == 0x01) // String
            {
                KadTagValueString str(fileIO.ReadStringUTF8());

                KadTagStrMakeLower(str); // make lowercase, the search code expects lower case strings!
                if (s_pstrDbgSearchExpr)
                    s_pstrDbgSearchExpr->AppendFormat(" \"%ls\"", str);

                SSearchTerm pSearchTerm = new SSearchTerm();
                pSearchTerm->m_type = SSearchTerm::String;
                pSearchTerm->m_pastr = new CStringWArray;

                // pre-tokenize the string term (care about quoted parts)
                TokenizeOptQuotedSearchTerm(str, pSearchTerm->m_pastr);

                return pSearchTerm;
            }
            else if (uOp == 0x02) // Meta tag
            {
                // read tag value
                CKadTagValueString strValue(fileIO.ReadStringUTF8());

                KadTagStrMakeLower(strValue); // make lowercase, the search code expects lower case strings!

                // read tag name
                string strTagName;
                ushort lenTagName = fileIO.ReadUInt16();
                fileIO.Read(strTagName.GetBuffer(lenTagName), lenTagName);
                strTagName.ReleaseBuffer(lenTagName);

                SSearchTerm pSearchTerm = new SSearchTerm();
                pSearchTerm.m_type = SSearchTerm::MetaTag;
                pSearchTerm.m_pTag = new Kademlia::CKadTagStr(strTagName, strValue);
                if (s_pstrDbgSearchExpr)
                {
                    if (lenTagName == 1)
                        s_pstrDbgSearchExpr->AppendFormat(" Tag%02X=\"%ls\"", (BYTE)strTagName[0], strValue);
                    else
                        s_pstrDbgSearchExpr->AppendFormat(" \"%s\"=\"%ls\"", strTagName, strValue);
                }
                return pSearchTerm;
            }
            else if (uOp == 0x03 || uOp == 0x08) // Numeric Relation (0x03=32-bit or 0x08=64-bit)
            {
                //      static const struct
                //      {
                //          SSearchTerm::ESearchTermType eSearchTermOp;
                //          LPCTSTR pszOp;
                //      }
                //      _aOps[] =
                //{
                //    { SSearchTerm::OpEqual,			"="     }, // mmop=0x00
                //    { SSearchTerm::OpGreater,		">"     }, // mmop=0x01
                //    { SSearchTerm::OpLess,			"<"     }, // mmop=0x02
                //    { SSearchTerm::OpGreaterEqual,	">="    }, // mmop=0x03
                //    { SSearchTerm::OpLessEqual,		"<="    }, // mmop=0x04
                //    { SSearchTerm::OpNotEqual,		"<>"    }  // mmop=0x05
                //}

                // read tag value
                ulong ullValue = (uOp == 0x03) ? fileIO.ReadUInt32() : fileIO.ReadUInt64();

                // read integer operator
                byte mmop = fileIO.ReadUInt8();
                if (mmop >= ARRSIZE(_aOps))
                {

                    AddDebugLogLine(false, _T("*** Unknown integer search op=0x%02x (CreateSearchExpressionTree)"), mmop);
                    return null;
                }

                // read tag name
                string strTagName;
                ushort uLenTagName = fileIO.ReadUInt16();
                fileIO.Read(strTagName.GetBuffer(uLenTagName), uLenTagName);
                strTagName.ReleaseBuffer(uLenTagName);

                SSearchTerm pSearchTerm = new SSearchTerm();
                pSearchTerm->m_type = _aOps[mmop].eSearchTermOp;
                pSearchTerm->m_pTag = new Kademlia.KadTagUInt64(strTagName, ullValue);

                if (s_pstrDbgSearchExpr)
                {
                    if (uLenTagName == 1)
                        s_pstrDbgSearchExpr->AppendFormat(_T(" Tag%02X%s%I64u"), (BYTE)strTagName[0], _aOps[mmop].pszOp, ullValue);
                    else
                        s_pstrDbgSearchExpr->AppendFormat(" \"%s\"%s%I64u", strTagName, _aOps[mmop].pszOp, ullValue);
                }

                return pSearchTerm;
            }
            else
            {

                AddDebugLogLine(false, "*** Unknown search op=0x%02x (CreateSearchExpressionTree)", uOp);
                return null;
            }
        }

        // Used in Kad2.0 only
        private void Process_KADEMLIA2_SEARCH_KEY_REQ(byte[] pbyPacketData, uint uLenPacket, uint uIP, ushort uUDPPort, KadUDPKey senderUDPKey)
        {
            CSafeMemFile fileIO(pbyPacketData, uLenPacket);
            UInt128 uTarget;
            fileIO.ReadUInt128(&uTarget);
            ushort uStartPosition = fileIO.ReadUInt16();
            bool uRestrictive = ((uStartPosition & 0x8000) == 0x8000);
            uStartPosition = uStartPosition & 0x7FFF;
            SSearchTerm* pSearchTerms = null;
            if (uRestrictive)
            {
                try
                {
#if defined(_DEBUG) || defined(USE_DEBUG_DEVICE)
			s_pstrDbgSearchExpr = (thePrefs.GetDebugServerSearchesLevel() > 0) ? new CString : null;
#endif
                    pSearchTerms = CreateSearchExpressionTree(fileIO, 0);
                    if (s_pstrDbgSearchExpr)
                    {
                        Debug(_T("KadSearchTerm=%s\n"), *s_pstrDbgSearchExpr);
                        delete s_pstrDbgSearchExpr;
                        s_pstrDbgSearchExpr = null;
                    }
                }
                catch (...)
		{
                    delete s_pstrDbgSearchExpr;
                    s_pstrDbgSearchExpr = null;
                    Free(pSearchTerms);
                    throw;
                }
                if (pSearchTerms == null)
                    throw CString(_T("Invalid search expression"));
                }
                CKademlia::GetIndexed()->SendValidKeywordResult(uTarget, pSearchTerms, uIP, uUDPPort, false, uStartPosition, senderUDPKey);
                if (pSearchTerms)
                    Free(pSearchTerms);
            }

        // Used in Kad2.0 only
        private void Process_KADEMLIA2_SEARCH_SOURCE_REQ(byte[] pbyPacketData, uint uLenPacket, uint uIP, ushort uUDPPort, KadUDPKey senderUDPKey)
        {
            CSafeMemFile fileIO(pbyPacketData, uLenPacket);
            UInt128 uTarget;
            fileIO.ReadUInt128(&uTarget);
            ushort uStartPosition = (fileIO.ReadUInt16() & 0x7FFF);
            uint64 uFileSize = fileIO.ReadUInt64();
            CKademlia::GetIndexed()->SendValidSourceResult(uTarget, uIP, uUDPPort, uStartPosition, uFileSize, senderUDPKey);
        }

        // Used in Kad1.0 only
        private void Process_KADEMLIA_SEARCH_RES(byte[] pbyPacketData, uint uLenPacket, uint uIP, ushort uUDPPort)
        {
            // Verify packet is expected size
            if (uLenPacket < 37)
            {
                CString strError;
                strError.Format(_T("***NOTE: Received wrong size (%u) packet in %hs"), uLenPacket, __FUNCTION__);
                throw strError;
            }

            // What search does this relate to
            CByteIO byteIO(pbyPacketData, uLenPacket);
            UInt128 uTarget;
            byteIO.ReadUInt128(&uTarget);

            // How many results.. Not supported yet..
            ushort uCount = byteIO.ReadUInt16();
            UInt128 uAnswer;
            while (uCount > 0)
            {
                // What is the answer
                byteIO.ReadUInt128(&uAnswer);

                // Get info about answer
                // NOTE: this is the one and only place in Kad where we allow string conversion to local code page in
                // case we did not receive an UTF8 string. this is for backward compatibility for search results which are
                // supposed to be 'viewed' by user only and not feed into the Kad engine again!
                // If that tag list is once used for something else than for viewing, special care has to be taken for any
                // string conversion!
                TagList* pTags = new TagList;
                try
                {
                    byteIO.ReadTagList(pTags, true);
                }
                catch (...)
		{
                    deleteTagListEntries(pTags);
                    delete pTags;
                    pTags = null;
                    throw;
                }
                CSearchManager::ProcessResult(uTarget, uAnswer, pTags, uIP, uUDPPort);
                uCount--;
                }
            }

        // Used in Kad2.0 only
        private void Process_KADEMLIA2_SEARCH_RES(byte[] pbyPacketData, uint uLenPacket, KadUDPKey senderUDPKey, uint uIP, ushort uUDPPort)
        {
            CByteIO byteIO(pbyPacketData, uLenPacket);

            // Who sent this packet.
            UInt128 uSource;
            byteIO.ReadUInt128(&uSource);

            // What search does this relate to
            UInt128 uTarget;
            byteIO.ReadUInt128(&uTarget);

            // Total results.
            ushort uCount = byteIO.ReadUInt16();
            UInt128 uAnswer;
            while (uCount > 0)
            {
                // What is the answer
                byteIO.ReadUInt128(&uAnswer);

                // Get info about answer
                // NOTE: this is the one and only place in Kad where we allow string conversion to local code page in
                // case we did not receive an UTF8 string. this is for backward compatibility for search results which are
                // supposed to be 'viewed' by user only and not feed into the Kad engine again!
                // If that tag list is once used for something else than for viewing, special care has to be taken for any
                // string conversion!
                TagList* pTags = new TagList;
                try
                {
                    byteIO.ReadTagList(pTags, true);
                }
                catch (...)
		{
                    deleteTagListEntries(pTags);
                    delete pTags;
                    pTags = null;
                    throw;
                }
                CSearchManager::ProcessResult(uTarget, uAnswer, pTags, uIP, uUDPPort);
                uCount--;
                }
            }

        // Used in Kad2.0 only
        private void Process_KADEMLIA2_PUBLISH_KEY_REQ(byte[] pbyPacketData, uint uLenPacket, uint uIP, ushort uUDPPort, KadUDPKey senderUDPKey)
        {
            //Used Pointers
            CIndexed* pIndexed = CKademlia::GetIndexed();

            // check if we are UDP firewalled
            if (CUDPFirewallTester::IsFirewalledUDP(true))
            {
                //We are firewalled. We should not index this entry and give publisher a false report.
                return;
            }

            CByteIO byteIO(pbyPacketData, uLenPacket);
            UInt128 uFile;
            byteIO.ReadUInt128(&uFile);

            UInt128 uDistance(CKademlia::GetPrefs()->GetKadID());
            uDistance.Xor(uFile);

            // Shouldn't LAN IPs already be filtered?
            if (uDistance.Get32BitChunk(0) > SEARCHTOLERANCE && !::IsLANIP(ntohl(uIP)))
                return;

            bool bDbgInfo = (thePrefs.GetDebugClientKadUDPLevel() > 0);
            CString sInfo;
            ushort uCount = byteIO.ReadUInt16();
            uint8 uLoad = 0;
            UInt128 uTarget;
            while (uCount > 0)
            {
                sInfo.Empty();

                byteIO.ReadUInt128(&uTarget);

                CKeyEntry* pEntry = new Kademlia::CKeyEntry();
                try
                {
                    pEntry->m_uIP = uIP;
                    pEntry->m_uUDPPort = uUDPPort;
                    pEntry->m_uKeyID.SetValue(uFile);
                    pEntry->m_uSourceID.SetValue(uTarget);
                    pEntry->m_tLifetime = (uint)time(null) + KADEMLIAREPUBLISHTIMEK;
                    pEntry->m_bSource = false;
                    uint uTags = byteIO.ReadByte();
                    while (uTags > 0)
                    {
                        CKadTag* pTag = byteIO.ReadTag();
                        if (pTag)
                        {
                            if (!pTag->m_name.Compare(TAG_FILENAME))
                            {
                                if (pEntry->GetCommonFileName().IsEmpty())
                                {
                                    pEntry->SetFileName(pTag->GetStr());
                                    if (bDbgInfo)
                                        sInfo.AppendFormat(_T("  Name=\"%ls\""), pEntry->GetCommonFileName());
                                }
                                delete pTag; // tag is no longer stored, but membervar is used
                            }
                            else if (!pTag->m_name.Compare(TAG_FILESIZE))
                            {
                                if (pEntry->m_uSize == 0)
                                {
                                    if (pTag->IsBsob() && pTag->GetBsobSize() == 8)
                                    {
                                        pEntry->m_uSize = *((uint64*)pTag->GetBsob());
                                    }
                                    else
                                        pEntry->m_uSize = pTag->GetInt();
                                    if (bDbgInfo)
                                        sInfo.AppendFormat(_T("  Size=%u"), pEntry->m_uSize);
                                }
                                delete pTag; // tag is no longer stored, but membervar is used
                            }
                            else if (!pTag->m_name.Compare(TAG_KADAICHHASHPUB))
                            {
                                if (pTag->IsBsob() && pTag->GetBsobSize() == CAICHHash::GetHashSize())
                                {
                                    if (pEntry->GetAICHHashCount() == 0)
                                    {
                                        pEntry->AddRemoveAICHHash(CAICHHash((uchar*)pTag->GetBsob()), true);
                                        if (bDbgInfo)
                                            sInfo.AppendFormat(_T("  AICH Hash=%s"), CAICHHash((uchar*)pTag->GetBsob()).GetString());
                                    }
                                    else
                                        DebugLogWarning(_T("Multiple TAG_KADAICHHASHPUB tags received for single file from %s"), ipstr(ntohl(uIP)));
                                }
                                else
                                    DEBUG_ONLY(DebugLogWarning(_T("Bad TAG_KADAICHHASHPUB received from %s"), ipstr(ntohl(uIP))));
                                delete pTag;
                            }
                            else
                            {
                                //TODO: Filter tags - we do some basic filtering already within this function, might want to do more at some point
                                pEntry->AddTag(pTag);
                            }
                        }
                        uTags--;
                    }
                    if (bDbgInfo && !sInfo.IsEmpty())
                        Debug(_T("%s\n"), sInfo);
                }
                catch (...)
		{
                    delete pEntry;
                    throw;
                }

                if (!pIndexed->AddKeyword(uFile, uTarget, pEntry, uLoad))
                {
                    //We already indexed the maximum number of keywords.
                    //We do not index anymore but we still send a success..
                    //Reason: Because if a VERY busy node tells the publisher it failed,
                    //this busy node will spread to all the surrounding nodes causing popular
                    //keywords to be stored on MANY nodes..
                    //So, once we are full, we will periodically clean our list until we can
                    //begin storing again..
                    delete pEntry;
                    pEntry = null;
                }
                uCount--;
                }
                CSafeMemFile fileIO2(17);
                fileIO2.WriteUInt128(&uFile);
                fileIO2.WriteUInt8(uLoad);
                if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                    DebugSend("KADEMLIA2_PUBLISH_RES", uIP, uUDPPort);
                SendPacket(&fileIO2, KADEMLIA2_PUBLISH_RES, uIP, uUDPPort, senderUDPKey, null);
            }

        // Used in Kad2.0 only
        private void Process_KADEMLIA2_PUBLISH_SOURCE_REQ(byte[] pbyPacketData, uint uLenPacket, uint uIP, ushort uUDPPort, KadUDPKey senderUDPKey)
        {
            //Used Pointers
            CIndexed* pIndexed = CKademlia::GetIndexed();

            // check if we are UDP firewalled
            if (CUDPFirewallTester::IsFirewalledUDP(true))
            {
                //We are firewalled. We should not index this entry and give publisher a false report.
                return;
            }

            CByteIO byteIO(pbyPacketData, uLenPacket);
            UInt128 uFile;
            byteIO.ReadUInt128(&uFile);

            UInt128 uDistance(CKademlia::GetPrefs()->GetKadID());
            uDistance.Xor(uFile);

            if (uDistance.Get32BitChunk(0) > SEARCHTOLERANCE && !::IsLANIP(ntohl(uIP)))
                return;

            bool bDbgInfo = (thePrefs.GetDebugClientKadUDPLevel() > 0);
            CString sInfo;
            sInfo.Empty();
            uint8 uLoad = 0;
            bool bFlag = false;
            UInt128 uTarget;
            byteIO.ReadUInt128(&uTarget);
            CEntry* pEntry = new Kademlia::CEntry();
            try
            {
                pEntry->m_uIP = uIP;
                pEntry->m_uUDPPort = uUDPPort;
                pEntry->m_uKeyID.SetValue(uFile);
                pEntry->m_uSourceID.SetValue(uTarget);
                pEntry->m_bSource = false;
                pEntry->m_tLifetime = (uint)time(null) + KADEMLIAREPUBLISHTIMES;
                bool bAddUDPPortTag = true;
                uint uTags = byteIO.ReadByte();
                while (uTags > 0)
                {
                    CKadTag* pTag = byteIO.ReadTag();
                    if (pTag)
                    {
                        if (!pTag->m_name.Compare(TAG_SOURCETYPE))
                        {
                            if (pEntry->m_bSource == false)
                            {
                                pEntry->AddTag(new CKadTagUInt(TAG_SOURCEIP, pEntry->m_uIP));
                                pEntry->AddTag(pTag);
                                pEntry->m_bSource = true;
                            }
                            else
                            {
                                //More then one sourcetype tag found.
                                delete pTag;
                            }
                        }
                        else if (!pTag->m_name.Compare(TAG_FILESIZE))
                        {
                            if (pEntry->m_uSize == 0)
                            {
                                if (pTag->IsBsob() && pTag->GetBsobSize() == 8)
                                {
                                    pEntry->m_uSize = *((uint64*)pTag->GetBsob());
                                }
                                else
                                    pEntry->m_uSize = pTag->GetInt();
                                if (bDbgInfo)
                                    sInfo.AppendFormat(_T("  Size=%u"), pEntry->m_uSize);
                            }
                            delete pTag;
                        }
                        else if (!pTag->m_name.Compare(TAG_SOURCEPORT))
                        {
                            if (pEntry->m_uTCPPort == 0)
                            {
                                pEntry->m_uTCPPort = (ushort)pTag->GetInt();
                                pEntry->AddTag(pTag);
                            }
                            else
                            {
                                //More then one port tag found
                                delete pTag;
                            }
                        }
                        else if (!pTag->m_name.Compare(TAG_SOURCEUPORT))
                        {
                            if (bAddUDPPortTag && pTag->IsInt() && pTag->GetInt() != 0)
                            {
                                pEntry->m_uUDPPort = (ushort)pTag->GetInt();
                                pEntry->AddTag(pTag);
                                bAddUDPPortTag = false;
                            }
                            else
                            {
                                //More then one udp port tag found
                                delete pTag;
                            }
                        }
                        else
                        {
                            //TODO: Filter tags
                            pEntry->AddTag(pTag);
                        }
                    }
                    uTags--;
                }
                if (bAddUDPPortTag)
                    pEntry->AddTag(new CKadTagUInt(TAG_SOURCEUPORT, pEntry->m_uUDPPort));

                if (bDbgInfo && !sInfo.IsEmpty())
                    Debug(_T("%s\n"), sInfo);
            }
            catch (...)
	{
                delete pEntry;
                throw;
            }

            if (pEntry->m_bSource == true)
            {
                if (pIndexed->AddSources(uFile, uTarget, pEntry, uLoad))
                    bFlag = true;
                else
                {
                    delete pEntry;
                    pEntry = null;
                }
            }
            else
            {
                delete pEntry;
                pEntry = null;
            }
            if (bFlag)
            {
                CSafeMemFile fileIO2(17);
                fileIO2.WriteUInt128(&uFile);
                fileIO2.WriteUInt8(uLoad);
                if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                    DebugSend("KADEMLIA2_PUBLISH_RES", uIP, uUDPPort);
                SendPacket(&fileIO2, KADEMLIA2_PUBLISH_RES, uIP, uUDPPort, senderUDPKey, null);
            }
            }

        // Used only by Kad1.0
        private void Process_KADEMLIA_PUBLISH_RES(byte[] pbyPacketData, uint uLenPacket, uint uIP)
        {
            // Verify packet is expected size
            if (uLenPacket < 16)
            {
                CString strError;
                strError.Format(_T("***NOTE: Received wrong size (%u) packet in %hs"), uLenPacket, __FUNCTION__);
                throw strError;
            }
            else if (!IsOnOutTrackList(uIP, KADEMLIA_PUBLISH_REQ))
            {
                CString strError;
                strError.Format(_T("***NOTE: Received unrequested response packet, size (%u) in %hs"), uLenPacket, __FUNCTION__);
                throw strError;
            }

            CSafeMemFile fileIO(pbyPacketData, uLenPacket);
            UInt128 uFile;
            fileIO.ReadUInt128(&uFile);

            bool bLoadResponse = false;
            uint8 uLoad = 0;
            if (fileIO.GetLength() > fileIO.GetPosition())
            {
                bLoadResponse = true;
                uLoad = fileIO.ReadUInt8();
            }

            SearchManager.ProcessPublishResult(uFile, uLoad, bLoadResponse);
        }

        // Used only by Kad2.0
        private void Process_KADEMLIA2_PUBLISH_RES(byte[] pbyPacketData, uint uLenPacket, uint uIP, ushort uUDPPort, KadUDPKey senderUDPKey)
        {
            if (!IsOnOutTrackList(uIP, KADEMLIA2_PUBLISH_KEY_REQ) && !IsOnOutTrackList(uIP, KADEMLIA2_PUBLISH_SOURCE_REQ) && !IsOnOutTrackList(uIP, KADEMLIA2_PUBLISH_NOTES_REQ))
            {
                CString strError;
                strError.Format(_T("***NOTE: Received unrequested response packet, size (%u) in %hs"), uLenPacket, __FUNCTION__);
                throw strError;
            }
            CSafeMemFile fileIO(pbyPacketData, uLenPacket);
            UInt128 uFile;
            fileIO.ReadUInt128(&uFile);
            uint8 uLoad = fileIO.ReadUInt8();
            CSearchManager::ProcessPublishResult(uFile, uLoad, true);
            if (fileIO.GetLength() > fileIO.GetPosition())
            {
                // for future use
                uint8 byOptions = fileIO.ReadUInt8();
                bool bRequestACK = (byOptions & 0x01) > 0;
                if (bRequestACK && !senderUDPKey.IsEmpty())
                {
                    DEBUG_ONLY(DebugLogWarning(_T("KADEMLIA2_PUBLISH_RES_ACK requested (%s)"), ipstr(ntohl(uIP))));
                    if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                        DebugSend("KADEMLIA2_PUBLISH_RES_ACK", uIP, uUDPPort);
                    SendNullPacket(KADEMLIA2_PUBLISH_RES_ACK, uIP, uUDPPort, senderUDPKey, null);
                }
            }
        }

        // Used only by Kad2.0
        private void Process_KADEMLIA2_SEARCH_NOTES_REQ(byte[] pbyPacketData, uint uLenPacket, uint uIP, ushort uUDPPort, KadUDPKey senderUDPKey)
        {
            CSafeMemFile fileIO(pbyPacketData, uLenPacket);
            UInt128 uTarget;
            fileIO.ReadUInt128(&uTarget);
            uint64 uFileSize = fileIO.ReadUInt64();
            CKademlia::GetIndexed()->SendValidNoteResult(uTarget, uIP, uUDPPort, uFileSize, senderUDPKey);
        }

        // Used only by Kad1.0
        private void Process_KADEMLIA_SEARCH_NOTES_RES(byte[] pbyPacketData, uint uLenPacket, uint uIP, ushort uUDPPort)
        {
            // Verify packet is expected size
            if (uLenPacket < 37)
            {
                CString strError;
                strError.Format(_T("***NOTE: Received wrong size (%u) packet in %hs"), uLenPacket, __FUNCTION__);
                throw strError;
            }
            else if (!IsOnOutTrackList(uIP, KADEMLIA_SEARCH_NOTES_REQ, true))
            {
                CString strError;
                strError.Format(_T("***NOTE: Received unrequested response packet, size (%u) in %hs"), uLenPacket, __FUNCTION__);
                throw strError;
            }

            // What search does this relate to
            CByteIO byteIO(pbyPacketData, uLenPacket);
            UInt128 uTarget;
            byteIO.ReadUInt128(&uTarget);

            ushort uCount = byteIO.ReadUInt16();
            UInt128 uAnswer;
            while (uCount > 0)
            {
                // What is the answer
                byteIO.ReadUInt128(&uAnswer);

                // Get info about answer
                // NOTE: this is the one and only place in Kad where we allow string conversion to local code page in
                // case we did not receive an UTF8 string. this is for backward compatibility for search results which are
                // supposed to be 'viewed' by user only and not feed into the Kad engine again!
                // If that tag list is once used for something else than for viewing, special care has to be taken for any
                // string conversion!
                TagList* pTags = new TagList;
                try
                {
                    byteIO.ReadTagList(pTags, true);
                }
                catch (...)
		{
                    deleteTagListEntries(pTags);
                    delete pTags;
                    pTags = null;
                    throw;
                }
                CSearchManager::ProcessResult(uTarget, uAnswer, pTags, uIP, uUDPPort);
                uCount--;
                }
            }

        // Used only by Kad2.0
        private void Process_KADEMLIA2_PUBLISH_NOTES_REQ(byte[] pbyPacketData, uint uLenPacket, uint uIP, ushort uUDPPort, KadUDPKey senderUDPKey)
        {
            // check if we are UDP firewalled
            if (CUDPFirewallTester::IsFirewalledUDP(true))
            {
                //We are firewalled. We should not index this entry and give publisher a false report.
                return;
            }

            CByteIO byteIO(pbyPacketData, uLenPacket);
            UInt128 uTarget;
            byteIO.ReadUInt128(&uTarget);

            UInt128 uDistance(CKademlia::GetPrefs()->GetKadID());
            uDistance.Xor(uTarget);

            // Shouldn't LAN IPs already be filtered?
            if (uDistance.Get32BitChunk(0) > SEARCHTOLERANCE && !::IsLANIP(ntohl(uIP)))
                return;

            UInt128 uSource;
            byteIO.ReadUInt128(&uSource);

            Kademlia::CEntry* pEntry = new Kademlia::CEntry();
            try
            {
                pEntry->m_uIP = uIP;
                pEntry->m_uUDPPort = uUDPPort;
                pEntry->m_uKeyID.SetValue(uTarget);
                pEntry->m_uSourceID.SetValue(uSource);
                pEntry->m_bSource = false;
                uint uTags = byteIO.ReadByte();
                while (uTags > 0)
                {
                    CKadTag* pTag = byteIO.ReadTag();
                    if (pTag)
                    {
                        if (!pTag->m_name.Compare(TAG_FILENAME))
                        {
                            if (pEntry->GetCommonFileName().IsEmpty())
                            {
                                pEntry->SetFileName(pTag->GetStr());
                            }
                            delete pTag;
                        }
                        else if (!pTag->m_name.Compare(TAG_FILESIZE))
                        {
                            if (pEntry->m_uSize == 0)
                            {
                                pEntry->m_uSize = pTag->GetInt();
                            }
                            delete pTag;
                        }
                        else
                        {
                            //TODO: Filter tags
                            pEntry->AddTag(pTag);
                        }
                    }
                    uTags--;
                }
            }
            catch (...)
	{
                delete pEntry;
                pEntry = null;
                throw;
            }

            uint8 uLoad = 0;
            if (CKademlia::GetIndexed()->AddNotes(uTarget, uSource, pEntry, uLoad))
            {
                CSafeMemFile fileIO2(17);
                fileIO2.WriteUInt128(&uTarget);
                fileIO2.WriteUInt8(uLoad);
                if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                    DebugSend("KADEMLIA2_PUBLISH_RES", uIP, uUDPPort);

                SendPacket(&fileIO2, KADEMLIA2_PUBLISH_RES, uIP, uUDPPort, senderUDPKey, null);
            }
            else
                delete pEntry;
            }

        // Used by Kad1.0 and Kad2.0
        private void Process_KADEMLIA_FIREWALLED_REQ(byte[] pbyPacketData, uint uLenPacket, uint uIP, ushort uUDPPort, KadUDPKey senderUDPKey)
        {
            // Verify packet is expected size
            if (uLenPacket != 2)
            {
                CString strError;
                strError.Format(_T("***NOTE: Received wrong size (%u) packet in %hs"), uLenPacket, __FUNCTION__);
                throw strError;
            }

            CSafeMemFile fileIO(pbyPacketData, uLenPacket);
            ushort uTCPPort = fileIO.ReadUInt16();

            CContact contact;
            contact.SetIPAddress(uIP);
            contact.SetTCPPort(uTCPPort);
            contact.SetUDPPort(uUDPPort);
            if (!theApp.clientlist->RequestTCP(&contact, 0))
                return; // cancelled for some reason, don't send a response

            // Send response
            CSafeMemFile fileIO2(4);
            fileIO2.WriteUInt32(uIP);
            if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                DebugSend("KADEMLIA_FIREWALLED_RES", uIP, uUDPPort);

            SendPacket(&fileIO2, KADEMLIA_FIREWALLED_RES, uIP, uUDPPort, senderUDPKey, null);
        }

        // Used by Kad2.0 Prot.Version 7+
        private void Process_KADEMLIA_FIREWALLED2_REQ(byte[] pbyPacketData, uint uLenPacket, uint uIP, ushort uUDPPort, KadUDPKey senderUDPKey)
        {
            // Verify packet is expected size
            if (uLenPacket < 19)
            {
                CString strError;
                strError.Format(_T("***NOTE: Received wrong size (%u) packet in %hs"), uLenPacket, __FUNCTION__);
                throw strError;
            }

            CSafeMemFile fileIO(pbyPacketData, uLenPacket);
            ushort uTCPPort = fileIO.ReadUInt16();
            UInt128 userID;
            fileIO.ReadUInt128(&userID);
            uint8 byConnectOptions = fileIO.ReadUInt8();

            CContact contact;
            contact.SetIPAddress(uIP);
            contact.SetTCPPort(uTCPPort);
            contact.SetUDPPort(uUDPPort);
            contact.SetClientID(userID);
            if (!theApp.clientlist->RequestTCP(&contact, byConnectOptions))
                return;  // cancelled for some reason, don't send a response

            // Send response
            CSafeMemFile fileIO2(4);
            fileIO2.WriteUInt32(uIP);
            if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                DebugSend("KADEMLIA_FIREWALLED_RES", uIP, uUDPPort);

            SendPacket(&fileIO2, KADEMLIA_FIREWALLED_RES, uIP, uUDPPort, senderUDPKey, null);
        }

        // Used by Kad1.0 and Kad2.0
        private void Process_KADEMLIA_FIREWALLED_RES(byte[] pbyPacketData, uint uLenPacket, uint uIP, KadUDPKey senderUDPKey)
        {
            // Verify packet is expected size
            if (uLenPacket != 4)
            {
                CString strError;
                strError.Format(_T("***NOTE: Received wrong size (%u) packet in %hs"), uLenPacket, __FUNCTION__);
                throw strError;
            }
            else if (!theApp.clientlist->IsKadFirewallCheckIP(ntohl(uIP)))
            { /*KADEMLIA_FIREWALLED2_REQ + KADEMLIA_FIREWALLED_REQ*/
                CString strError;
                strError.Format(_T("Received unrequested firewall response packet in %hs"), __FUNCTION__);
                throw strError;
            }

            CSafeMemFile fileIO(pbyPacketData, uLenPacket);
            uint uFirewalledIP = fileIO.ReadUInt32();

            //Update con state only if something changes.
            if (CKademlia::GetPrefs()->GetIPAddress() != uFirewalledIP)
            {
                CKademlia::GetPrefs()->SetIPAddress(uFirewalledIP);
                theApp.emuledlg->ShowConnectionState();
            }
            CKademlia::GetPrefs()->IncRecheckIP();
        }

        // Used by Kad1.0 and Kad2.0
        private void Process_KADEMLIA_FIREWALLED_ACK_RES(uint uLenPacket)
        {
            // deprecated since KadVersion 7+, the result is now sent per TCP instead of UDP, because this will fail if our intern UDP port is unreachable.
            // But we want the TCP testresult reagrdless if UDP is firewalled, the new UDP state and test takes care of the rest
            // Verify packet is expected size
            if (uLenPacket != 0)
            {
                CString strError;
                strError.Format(_T("***NOTE: Received wrong size (%u) packet in %hs"), uLenPacket, __FUNCTION__);
                throw strError;
            }

            CKademlia::GetPrefs()->IncFirewalled();
        }

        // Used by Kad1.0 and Kad2.0
        private void Process_KADEMLIA_FINDBUDDY_REQ(byte[] pbyPacketData, uint uLenPacket, uint uIP, ushort uUDPPort, KadUDPKey senderUDPKey)
        {
            // Verify packet is expected size
            if (uLenPacket < 34)
            {
                CString strError;
                strError.Format(_T("***NOTE: Received wrong size (%u) packet in %hs"), uLenPacket, __FUNCTION__);
                throw strError;
            }

            if (CKademlia::GetPrefs()->GetFirewalled() || CUDPFirewallTester::IsFirewalledUDP(true) || !CUDPFirewallTester::IsVerified())
                //We are firewalled but somehow we still got this packet.. Don't send a response..
                return;
            else if (theApp.clientlist->GetBuddyStatus() == Connected)
                // we aready have a buddy
                return;

            CSafeMemFile fileIO(pbyPacketData, uLenPacket);
            UInt128 BuddyID;
            fileIO.ReadUInt128(&BuddyID);
            UInt128 userID;
            fileIO.ReadUInt128(&userID);
            ushort uTCPPort = fileIO.ReadUInt16();

            CContact contact;
            contact.SetIPAddress(uIP);
            contact.SetTCPPort(uTCPPort);
            contact.SetUDPPort(uUDPPort);
            contact.SetClientID(userID);
            if (!theApp.clientlist->IncomingBuddy(&contact, &BuddyID))
                return; // cancelled for some reason, don't send a response

            CSafeMemFile fileIO2(34);
            fileIO2.WriteUInt128(&BuddyID);
            fileIO2.WriteUInt128(&CKademlia::GetPrefs()->GetClientHash());
            fileIO2.WriteUInt16(thePrefs.GetPort());
            if (!senderUDPKey.IsEmpty()) // remove check for later versions
                fileIO2.WriteUInt8(CKademlia::GetPrefs()->GetMyConnectOptions(true, false)); // new since 0.49a, old mules will ignore it (hopefully ;) )
            if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                DebugSend("KADEMLIA_FINDBUDDY_RES", uIP, uUDPPort);

            SendPacket(&fileIO2, KADEMLIA_FINDBUDDY_RES, uIP, uUDPPort, senderUDPKey, null);
        }

        // Used by Kad1.0 and Kad2.0
        private void Process_KADEMLIA_FINDBUDDY_RES(byte[] pbyPacketData, uint uLenPacket, uint uIP, ushort uUDPPort, KadUDPKey senderUDPKey)
        {
            // Verify packet is expected size
            if (uLenPacket < 34)
            {
                CString strError;
                strError.Format(_T("***NOTE: Received wrong size (%u) packet in %hs"), uLenPacket, __FUNCTION__);
                throw strError;
            }
            else if (!IsOnOutTrackList(uIP, KADEMLIA_FINDBUDDY_REQ))
            {
                CString strError;
                strError.Format(_T("***NOTE: Received unrequested response packet, size (%u) in %hs"), uLenPacket, __FUNCTION__);
                throw strError;
            }


            CSafeMemFile fileIO(pbyPacketData, uLenPacket);
            UInt128 uCheck;
            fileIO.ReadUInt128(&uCheck);
            uCheck.Xor(UInt128(true));
            if (CKademlia::GetPrefs()->GetKadID() == uCheck)
            {
                UInt128 userID;
                fileIO.ReadUInt128(&userID);
                ushort uTCPPort = fileIO.ReadUInt16();
                uint8 byConnectOptions = 0;
                if (uLenPacket > 34)
                {
                    // 0.49+ (kad version 7) sends addtional its connect options so we know if to use an obfuscated connection
                    byConnectOptions = fileIO.ReadUInt8();
                }
                CContact contact;
                contact.SetIPAddress(uIP);
                contact.SetTCPPort(uTCPPort);
                contact.SetUDPPort(uUDPPort);
                contact.SetClientID(userID);

                theApp.clientlist->RequestBuddy(&contact, byConnectOptions);
            }
        }

        // Used by Kad1.0 and Kad2.0
        private void Process_KADEMLIA_CALLBACK_REQ(byte[] pbyPacketData, uint uLenPacket, uint uIP, KadUDPKey senderUDPKey)
        {
            // Verify packet is expected size
            if (uLenPacket < 34)
            {
                CString strError;
                strError.Format(_T("***NOTE: Received wrong size (%u) packet in %hs"), uLenPacket, __FUNCTION__);
                throw strError;
            }

            CUpDownClient* pBuddy = theApp.clientlist->GetBuddy();
            if (pBuddy != null)
            {
                CSafeMemFile fileIO(pbyPacketData, uLenPacket);
                UInt128 uCheck;
                fileIO.ReadUInt128(&uCheck);
                //JOHNTODO: Begin filtering bad buddy ID's..
                //UInt128 bud(buddy->GetBuddyID());
                UInt128 uFile;
                fileIO.ReadUInt128(&uFile);
                ushort uTCP = fileIO.ReadUInt16();

                if (pBuddy->socket == null)
                    throw CString(__FUNCTION__ ": Buddy has no valid socket.");
                CSafeMemFile fileIO2(uLenPacket + 6);
                fileIO2.WriteUInt128(&uCheck);
                fileIO2.WriteUInt128(&uFile);
                fileIO2.WriteUInt32(uIP);
                fileIO2.WriteUInt16(uTCP);
                Packet* pPacket = new Packet(&fileIO2, OP_EMULEPROT, OP_CALLBACK);
                if (thePrefs.GetDebugClientKadUDPLevel() > 0 || thePrefs.GetDebugClientTCPLevel() > 0)
                    DebugSend("OP_CALLBACK", pBuddy);
                theStats.AddUpDataOverheadFileRequest(pPacket->size);
                pBuddy->socket->SendPacket(pPacket);
            }
        }

        private void Process_KADEMLIA2_PING(uint uIP, ushort uUDPPort, KadUDPKey senderUDPKey)
        {
            // can be used just as PING, currently it is however only used to determine ones external port
            CSafeMemFile fileIO2(2);
            fileIO2.WriteUInt16(uUDPPort);
            if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                DebugSend("KADEMLIA2_PONG", uIP, uUDPPort);
            SendPacket(&fileIO2, KADEMLIA2_PONG, uIP, uUDPPort, senderUDPKey, null);
        }

        private void Process_KADEMLIA2_PONG(byte[] pbyPacketData, uint uLenPacket, uint uIP, ushort uUDPPort, KadUDPKey senderUDPKey)
        {
            if (uLenPacket < 2)
            {
                CString strError;
                strError.Format(_T("***NOTE: Received wrong size (%u) packet in %hs"), uLenPacket, __FUNCTION__);
                throw strError;
            }
            else if (!IsOnOutTrackList(uIP, KADEMLIA2_PING))
            {
                CString strError;
                strError.Format(_T("***NOTE: Received unrequested response packet, size (%u) in %hs"), uLenPacket, __FUNCTION__);
                throw strError;
            }

            // is this one of our legacy challenge packets?
            UInt128 uContactID;
            if (IsLegacyChallenge((ULONG)0, uIP, KADEMLIA2_PING, uContactID))
            {
                // yup it is, set the contact as verified
                if (!CKademlia::GetRoutingZone()->VerifyContact(uContactID, uIP))
                {
                    DebugLogWarning(_T("Kad: KADEMLIA2_PONG: Unable to find valid sender in routing table (sender: %s)"), ipstr(ntohl(uIP)));
                }
                else
                    DEBUG_ONLY(AddDebugLogLine(DLP_LOW, false, _T("Verified contact with legacy challenge (KADEMLIA2_PING) - %s"), ipstr(ntohl(uIP))));
                // we might care for its other content
            }

            if (CKademlia::GetPrefs()->FindExternKadPort(false))
            {
                // the reported port doesn't always has to be our true external port, esp. if we used our intern port
                // and communicated recently with the client some routers might remember this and assign the intern port as source
                // but this shouldn't be a problem because we prefer intern ports anyway.
                // might have to be reviewed in later versions when more data is available
                CKademlia::GetPrefs()->SetExternKadPort(PeekUInt16(pbyPacketData), uIP);
                if (CUDPFirewallTester::IsFWCheckUDPRunning())
                    CUDPFirewallTester::QueryNextClient();
            }
            theApp.emuledlg->ShowConnectionState();
        }

        private void Process_KADEMLIA2_FIREWALLUDP(byte[] pbyPacketData, uint uLenPacket, uint uIP, KadUDPKey senderUDPKey)
        {
            // Verify packet is expected size
            if (uLenPacket < 3)
            {
                CString strError;
                strError.Format(_T("***NOTE: Received wrong size (%u) packet in %hs"), uLenPacket, __FUNCTION__);
                throw strError;
            }
            uint8 byErrorCode = PeekUInt8(pbyPacketData);
            ushort nIncomingPort = PeekUInt16(pbyPacketData + 1);

            if ((nIncomingPort != CKademlia::GetPrefs()->GetExternalKadPort() && nIncomingPort != CKademlia::GetPrefs()->GetInternKadPort())
                || nIncomingPort == 0)
            {
                DebugLogWarning(_T("Received UDP FirewallCheck on unexpected incoming port %u (%s)"), nIncomingPort, ipstr(ntohl(uIP)));
                CUDPFirewallTester::SetUDPFWCheckResult(false, true, uIP, 0);
            }
            else if (byErrorCode == 0)
            {
                DebugLog(_T("Received UDP FirewallCheck packet from %s with incoming port %u"), ipstr(ntohl(uIP)), nIncomingPort);
                CUDPFirewallTester::SetUDPFWCheckResult(true, false, uIP, nIncomingPort);
            }
            else
            {
                DebugLog(_T("Received UDP FirewallCheck packet from %s with incoming port %u with remote errorcode %u - ignoring result"), ipstr(ntohl(uIP)), nIncomingPort, byErrorCode);
                CUDPFirewallTester::SetUDPFWCheckResult(false, true, uIP, 0);
            }
        }

        public void SendPacket(byte[] pbyData, uint uLenData, uint uDestinationHost, ushort uDestinationPort, KadUDPKey targetUDPKey, UInt128 uCryptTargetID)
        {
            if (uLenData < 2)
            {
                Debug.Assert(false);
                return;
            }
            AddTrackedOutPacket(uDestinationHost, pbyData[1]);
            Packet pPacket = new Packet(Opcodes.OP_KADEMLIAHEADER);
            pPacket.opcode = pbyData[1];
            pPacket.pBuffer = new byte[uLenData + 8];
            memcpy(pPacket.pBuffer, pbyData + 2, uLenData - 2);
            pPacket.size = uLenData - 2;
            if (uLenData > 200)
                pPacket.PackPacket();
            theStats.AddUpDataOverheadKad(pPacket.size);
            theApp.clientudp.SendPacket(pPacket, IPAddress.NetworkToHostOrder(uDestinationHost), uDestinationPort, true
                , (uCryptTargetID != null) ? uCryptTargetID.GetData() : null
                , true, targetUDPKey.GetKeyValue(theApp.GetPublicIP(false)));
        }

        public void SendPacket(byte[] pbyData, uint uLenData, byte byOpcode, uint uDestinationHost, ushort uDestinationPort, KadUDPKey targetUDPKey, UInt128 uCryptTargetID)
        {
            AddTrackedOutPacket(uDestinationHost, byOpcode);
            Packet pPacket = new Packet(Opcodes.OP_KADEMLIAHEADER);
            pPacket.opcode = byOpcode;
            pPacket.pBuffer = new byte[uLenData];
            memcpy(pPacket.pBuffer, pbyData, uLenData);
            pPacket.size = uLenData;
            if (uLenData > 200)
                pPacket.PackPacket();
            theStats.AddUpDataOverheadKad(pPacket.size);
            theApp.clientudp->SendPacket(pPacket, IPAddress.NetworkToHostOrder(uDestinationHost), uDestinationPort, true
                , (uCryptTargetID != null) ? uCryptTargetID.GetData() : null
                , true, targetUDPKey.GetKeyValue(theApp.GetPublicIP(false)));
        }

        public void SendPacket(SafeMemFile pbyData, byte byOpcode, uint uDestinationHost, ushort uDestinationPort, KadUDPKey targetUDPKey, UInt128 uCryptTargetID)
        {
            AddTrackedOutPacket(uDestinationHost, byOpcode);
            Packet pPacket = new Packet(pbyData, Opcodes.OP_KADEMLIAHEADER);
            pPacket.opcode = byOpcode;
            if (pPacket.size > 200)
                pPacket.PackPacket();
            theStats.AddUpDataOverheadKad(pPacket.size);
            theApp.clientudp->SendPacket(pPacket, IPAddress.NetworkToHostOrder(uDestinationHost), uDestinationPort, true
                , (uCryptTargetID != null) ? uCryptTargetID.GetData() : null
                , true, targetUDPKey.GetKeyValue(theApp.GetPublicIP(false)));
        }

        public bool FindNodeIDByIP(KadClientSearcher pRequester, uint dwIP, ushort nTCPPort, ushort nUDPPort)
        {
            // send a hello packet to the given IP in order to get a HELLO_RES with the NodeID

            // we will drop support for Kad1 soon, so dont bother sending two packets in case we don't know if kad2 is supported
            // (if we know that its not, this function isn't called in the first place)
            DebugLog(_T("FindNodeIDByIP: Requesting NodeID from %s by sending KADEMLIA2_HELLO_REQ"), ipstr(ntohl(dwIP)));
            if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                DebugSend("KADEMLIA2_HELLO_REQ", dwIP, nUDPPort);
            SendMyDetails(KADEMLIA2_HELLO_REQ, dwIP, nUDPPort, 1, 0, null, false); // todo: we send this unobfuscated, which is not perfect, see this can be avoided in the future
            FetchNodeID_Struct sRequest = { dwIP, nTCPPort, ::GetTickCount() + SEC2MS(60), pRequester };
            listFetchNodeIDRequests.AddTail(sRequest);
            return true;
        }

        public void ExpireClientSearch(KadClientSearcher pExpireImmediately)
        {
            POSITION pos1, pos2;
            for (pos1 = listFetchNodeIDRequests.GetHeadPosition(); (pos2 = pos1) != null;)
            {
                listFetchNodeIDRequests.GetNext(pos1);
                FetchNodeID_Struct sRequest = listFetchNodeIDRequests.GetAt(pos2);
                if (sRequest.pRequester == pExpireImmediately)
                {
                    listFetchNodeIDRequests.RemoveAt(pos2);
                }
                else if (sRequest.dwExpire < ::GetTickCount())
                {
                    sRequest.pRequester->KadSearchNodeIDByIPResult(KCSR_TIMEOUT, null);
                    listFetchNodeIDRequests.RemoveAt(pos2);
                }
            }
        }

        private void SendLegacyChallenge(uint uIP, ushort uUDPPort, UInt128 uContactID)
        {
            // We want to verify that a pre-0.49a contact is valid and not sent from a spoofed IP.
            // Because those versions don'T support any direct validating, we sent a KAD_REQ with a random ID,
            // which is our challenge. If we receive an answer packet for this request, we can be sure the
            // contact is not spoofed
#if DEBUG
            Contact pContact = Kademlia.GetRoutingZone().GetContact(uContactID);
            if (pContact != null)
            {
                if (pContact->GetType() < 2)
                    DebugLogWarning(_T("Process_KADEMLIA_HELLO_RES: Sending challenge to a long known contact (should be verified already) - %s"), ipstr(ntohl(uIP)));
            }
            else
                Debug.Assert(false);
#endif
            if (HasActiveLegacyChallenge(uIP)) // don't sent more than one challange at a time
                return;
            CSafeMemFile fileIO(33);
            fileIO.WriteUInt8(KADEMLIA_FIND_VALUE);
            UInt128 uChallenge;
            uChallenge.SetValueRandom();
            if (uChallenge == 0)
            {
                // hey there is a 2^128 chance that this happens ;)
                Debug.Assert(false);
                uChallenge = 1;
            }
            // Put the target we want into the packet. This is our challenge
            fileIO.WriteUInt128(&uChallenge);
            // Add the ID of the contact we are contacting for sanity checks on the other end.
            fileIO.WriteUInt128(&uContactID);
            // those versions we send those requests to don't support encryption / obfuscation
            Kademlia.GetUDPListener().SendPacket(&fileIO, KADEMLIA2_REQ, uIP, uUDPPort, 0, null);
            if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                DebugSend("KADEMLIA2_REQ(SendLegacyChallenge)", uIP, uUDPPort);
            AddLegacyChallenge(uContactID, uChallenge, uIP, KADEMLIA2_REQ);
        }
    }
}
