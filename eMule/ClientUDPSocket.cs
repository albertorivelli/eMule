using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Windows.Networking.Sockets;

namespace eMule
{
    [StructLayout(LayoutKind.Sequential, Pack = 0)]
    public struct UDPPack
    {
        //public Packet packet;
        public uint dwIP;
        public ushort nPort;
        public uint dwTime;
        public bool bEncrypt;
        public bool bKad;
        public uint nReceiverVerifyKey;
        //public byte[16] pachTargetClientHashORKadID;
        //uint16 nPriority; We could add a priority system here to force some packets.
    }

    public class ClientUDPSocket
    {
//        private ushort m_port;
//        private Queue<UDPPack> controlpacket_queue;
//        private CriticalSection sendLocker; // ZZ:UploadBandWithThrottler (UDP)
//        private bool m_bWouldBlock;
//        private bool IsBusy() { return m_bWouldBlock; }
//        public ushort GetConnectedPort() { return m_port; }

//        public ClientUDPSocket()
//        {
//            m_bWouldBlock = false;
//            m_port = 0;
//        }

//        ~ClientUDPSocket()
//        {
//            //theApp.uploadBandwidthThrottler->RemoveFromAllQueues(this); // ZZ:UploadBandWithThrottler (UDP)

//            //controlpacket_queue.Clear();

//            //controlpacket_queue = null;
//        }

//        protected void OnReceive(DatagramSocket sender, DatagramSocketMessageReceivedEventArgs args)
//        {
//            //Read the message that was received from the UDP echo client.
//            Stream streamIn = args.GetDataStream().AsStreamForRead();
//            StreamReader reader = new StreamReader(streamIn);
//            string message = await reader.ReadLineAsync();

//            if (nErrorCode)
//            {
//                if (thePrefs.GetVerbose())
//                    DebugLogError("Error: Client UDP socket, error on receive event: %s", GetErrorMessage(nErrorCode, 1));
//            }

//            BYTE buffer[5000];
//            SOCKADDR_IN sockAddr = { 0 };
//            int iSockAddrLen = sizeof sockAddr;
//            int nRealLen = ReceiveFrom(buffer, sizeof buffer, (SOCKADDR*)&sockAddr, &iSockAddrLen);
//            if (!(theApp.ipfilter.IsFiltered(sockAddr.sin_addr.S_un.S_addr) || theApp.clientlist.IsBannedClient(sockAddr.sin_addr.S_un.S_addr)))
//            {
//                BYTE* pBuffer;
//                uint nReceiverVerifyKey;
//                uint nSenderVerifyKey;
//                int nPacketLen = DecryptReceivedClient(buffer, nRealLen, &pBuffer, sockAddr.sin_addr.S_un.S_addr, &nReceiverVerifyKey, &nSenderVerifyKey);
//                if (nPacketLen >= 1)
//                {
//                    string strError;
//                    try
//                    {
//                        switch (pBuffer[0])
//                        {
//                            case OP_EMULEPROT:
//                                {
//                                    if (nPacketLen >= 2)
//                                        ProcessPacket(pBuffer + 2, nPacketLen - 2, pBuffer[1], sockAddr.sin_addr.S_un.S_addr, ntohs(sockAddr.sin_port));
//                                    else
//                                        throw CString(_T("eMule packet too short"));
//                                    break;
//                                }
//                            case OP_KADEMLIAPACKEDPROT:
//                                {
//                                    theStats.AddDownDataOverheadKad(nPacketLen);
//                                    if (nPacketLen >= 2)
//                                    {
//                                        uint32 nNewSize = nPacketLen * 10 + 300;
//                                        BYTE* unpack = NULL;
//                                        uLongf unpackedsize = 0;
//                                        int iZLibResult = 0;
//                                        do
//                                        {
//                                            delete[] unpack;
//                                            unpack = new BYTE[nNewSize];
//                                            unpackedsize = nNewSize - 2;
//                                            iZLibResult = uncompress(unpack + 2, &unpackedsize, pBuffer + 2, nPacketLen - 2);
//                                            nNewSize *= 2; // size for the next try if needed
//                                        } while (iZLibResult == Z_BUF_ERROR && nNewSize < 250000);

//                                        if (iZLibResult == Z_OK)
//                                        {
//                                            unpack[0] = OP_KADEMLIAHEADER;
//                                            unpack[1] = pBuffer[1];
//                                            try
//                                            {
//                                                Kademlia::CKademlia::ProcessPacket(unpack, unpackedsize + 2, ntohl(sockAddr.sin_addr.S_un.S_addr), ntohs(sockAddr.sin_port)
//                                                    , (Kademlia::CPrefs::GetUDPVerifyKey(sockAddr.sin_addr.S_un.S_addr) == nReceiverVerifyKey)
//                                                    , Kademlia::CKadUDPKey(nSenderVerifyKey, theApp.GetPublicIP(false)));
//                                            }
//                                            catch (...)
//								{
//                                                delete[] unpack;
//                                                throw;
//                                            }
//                                            }
//							else
//							{
//                                                delete[] unpack;
//                                                CString strError;
//                                                strError.Format(_T("Failed to uncompress Kad packet: zip error: %d (%hs)"), iZLibResult, zError(iZLibResult));
//                                                throw strError;
//                                            }
//                                            delete[] unpack;
//                                        }
//                                        else
//                                            throw CString(_T("Kad packet (compressed) too short"));
//                                        break;
//                                    }

//                    case OP_KADEMLIAHEADER:
//                                {
//                                    theStats.AddDownDataOverheadKad(nPacketLen);
//                                    if (nPacketLen >= 2)
//                                        Kademlia::CKademlia::ProcessPacket(pBuffer, nPacketLen, ntohl(sockAddr.sin_addr.S_un.S_addr), ntohs(sockAddr.sin_port)
//                                        , (Kademlia::CPrefs::GetUDPVerifyKey(sockAddr.sin_addr.S_un.S_addr) == nReceiverVerifyKey)
//                                        , Kademlia::CKadUDPKey(nSenderVerifyKey, theApp.GetPublicIP(false)));
//                                    else
//                                        throw CString(_T("Kad packet too short"));
//                                    break;
//                                }
//                            default:
//                                {
//                                    CString strError;
//                                    strError.Format(_T("Unknown protocol 0x%02x"), pBuffer[0]);
//                                    throw strError;
//                                }
//                        }
//                    }
//                    catch (CFileException* error)
//                    {
//                        error->Delete();
//                        strError = _T("Invalid packet received");
//                    }
//                    catch (CMemoryException* error)
//                    {
//                        error->Delete();
//                        strError = _T("Memory exception");
//                    }
//                    catch (CString error)
//                    {
//                        strError = error;
//                    }
//                    catch (Kademlia::CIOException* error)
//                    {
//                        error->Delete();
//                        strError = _T("Invalid packet received");
//                    }
//                    catch (CException* error)
//                    {
//                        error->Delete();
//                        strError = _T("General packet error");
//                    }
//#if DEBUG
//                    catch (Exception ex)
//                    {
//                        strError = "Unknown exception";
//                        Debug.Assert(false);
//                    }
//#endif
//                    if (thePrefs.GetVerbose() && strError.Length > 0)
//                    {
//                        string strClientInfo = "";
//                        CUpDownClient* client;
//                        if (pBuffer[0] == OP_EMULEPROT)
//                            client = theApp.clientlist->FindClientByIP_UDP(sockAddr.sin_addr.S_un.S_addr, ntohs(sockAddr.sin_port));
//                        else
//                            client = theApp.clientlist->FindClientByIP_KadPort(sockAddr.sin_addr.S_un.S_addr, ntohs(sockAddr.sin_port));
//                        if (client)
//                            strClientInfo = client.DbgGetClientInfo();
//                        else
//                            strClientInfo.Format("%s:%u", ipstr(sockAddr.sin_addr), ntohs(sockAddr.sin_port));

//                        DebugLogWarning("Client UDP socket: prot=0x%02x  opcode=0x%02x  sizeaftercrypt=%u realsize=%u  %s: %s", pBuffer[0], pBuffer[1], nPacketLen, nRealLen, strError, strClientInfo);
//                    }
//                }
//                else if (nPacketLen == SOCKET_ERROR)
//                {
//                    DWORD dwError = WSAGetLastError();
//                    if (dwError == WSAECONNRESET)
//                    {
//                        // Depending on local and remote OS and depending on used local (remote?) router we may receive
//                        // WSAECONNRESET errors. According some KB articles, this is a special way of winsock to report 
//                        // that a sent UDP packet was not received by the remote host because it was not listening on 
//                        // the specified port -> no eMule running there.
//                        //
//                        // TODO: So, actually we should do something with this information and drop the related Kad node 
//                        // or eMule client...
//                        ;
//                    }
//                    if (thePrefs.GetVerbose() && dwError != WSAECONNRESET)
//                    {
//                        string strClientInfo = "";
//                        if (iSockAddrLen > 0 && sockAddr.sin_addr.S_un.S_addr != 0 && sockAddr.sin_addr.S_un.S_addr != INADDR_NONE)
//                            strClientInfo.Format(" from %s:%u", ipstr(sockAddr.sin_addr), ntohs(sockAddr.sin_port));
//                        DebugLogError("Error: Client UDP socket, failed to receive data%s: %s", strClientInfo, GetErrorMessage(dwError, 1));
//                    }
//                }
//            }
//        }

//        protected bool ProcessPacket(byte packet, uint size, byte opcode, uint ip, ushort port)
//        {
//            switch (opcode)
//            {
//                case OP_REASKCALLBACKUDP:
//                    {
//                        if (thePrefs.GetDebugClientUDPLevel() > 0)
//                            DebugRecv("OP_ReaskCallbackUDP", NULL, NULL, ip);
//                        theStats.AddDownDataOverheadOther(size);
//                        CUpDownClient* buddy = theApp.clientlist->GetBuddy();
//                        if (buddy)
//                        {
//                            if (size < 17 || buddy->socket == NULL)
//                                break;
//                            if (!md4cmp(packet, buddy->GetBuddyID()))
//                            {
//                                PokeUInt32(const_cast<BYTE*>(packet) + 10, ip);
//                                PokeUInt16(const_cast<BYTE*>(packet) + 14, port);
//                                Packet* response = new Packet(OP_EMULEPROT);
//                                response->opcode = OP_REASKCALLBACKTCP;
//                                response->pBuffer = new char[size];
//                                memcpy(response->pBuffer, packet + 10, size - 10);
//                                response->size = size - 10;
//                                if (thePrefs.GetDebugClientTCPLevel() > 0)
//                                    DebugSend("OP__ReaskCallbackTCP", buddy);
//                                theStats.AddUpDataOverheadFileRequest(response->size);
//                                buddy->SendPacket(response, true);
//                            }
//                        }
//                        break;
//                    }
//                case OP_REASKFILEPING:
//                    {
//                        theStats.AddDownDataOverheadFileRequest(size);
//                        CSafeMemFile data_in(packet, size);
//                        uchar reqfilehash[16];
//                        data_in.ReadHash16(reqfilehash);
//                        CKnownFile* reqfile = theApp.sharedfiles->GetFileByID(reqfilehash);

//                        bool bSenderMultipleIpUnknown = false;
//                        CUpDownClient* sender = theApp.uploadqueue->GetWaitingClientByIP_UDP(ip, port, true, &bSenderMultipleIpUnknown);
//                        if (!reqfile)
//                        {
//                            if (thePrefs.GetDebugClientUDPLevel() > 0)
//                            {
//                                DebugRecv("OP_ReaskFilePing", NULL, reqfilehash, ip);
//                                DebugSend("OP__FileNotFound", NULL);
//                            }

//                            Packet* response = new Packet(OP_FILENOTFOUND, 0, OP_EMULEPROT);
//                            theStats.AddUpDataOverheadFileRequest(response->size);
//                            if (sender != NULL)
//                                SendPacket(response, ip, port, sender->ShouldReceiveCryptUDPPackets(), sender->GetUserHash(), false, 0);
//                            else
//                                SendPacket(response, ip, port, false, NULL, false, 0);
//                            break;
//                        }
//                        if (sender)
//                        {
//                            if (thePrefs.GetDebugClientUDPLevel() > 0)
//                                DebugRecv("OP_ReaskFilePing", sender, reqfilehash);

//                            //Make sure we are still thinking about the same file
//                            if (md4cmp(reqfilehash, sender->GetUploadFileID()) == 0)
//                            {
//                                sender->AddAskedCount();
//                                sender->SetLastUpRequest();
//                                //I messed up when I first added extended info to UDP
//                                //I should have originally used the entire ProcessExtenedInfo the first time.
//                                //So now I am forced to check UDPVersion to see if we are sending all the extended info.
//                                //For now on, we should not have to change anything here if we change
//                                //anything to the extended info data as this will be taken care of in ProcessExtendedInfo()
//                                //Update extended info. 
//                                if (sender->GetUDPVersion() > 3)
//                                {
//                                    sender->ProcessExtendedInfo(&data_in, reqfile);
//                                }
//                                //Update our complete source counts.
//                                else if (sender->GetUDPVersion() > 2)
//                                {
//                                    uint16 nCompleteCountLast = sender->GetUpCompleteSourcesCount();
//                                    uint16 nCompleteCountNew = data_in.ReadUInt16();
//                                    sender->SetUpCompleteSourcesCount(nCompleteCountNew);
//                                    if (nCompleteCountLast != nCompleteCountNew)
//                                    {
//                                        reqfile->UpdatePartsInfo();
//                                    }
//                                }
//                                CSafeMemFile data_out(128);
//                                if (sender->GetUDPVersion() > 3)
//                                {
//                                    if (reqfile->IsPartFile())
//                                        ((CPartFile*)reqfile)->WritePartStatus(&data_out);
//                                    else
//                                        data_out.WriteUInt16(0);
//                                }
//                                data_out.WriteUInt16((uint16)(theApp.uploadqueue->GetWaitingPosition(sender)));
//                                if (thePrefs.GetDebugClientUDPLevel() > 0)
//                                    DebugSend("OP__ReaskAck", sender);
//                                Packet* response = new Packet(&data_out, OP_EMULEPROT);
//                                response->opcode = OP_REASKACK;
//                                theStats.AddUpDataOverheadFileRequest(response->size);
//                                SendPacket(response, ip, port, sender->ShouldReceiveCryptUDPPackets(), sender->GetUserHash(), false, 0);
//                            }
//                            else
//                            {
//                                DebugLogError(_T("Client UDP socket; ReaskFilePing; reqfile does not match"));
//                                TRACE(_T("reqfile:         %s\n"), DbgGetFileInfo(reqfile->GetFileHash()));
//                                TRACE(_T("sender->GetRequestFile(): %s\n"), sender->GetRequestFile() ? DbgGetFileInfo(sender->GetRequestFile()->GetFileHash()) : _T("(null)"));
//                            }
//                        }
//                        else
//                        {
//                            if (thePrefs.GetDebugClientUDPLevel() > 0)
//                                DebugRecv("OP_ReaskFilePing", NULL, reqfilehash, ip);
//                            // Don't answer him. We probably have him on our queue already, but can't locate him. Force him to establish a TCP connection
//                            if (!bSenderMultipleIpUnknown)
//                            {
//                                if (((uint32)theApp.uploadqueue->GetWaitingUserCount() + 50) > thePrefs.GetQueueSize())
//                                {
//                                    if (thePrefs.GetDebugClientUDPLevel() > 0)
//                                        DebugSend("OP__QueueFull", NULL);
//                                    Packet* response = new Packet(OP_QUEUEFULL, 0, OP_EMULEPROT);
//                                    theStats.AddUpDataOverheadFileRequest(response->size);
//                                    SendPacket(response, ip, port, false, NULL, false, 0); // we cannot answer this one encrypted since we dont know this client
//                                }
//                            }
//                            else
//                            {
//                                DebugLogWarning(_T("UDP Packet received - multiple clients with the same IP but different UDP port found. Possible UDP Portmapping problem, enforcing TCP connection. IP: %s, Port: %u"), ipstr(ip), port);
//                            }
//                        }
//                        break;
//                    }
//                case OP_QUEUEFULL:
//                    {
//                        theStats.AddDownDataOverheadFileRequest(size);
//                        CUpDownClient* sender = theApp.downloadqueue->GetDownloadClientByIP_UDP(ip, port, true);
//                        if (thePrefs.GetDebugClientUDPLevel() > 0)
//                            DebugRecv("OP_QueueFull", sender, NULL, ip);
//                        if (sender && sender->UDPPacketPending())
//                        {
//                            sender->SetRemoteQueueFull(true);
//                            sender->UDPReaskACK(0);
//                        }
//                        else if (sender != NULL)
//                            DebugLogError(_T("Received UDP Packet (OP_QUEUEFULL) which was not requested (pendingflag == false); Ignored packet - %s"), sender->DbgGetClientInfo());
//                        break;
//                    }
//                case OP_REASKACK:
//                    {
//                        theStats.AddDownDataOverheadFileRequest(size);
//                        CUpDownClient* sender = theApp.downloadqueue->GetDownloadClientByIP_UDP(ip, port, true);
//                        if (thePrefs.GetDebugClientUDPLevel() > 0)
//                            DebugRecv("OP_ReaskAck", sender, NULL, ip);
//                        if (sender && sender->UDPPacketPending())
//                        {
//                            CSafeMemFile data_in(packet, size);
//                            if (sender->GetUDPVersion() > 3)
//                            {
//                                sender->ProcessFileStatus(true, &data_in, sender->GetRequestFile());
//                            }
//                            uint16 nRank = data_in.ReadUInt16();
//                            sender->SetRemoteQueueFull(false);
//                            sender->UDPReaskACK(nRank);
//                            sender->AddAskedCountDown();
//                        }
//                        else if (sender != NULL)
//                            DebugLogError(_T("Received UDP Packet (OP_REASKACK) which was not requested (pendingflag == false); Ignored packet - %s"), sender->DbgGetClientInfo());

//                        break;
//                    }
//                case OP_FILENOTFOUND:
//                    {
//                        theStats.AddDownDataOverheadFileRequest(size);
//                        CUpDownClient* sender = theApp.downloadqueue->GetDownloadClientByIP_UDP(ip, port, true);
//                        if (thePrefs.GetDebugClientUDPLevel() > 0)
//                            DebugRecv("OP_FileNotFound", sender, NULL, ip);
//                        if (sender && sender->UDPPacketPending())
//                        {
//                            sender->UDPReaskFNF(); // may delete 'sender'!
//                            sender = NULL;
//                        }
//                        else if (sender != NULL)
//                            DebugLogError(_T("Received UDP Packet (OP_FILENOTFOUND) which was not requested (pendingflag == false); Ignored packet - %s"), sender->DbgGetClientInfo());

//                        break;
//                    }
//                case OP_PORTTEST:
//                    {
//                        if (thePrefs.GetDebugClientUDPLevel() > 0)
//                            DebugRecv("OP_PortTest", NULL, NULL, ip);
//                        theStats.AddDownDataOverheadOther(size);
//                        if (size == 1)
//                        {
//                            if (packet[0] == 0x12)
//                            {
//                                bool ret = theApp.listensocket->SendPortTestReply('1', true);
//                                AddDebugLogLine(true, _T("UDP Portcheck packet arrived - ACK sent back (status=%i)"), ret);
//                            }
//                        }
//                        break;
//                    }
//                case OP_DIRECTCALLBACKREQ:
//                    {
//                        if (thePrefs.GetDebugClientUDPLevel() > 0)
//                            DebugRecv("OP_DIRECTCALLBACKREQ", NULL, NULL, ip);
//                        if (!theApp.clientlist->AllowCalbackRequest(ip))
//                        {
//                            DebugLogWarning(_T("Ignored DirectCallback Request because this IP (%s) has sent too many request within a short time"), ipstr(ip));
//                            break;
//                        }
//                        // do we accept callbackrequests at all?
//                        if (Kademlia::CKademlia::IsRunning() && Kademlia::CKademlia::IsFirewalled())
//                        {
//                            theApp.clientlist->AddTrackCallbackRequests(ip);
//                            CSafeMemFile data(packet, size);
//                            uint16 nRemoteTCPPort = data.ReadUInt16();
//                            uchar uchUserHash[16];
//                            data.ReadHash16(uchUserHash);
//                            uint8 byConnectOptions = data.ReadUInt8();
//                            CUpDownClient* pRequester = theApp.clientlist->FindClientByUserHash(uchUserHash, ip, nRemoteTCPPort);
//                            if (pRequester == NULL)
//                            {
//                                pRequester = new CUpDownClient(NULL, nRemoteTCPPort, ip, 0, 0, true);
//                                pRequester->SetUserHash(uchUserHash);
//                                theApp.clientlist->AddClient(pRequester);
//                            }
//                            pRequester->SetConnectOptions(byConnectOptions, true, false);
//                            pRequester->SetDirectUDPCallbackSupport(false);
//                            pRequester->SetIP(ip);
//                            pRequester->SetUserPort(nRemoteTCPPort);
//                            DEBUG_ONLY(DebugLog(_T("Accepting incoming DirectCallbackRequest from %s"), pRequester->DbgGetClientInfo()));
//                            pRequester->TryToConnect();
//                        }
//                        else
//                            DebugLogWarning(_T("Ignored DirectCallback Request because we do not accept DirectCall backs at all (%s)"), ipstr(ip));

//                        break;
//                    }
//                default:
//                    theStats.AddDownDataOverheadOther(size);
//                    if (thePrefs.GetDebugClientUDPLevel() > 0)
//                    {
//                        CUpDownClient* sender = theApp.downloadqueue->GetDownloadClientByIP_UDP(ip, port, true);
//                        Debug(_T("Unknown client UDP packet: host=%s:%u (%s) opcode=0x%02x  size=%u\n"), ipstr(ip), port, sender ? sender->DbgGetClientInfo() : _T(""), opcode, size);
//                    }
//                    return false;
//            }
//            return true;
//        }

//        protected void OnSend(int nErrorCode)
//        {
//            if (nErrorCode)
//            {
//                if (thePrefs.GetVerbose())
//                    DebugLogError(_T("Error: Client UDP socket, error on send event: %s"), GetErrorMessage(nErrorCode, 1));
//                return;
//            }

//            // ZZ:UploadBandWithThrottler (UDP) -->
//            sendLocker.Lock();
//            m_bWouldBlock = false;

//            if (controlpacket_queue.Count > 0)
//            {
//                theApp.uploadBandwidthThrottler->QueueForSendingControlPacket(this);
//            }
//            sendLocker.Unlock();
//            // <-- ZZ:UploadBandWithThrottler (UDP)
//        }

//        public SocketSentBytes SendControlData(uint maxNumberOfBytesToSend, uint /*minFragSize*/)
//        {
//            // ZZ:UploadBandWithThrottler (UDP)
//            // ZZ:UploadBandWithThrottler (UDP) -->
//            // NOTE: *** This function is invoked from a *different* thread!
//            sendLocker.Lock();

//            uint32 sentBytes = 0;
//            // <-- ZZ:UploadBandWithThrottler (UDP)

//            while (controlpacket_queue.Count > 0 && !IsBusy() && sentBytes < maxNumberOfBytesToSend)
//            { // ZZ:UploadBandWithThrottler (UDP)
//                UDPPack cur_packet = controlpacket_queue.Peek();
//                if (GetTickCount() - cur_packet.dwTime < UDPMAXQUEUETIME)
//                {
//                    uint nLen = cur_packet->packet->size + 2;
//                    byte[] sendbuffer = new byte[nLen];
//                    memcpy(sendbuffer, cur_packet.packet.GetUDPHeader(), 2);
//                    memcpy(sendbuffer + 2, cur_packet.packet.pBuffer, cur_packet.packet.size);

//                    if (cur_packet->bEncrypt && (theApp.GetPublicIP() > 0 || cur_packet->bKad))
//                    {
//                        nLen = EncryptSendClient(&sendbuffer, nLen, cur_packet->pachTargetClientHashORKadID, cur_packet->bKad, cur_packet->nReceiverVerifyKey, (cur_packet->bKad ? Kademlia::CPrefs::GetUDPVerifyKey(cur_packet->dwIP) : (uint16)0));
//                        //DEBUG_ONLY(  AddDebugLogLine(DLP_VERYLOW, false, _T("Sent obfuscated UDP packet to clientIP: %s, Kad: %s, ReceiverKey: %u"), ipstr(cur_packet->dwIP), cur_packet->bKad ? _T("Yes") : _T("No"), cur_packet->nReceiverVerifyKey) );
//                    }

//                    if (!SendTo((char*)sendbuffer, nLen, cur_packet->dwIP, cur_packet->nPort))
//                    {
//                        sentBytes += nLen; // ZZ:UploadBandWithThrottler (UDP)

//                        controlpacket_queue.Dequeue();
//                    }
//                    delete[] sendbuffer;
//                }
//                else
//                {
//                    controlpacket_queue.Dequeue();
//                }
//            }

//            // ZZ:UploadBandWithThrottler (UDP) -->
//            if (!IsBusy() && controlpacket_queue.Count > 0)
//            {
//                theApp.uploadBandwidthThrottler->QueueForSendingControlPacket(this);
//            }
//            sendLocker.Unlock();

//            SocketSentBytes returnVal = { true, 0, sentBytes };
//            return returnVal;
//            // <-- ZZ:UploadBandWithThrottler (UDP)
//        }


//        private int SendTo(byte[] lpBuf, int nBufLen, uint dwIP, ushort nPort)
//        {
//            // NOTE: *** This function is invoked from a *different* thread!
//            uint result = CAsyncSocket.SendTo(lpBuf, nBufLen, nPort, ipstr(dwIP));
//            if (result == (uint)SOCKET_ERROR)
//            {
//                uint error = GetLastError();
//                if (error == WSAEWOULDBLOCK)
//                {
//                    m_bWouldBlock = true;
//                    return -1;
//                }
//                if (thePrefs.GetVerbose())
//                    DebugLogError($"Error: Client UDP socket, failed to send data to %s:%u: %s", ipstr(dwIP), nPort, GetErrorMessage(error, 1));
//            }
//            return 0;
//        }

//        public bool SendPacket(Packet packet, uint dwIP, ushort nPort, bool bEncrypt, byte[] pachTargetClientHashORKadID, bool bKad, uint nReceiverVerifyKey)
//        {
//            UDPPack newpending = new UDPPack();
//            newpending.dwIP = dwIP;
//            newpending.nPort = nPort;
//            newpending.packet = packet;
//            newpending.dwTime = GetTickCount();
//            newpending.bEncrypt = bEncrypt && (pachTargetClientHashORKadID != null || (bKad && nReceiverVerifyKey != 0));
//            newpending.bKad = bKad;
//            newpending.nReceiverVerifyKey = nReceiverVerifyKey;

//#if DEBUG
//            if (newpending.packet.size > UDP_KAD_MAXFRAGMENT)
//                DebugLogWarning("Sending UDP packet > UDP_KAD_MAXFRAGMENT, opcode: %X, size: %u", packet->opcode, packet->size);
//#endif

//            if (newpending.bEncrypt && pachTargetClientHashORKadID != null)
//                md4cpy(newpending.pachTargetClientHashORKadID, pachTargetClientHashORKadID);
//            else
//                md4clr(newpending.pachTargetClientHashORKadID);
//            // ZZ:UploadBandWithThrottler (UDP) -->
//            sendLocker.Lock();
//            controlpacket_queue.Enqueue(newpending);
//            sendLocker.Unlock();

//            theApp.uploadBandwidthThrottler->QueueForSendingControlPacket(this);
//            return true;
//            // <-- ZZ:UploadBandWithThrottler (UDP)
//        }

//        public bool Create()
//        {
//            bool ret = true;

//            Windows.Networking.Sockets.DatagramSocket socket = new Windows.Networking.Sockets.DatagramSocket();

//            socket.MessageReceived += OnReceive;

//            //You can use any port that is not currently in use already on the machine. We will be using two separate and random 
//            //ports for the client and server because both the will be running on the same machine.
//            string serverPort = "1337";
//            string clientPort = "1338";

//            //Because we will be running the client and server on the same machine, we will use localhost as the hostname.
//            Windows.Networking.HostName serverHost = new Windows.Networking.HostName("localhost");

//            //Bind the socket to the clientPort so that we can start listening for UDP messages from the UDP echo server.
//            await socket.BindServiceNameAsync(thePrefs.GetUDPPort());

//            //Write a message to the UDP echo server.
//            Stream streamOut = (await socket.GetOutputStreamAsync(serverHost, serverPort)).AsStreamForWrite();
//            StreamWriter writer = new StreamWriter(streamOut);

//            if (thePrefs.GetUDPPort())
//            {
//                ret = CAsyncSocket.Create(thePrefs.GetUDPPort(), SOCK_DGRAM, FD_READ | FD_WRITE, thePrefs.GetBindAddrW()) != false;
//                if (ret)
//                {
//                    m_port = thePrefs.GetUDPPort();
//                    // the default socket size seems to be not enough for this UDP socket
//                    // because we tend to drop packets if several flow in at the same time
//                    int val = 64 * 1024;
//                    if (!SetSockOpt(SO_RCVBUF, &val, sizeof(val)))
//                        DebugLogError("Failed to increase socket size on UDP socket");
//                }
//            }

//            if (ret)
//                m_port = thePrefs.GetUDPPort();

//            return ret;
//        }

//        public bool Rebind()
//        {
//            if (thePrefs.GetUDPPort() == m_port)
//                return false;
//            Close();
//            return Create();
//        }
    }
}
