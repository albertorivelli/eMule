using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace eMule
{
    public class ListenSocket
    {
//        private bool bListening;
//        private List<ClientReqSocket> socket_list;
//        private ushort m_OpenSocketsInterval;
//        private uint maxconnectionreached;
//        private ushort m_ConnectionStates[3];
//        private int m_nPendingConnections;
//        private uint peakconnections;
//        private uint totalconnectionchecks;
//        private float averageconnections;
//        private uint activeconnections;
//        private ushort m_port;
//        private uint m_nHalfOpen;
//        private uint m_nComp;
//        static int s_iAcceptConnectionCondRejected;

//        public bool SendPortTestReply(char result, bool disconnect = false)
//        {
//            POSITION pos2;
//            for (POSITION pos1 = socket_list.GetHeadPosition(); (pos2 = pos1) != NULL;)
//            {
//                socket_list.GetNext(pos1);
//                ClientReqSocket cur_sock = socket_list.GetAt(pos2);
//                if (cur_sock->m_bPortTestCon)
//                {
//                    if (thePrefs.GetDebugClientTCPLevel() > 0)
//                        DebugSend("OP__PortTest", cur_sock->client);
//                    Packet replypacket = new Packet(OP_PORTTEST, 1);
//                    replypacket->pBuffer[0] = result;
//                    theStats.AddUpDataOverheadOther(replypacket->size);
//                    cur_sock.SendPacket(replypacket);
//                    if (disconnect)
//                        cur_sock->m_bPortTestCon = false;
//                    return true;
//                }
//            }
//            return false;
//        }

//        public ListenSocket()
//        {
//            bListening = false;
//            maxconnectionreached = 0;
//            m_OpenSocketsInterval = 0;
//            m_nPendingConnections = 0;

//            memset(m_ConnectionStates, 0, sizeof m_ConnectionStates);
//            peakconnections = 0;
//            totalconnectionchecks = 0;
//            averageconnections = 0.0f;
//            activeconnections = 0;
//            m_port = 0;
//            m_nHalfOpen = 0;
//            m_nComp = 0;
//        }

//        ~ListenSocket()
//        {
//            Close();
//            KillAllSockets();
//        }

//        public bool Rebind()
//        {
//            if (thePrefs.GetPort() == m_port)
//                return false;

//            Close();
//            KillAllSockets();

//            return StartListening();
//        }

//        public bool StartListening()
//        {
//            bListening = true;

//            // Creating the socket with SO_REUSEADDR may solve LowID issues if emule was restarted
//            // quickly or started after a crash, but(!) it will also create another problem. If the
//            // socket is already used by some other application (e.g. a 2nd emule), we though bind
//            // to that socket leading to the situation that 2 applications are listening at the same
//            // port!
//            if (!Create(thePrefs.GetPort(), SOCK_STREAM, FD_ACCEPT, thePrefs.GetBindAddrA(), FALSE/*bReuseAddr*/))
//                return false;

//            // Rejecting a connection with conditional WSAAccept and not using SO_CONDITIONAL_ACCEPT
//            // -------------------------------------------------------------------------------------
//            // recv: SYN
//            // send: SYN ACK (!)
//            // recv: ACK
//            // send: ACK RST
//            // recv: PSH ACK + OP_HELLO packet
//            // send: RST
//            // --- 455 total bytes (depending on OP_HELLO packet)
//            // In case SO_CONDITIONAL_ACCEPT is not used, the TCP/IP stack establishes the connection
//            // before WSAAccept has a chance to reject it. That's why the remote peer starts to send
//            // it's first data packet.
//            // ---
//            // Not using SO_CONDITIONAL_ACCEPT gives us 6 TCP packets and the OP_HELLO data. We
//            // have to lookup the IP only 1 time. This is still way less traffic than rejecting the
//            // connection by closing it after the 'Accept'.

//            // Rejecting a connection with conditional WSAAccept and using SO_CONDITIONAL_ACCEPT
//            // ---------------------------------------------------------------------------------
//            // recv: SYN
//            // send: ACK RST
//            // recv: SYN
//            // send: ACK RST
//            // recv: SYN
//            // send: ACK RST
//            // --- 348 total bytes
//            // The TCP/IP stack tries to establish the connection 3 times until it gives up. 
//            // Furthermore the remote peer experiences a total timeout of ~ 1 minute which is
//            // supposed to be the default TCP/IP connection timeout (as noted in MSDN).
//            // ---
//            // Although we get a total of 6 TCP packets in case of using SO_CONDITIONAL_ACCEPT,
//            // it's still less than not using SO_CONDITIONAL_ACCEPT. But, we have to lookup
//            // the IP 3 times instead of 1 time.

//            //if (thePrefs.GetConditionalTCPAccept() && !thePrefs.GetProxySettings().UseProxy) {
//            //	int iOptVal = 1;
//            //	VERIFY( SetSockOpt(SO_CONDITIONAL_ACCEPT, &iOptVal, sizeof iOptVal) );
//            //}

//            if (!Listen())
//                return false;

//            m_port = thePrefs.GetPort();
//            return true;
//        }

//        public void ReStartListening()
//        {
//            bListening = true;

//            ASSERT(m_nPendingConnections >= 0);
//            if (m_nPendingConnections > 0)
//            {
//                m_nPendingConnections--;
//                OnAccept(0);
//            }
//        }

//        public void StopListening()
//        {
//            bListening = false;
//            maxconnectionreached++;
//        }

//        private int AcceptConnectionCond(LPWSABUF lpCallerId, LPWSABUF /*lpCallerData*/, LPQOS /*lpSQOS*/, LPQOS /*lpGQOS*/,
//                                          LPWSABUF /*lpCalleeId*/, LPWSABUF /*lpCalleeData*/, GROUP FAR* /*g*/, DWORD /*dwCallbackData*/)
//        {
//            if (lpCallerId && lpCallerId->buf && lpCallerId->len >= sizeof SOCKADDR_IN)



//    {
//                LPSOCKADDR_IN pSockAddr = (LPSOCKADDR_IN)lpCallerId->buf;
//                ASSERT(pSockAddr->sin_addr.S_un.S_addr != 0 && pSockAddr->sin_addr.S_un.S_addr != INADDR_NONE);

//                if (theApp.ipfilter->IsFiltered(pSockAddr->sin_addr.S_un.S_addr))
//                {
//                    if (thePrefs.GetLogFilteredIPs())
//                        AddDebugLogLine(false, _T("Rejecting connection attempt (IP=%s) - IP filter (%s)"), ipstr(pSockAddr->sin_addr.S_un.S_addr), theApp.ipfilter->GetLastHit());
//                    s_iAcceptConnectionCondRejected = 1;
//                    return CF_REJECT;
//                }

//                if (theApp.clientlist->IsBannedClient(pSockAddr->sin_addr.S_un.S_addr))
//                {
//                    if (thePrefs.GetLogBannedClients())
//                    {
//                        CUpDownClient* pClient = theApp.clientlist->FindClientByIP(pSockAddr->sin_addr.S_un.S_addr);
//                        AddDebugLogLine(false, _T("Rejecting connection attempt of banned client %s %s"), ipstr(pSockAddr->sin_addr.S_un.S_addr), pClient->DbgGetClientInfo());
//                    }
//                    s_iAcceptConnectionCondRejected = 2;
//                    return CF_REJECT;
//                }
//            }
//            else
//            {
//                if (thePrefs.GetVerbose())
//                    DebugLogError(_T("Client TCP socket: AcceptConnectionCond unexpected lpCallerId"));
//            }

//            return CF_ACCEPT;
//        }

//        public void OnAccept(int nErrorCode)
//        {
//            if (!nErrorCode)
//            {
//                m_nPendingConnections++;
//                if (m_nPendingConnections < 1)
//                {
//                    ASSERT(0);
//                    m_nPendingConnections = 1;
//                }

//                if (TooManySockets(true) && !theApp.serverconnect->IsConnecting())
//                {
//                    StopListening();
//                    return;
//                }
//                else if (!bListening)
//                    ReStartListening(); //If the client is still at maxconnections, this will allow it to go above it.. But if you don't, you will get a lowID on all servers.

//                uint32 nFataErrors = 0;
//                while (m_nPendingConnections > 0)
//                {
//                    m_nPendingConnections--;

//                    CClientReqSocket* newclient;
//                    SOCKADDR_IN SockAddr = { 0 };
//                    int iSockAddrLen = sizeof SockAddr;
//                    if (thePrefs.GetConditionalTCPAccept() && !thePrefs.GetProxySettings().UseProxy)
//                    {
//                        s_iAcceptConnectionCondRejected = 0;
//                        SOCKET sNew = WSAAccept(m_SocketData.hSocket, (SOCKADDR*)&SockAddr, &iSockAddrLen, AcceptConnectionCond, 0);
//                        if (sNew == INVALID_SOCKET)
//                        {
//                            DWORD nError = GetLastError();
//                            if (nError == WSAEWOULDBLOCK)
//                            {
//                                DebugLogError(LOG_STATUSBAR, _T("%hs: Backlogcounter says %u connections waiting, Accept() says WSAEWOULDBLOCK - setting counter to zero!"), __FUNCTION__, m_nPendingConnections);
//                                m_nPendingConnections = 0;
//                                break;
//                            }
//                            else
//                            {
//                                if (nError != WSAECONNREFUSED || s_iAcceptConnectionCondRejected == 0)
//                                {
//                                    DebugLogError(LOG_STATUSBAR, _T("%hs: Backlogcounter says %u connections waiting, Accept() says %s - setting counter to zero!"), __FUNCTION__, m_nPendingConnections, GetErrorMessage(nError, 1));
//                                    nFataErrors++;
//                                }
//                                else if (s_iAcceptConnectionCondRejected == 1)
//                                    theStats.filteredclients++;
//                            }
//                            if (nFataErrors > 10)
//                            {
//                                // the question is what todo on a error. We cant just ignore it because then the backlog will fill up
//                                // and lock everything. We can also just endlos try to repeat it because this will lock up eMule
//                                // this should basically never happen anyway
//                                // however if we are in such a position, try to reinitalize the socket.
//                                DebugLogError(LOG_STATUSBAR, _T("%hs: Accept() Error Loop, recreating socket"), __FUNCTION__);
//                                Close();
//                                StartListening();
//                                m_nPendingConnections = 0;
//                                break;
//                            }
//                            continue;
//                        }
//                        newclient = new CClientReqSocket;
//                        VERIFY(newclient->InitAsyncSocketExInstance());
//                        newclient->m_SocketData.hSocket = sNew;
//                        newclient->AttachHandle(sNew);

//                        AddConnection();
//                    }
//                    else
//                    {
//                        newclient = new CClientReqSocket;
//                        if (!Accept(*newclient, (SOCKADDR*)&SockAddr, &iSockAddrLen))
//                        {
//                            newclient->Safe_Delete();
//                            DWORD nError = GetLastError();
//                            if (nError == WSAEWOULDBLOCK)
//                            {
//                                DebugLogError(LOG_STATUSBAR, _T("%hs: Backlogcounter says %u connections waiting, Accept() says WSAEWOULDBLOCK - setting counter to zero!"), __FUNCTION__, m_nPendingConnections);
//                                m_nPendingConnections = 0;
//                                break;
//                            }
//                            else
//                            {
//                                DebugLogError(LOG_STATUSBAR, _T("%hs: Backlogcounter says %u connections waiting, Accept() says %s - setting counter to zero!"), __FUNCTION__, m_nPendingConnections, GetErrorMessage(nError, 1));
//                                nFataErrors++;
//                            }
//                            if (nFataErrors > 10)
//                            {
//                                // the question is what todo on a error. We cant just ignore it because then the backlog will fill up
//                                // and lock everything. We can also just endlos try to repeat it because this will lock up eMule
//                                // this should basically never happen anyway
//                                // however if we are in such a position, try to reinitalize the socket.
//                                DebugLogError(LOG_STATUSBAR, _T("%hs: Accept() Error Loop, recreating socket"), __FUNCTION__);
//                                Close();
//                                StartListening();
//                                m_nPendingConnections = 0;
//                                break;
//                            }
//                            continue;
//                        }

//                        AddConnection();

//                        if (SockAddr.sin_addr.S_un.S_addr == 0) // for safety..
//                        {
//                            iSockAddrLen = sizeof SockAddr;
//                            newclient->GetPeerName((SOCKADDR*)&SockAddr, &iSockAddrLen);
//                            DebugLogWarning(_T("SockAddr.sin_addr.S_un.S_addr == 0;  GetPeerName returned %s"), ipstr(SockAddr.sin_addr.S_un.S_addr));
//                        }

//                        ASSERT(SockAddr.sin_addr.S_un.S_addr != 0 && SockAddr.sin_addr.S_un.S_addr != INADDR_NONE);

//                        if (theApp.ipfilter->IsFiltered(SockAddr.sin_addr.S_un.S_addr))
//                        {
//                            if (thePrefs.GetLogFilteredIPs())
//                                AddDebugLogLine(false, _T("Rejecting connection attempt (IP=%s) - IP filter (%s)"), ipstr(SockAddr.sin_addr.S_un.S_addr), theApp.ipfilter->GetLastHit());
//                            newclient->Safe_Delete();
//                            theStats.filteredclients++;
//                            continue;
//                        }

//                        if (theApp.clientlist->IsBannedClient(SockAddr.sin_addr.S_un.S_addr))
//                        {
//                            if (thePrefs.GetLogBannedClients())
//                            {
//                                CUpDownClient* pClient = theApp.clientlist->FindClientByIP(SockAddr.sin_addr.S_un.S_addr);
//                                AddDebugLogLine(false, _T("Rejecting connection attempt of banned client %s %s"), ipstr(SockAddr.sin_addr.S_un.S_addr), pClient->DbgGetClientInfo());
//                            }
//                            newclient->Safe_Delete();
//                            continue;
//                        }
//                    }
//                    newclient->AsyncSelect(FD_WRITE | FD_READ | FD_CLOSE);
//                }

//                ASSERT(m_nPendingConnections >= 0);
//            }
//        }

//        public void Process()
//        {
//            m_OpenSocketsInterval = 0;
//            POSITION pos2;
//            for (POSITION pos1 = socket_list.GetHeadPosition(); (pos2 = pos1) != NULL;)
//            {
//                socket_list.GetNext(pos1);
//                CClientReqSocket* cur_sock = socket_list.GetAt(pos2);
//                if (cur_sock->deletethis)
//                {
//                    if (cur_sock->m_SocketData.hSocket != INVALID_SOCKET)
//                    {
//                        cur_sock->Close();          // calls 'closesocket'
//                    }
//                    else
//                    {
//                        cur_sock->Delete_Timed();   // may delete 'cur_sock'
//                    }
//                }
//                else
//                {
//                    cur_sock->CheckTimeOut();       // may call 'shutdown'
//                }
//            }

//            if ((GetOpenSockets() + 5 < thePrefs.GetMaxConnections() || theApp.serverconnect->IsConnecting()) && !bListening)
//                ReStartListening();
//        }

//        public void RecalculateStats()
//        {
//            memset(m_ConnectionStates, 0, sizeof m_ConnectionStates);
//            for (POSITION pos = socket_list.GetHeadPosition(); pos != NULL;)
//            {
//                switch (socket_list.GetNext(pos)->GetConState())
//                {
//                    case ES_DISCONNECTED:
//                        m_ConnectionStates[0]++;
//                        break;
//                    case ES_NOTCONNECTED:
//                        m_ConnectionStates[1]++;
//                        break;
//                    case ES_CONNECTED:
//                        m_ConnectionStates[2]++;
//                        break;
//                }
//            }
//        }

//        public void AddSocket(ClientReqSocket* toadd)
//        {
//            socket_list.AddTail(toadd);
//        }

//        public void RemoveSocket(ClientReqSocket* todel)
//        {
//            for (POSITION pos = socket_list.GetHeadPosition(); pos != NULL;)
//            {
//                POSITION posLast = pos;
//                if (socket_list.GetNext(pos) == todel)
//                    socket_list.RemoveAt(posLast);
//            }
//        }

//        public void KillAllSockets()
//        {
//            for (POSITION pos = socket_list.GetHeadPosition(); pos != 0; pos = socket_list.GetHeadPosition())
//            {
//                CClientReqSocket* cur_socket = socket_list.GetAt(pos);
//                if (cur_socket->client)
//                    delete cur_socket->client;
//		else
//			delete cur_socket;
//            }
//        }

//        public void AddConnection()
//        {
//            m_OpenSocketsInterval++;
//        }

//        public bool TooManySockets(bool bIgnoreInterval)
//        {
//            if (GetOpenSockets() > thePrefs.GetMaxConnections()
//                || (m_OpenSocketsInterval > (thePrefs.GetMaxConperFive() * GetMaxConperFiveModifier()) && !bIgnoreInterval)
//                || (m_nHalfOpen >= thePrefs.GetMaxHalfConnections() && !bIgnoreInterval))
//                return true;
//            return false;
//        }

//        public bool IsValidSocket(ClientReqSocket totest)
//        {
//            return socket_list.Find(totest) != NULL;
//        }

//#if DEBUG
//        public void Debug_ClientDeleted(CUpDownClient* deleted)
//        {
//            for (POSITION pos = socket_list.GetHeadPosition(); pos != NULL;)
//            {
//                CClientReqSocket* cur_sock = socket_list.GetNext(pos);
//                if (!AfxIsValidAddress(cur_sock, sizeof(CClientReqSocket)))
//                    AfxDebugBreak();
//                if (thePrefs.m_iDbgHeap >= 2)
//                    ASSERT_VALID(cur_sock);
//                if (cur_sock->client == deleted)
//                    AfxDebugBreak();
//            }
//        }
//#endif

//        public void UpdateConnectionsStatus()
//        {
//            activeconnections = GetOpenSockets();

//            // Update statistics for 'peak connections'
//            if (peakconnections < activeconnections)
//                peakconnections = activeconnections;
//            if (peakconnections > thePrefs.GetConnPeakConnections())
//                thePrefs.SetConnPeakConnections(peakconnections);

//            if (theApp.IsConnected())
//            {
//                totalconnectionchecks++;
//                if (totalconnectionchecks == 0)
//                {
//                    // wrap around occured, avoid division by zero
//                    totalconnectionchecks = 100;
//                }

//                // Get a weight for the 'avg. connections' value. The longer we run the higher 
//                // gets the weight (the percent of 'avg. connections' we use).
//                float fPercent = (float)(totalconnectionchecks - 1) / (float)totalconnectionchecks;
//                if (fPercent > 0.99F)
//                    fPercent = 0.99F;

//                // The longer we run the more we use the 'avg. connections' value and the less we
//                // use the 'active connections' value. However, if we are running quite some time
//                // without any connections (except the server connection) we will eventually create 
//                // a floating point underflow exception.
//                averageconnections = averageconnections * fPercent + activeconnections * (1.0F - fPercent);
//                if (averageconnections < 0.001F)
//                    averageconnections = 0.001F;    // avoid floating point underflow
//            }
//        }

//        public float GetMaxConperFiveModifier()
//        {
//            float SpikeSize = GetOpenSockets() - averageconnections;
//            if (SpikeSize < 1.0F)
//                return 1.0F;

//            float SpikeTolerance = 25.0F * (float)thePrefs.GetMaxConperFive() / 10.0F;
//            if (SpikeSize > SpikeTolerance)
//                return 0;

//            float Modifier = 1.0F - SpikeSize / SpikeTolerance;
//            return Modifier;
//        }
    }
}
