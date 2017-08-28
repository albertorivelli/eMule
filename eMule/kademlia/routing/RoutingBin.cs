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
 
 
This work is based on the java implementation of the Kademlia protocol.
Kademlia: Peer-to-peer routing based on the XOR metric
Copyright (C) 2002  Petar Maymounkov [petar@post.harvard.edu]
http://kademlia.scs.cs.nyu.edu
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
using System.Text;
using System.Threading.Tasks;

namespace Kademlia
{
    public class RoutingBin
    {
        private List<Contact> m_listEntries;
        private static Dictionary<uint, uint> s_mapGlobalContactIPs;
        private static Dictionary<uint, uint> s_mapGlobalContactSubnets;
        public bool m_bDontDeleteContacts;

        const int MAX_CONTACTS_SUBNET = 10;
        const int MAX_CONTACTS_IP = 1;

        public RoutingBin()
        {
            // Init delete contact flag.
            m_bDontDeleteContacts = false;
        }

        public bool AddContact(Contact pContact)
        {
            Debug.Assert(pContact != null);
            uint cSameSubnets = 0;

            // Check if we already have a contact with this ID in the list.
            foreach (var contact in m_listEntries)
            {
                if (contact.ClientID == pContact.ClientID)
                {
                    return false;
                }

                if ((contact.IPAddress & 0xFFFFFF00) == (pContact.IPAddress & 0xFFFFFF00))
                    cSameSubnets++;
            }

            // Several checks to make sure that we don't store multiple contacts from the same IP or too many contacts from the same subnet
            // This is supposed to add a bit of protection against several attacks and raise the ressource needs (IPs) for a successful contact on the attacker side 
            // Such IPs are not banned from Kad, they still can index, search, etc so multiple KAD clients behind one IP still work
            if (!CheckGlobalIPLimits(pContact.IPAddress, pContact.UDPPort, true))
                return false;

            // no more than 2 IPs from the same /24 netmask in one bin, except if its a LANIP (if we don't accept LANIPs they already have been filtered before)
            if (cSameSubnets >= 2 && !OtherFunctions.IsLANIP((uint)IPAddress.NetworkToHostOrder(pContact.IPAddress)))
            {
                if (thePrefs.GetLogFilteredIPs())
                    AddDebugLogLine(false, "Ignored kad contact (IP=%s:%u) - too many contacts with the same subnet in RoutingBin", IPAddress.NetworkToHostOrder(pContact.IPAddress), pContact.UDPPort);
                return false;
            }

            // If not full, add to end of list
            if (m_listEntries.Count < Defines.K)
            {
                m_listEntries.Add(pContact);
                AdjustGlobalTracking(pContact.IPAddress, true);
                return true;
            }
            return false;
        }

        public void SetAlive(Contact pContact)
        {
            Debug.Assert(pContact != null);
            // Check if we already have a contact with this ID in the list.
            Contact pContactTest = GetContact(pContact.ClientID);
            Debug.Assert(pContact == pContactTest);
            if (pContactTest != null)
            {
                // Mark contact as being alive.
                pContactTest.UpdateType();
                // Move to the end of the list
                PushToBottom(pContactTest);
            }
        }

        public void SetTCPPort(uint uIP, ushort uUDPPort, ushort uTCPPort)
        {
            // Find contact with IP/Port
            foreach (var contact in m_listEntries)
            {
                if ((uIP == contact.IPAddress) && (uUDPPort == contact.UDPPort))
                {
                    // Set TCPPort and mark as alive.
                    contact.TCPPort = uTCPPort;
                    contact.UpdateType();
                    // Move to the end of the list
                    PushToBottom(contact);
                    break;
                }
            }
        }

        public Contact GetContact(UInt128 uID)
        {
            // Find contact by ID.
            foreach (var pContact in m_listEntries)
            {
                if (uID == pContact.ClientID)
                    return pContact;
            }
            return null;
        }

        public Contact GetContact(uint uIP, uint nPort, bool bTCPPort)
        {
            // Find contact with IP/Port
            foreach(var contact in m_listEntries)
            {
                if ((uIP == contact.IPAddress)
                    && ((!bTCPPort && nPort == contact.UDPPort) || (bTCPPort && nPort == contact.TCPPort) || nPort == 0))
                {
                    return contact;
                }
            }
            return null;
        }

        public void RemoveContact(Contact pContact, bool bNoTrackingAdjust = false)
        {
            if (!bNoTrackingAdjust)
                AdjustGlobalTracking(pContact.IPAddress, false);
            m_listEntries.Remove(pContact);
        }

        public uint GetSize()
        {
            return (uint)m_listEntries.Count;
        }

        public void GetNumContacts(ref uint nInOutContacts, ref uint nInOutFilteredContacts, byte byMinVersion)
        {
            // Count all Nodes which meet the search criteria and also report those who don't
            foreach (var contact in m_listEntries)
            {
                if (contact.Version >= byMinVersion)
                    nInOutContacts++;
                else
                    nInOutFilteredContacts++;
            }
        }

        public uint GetRemaining()
        {
            return (uint)Defines.K - m_listEntries.Count;
        }

        public void GetEntries(List<Contact> plistResult, bool bEmptyFirst = true)
        {
            // Clear results if requested first.
            if (bEmptyFirst)
                plistResult.Clear();

            // Append all entries to the results.
            if (m_listEntries.Count > 0)
                plistResult.AddRange(m_listEntries);
        }

        public Contact GetOldest()
        {
            // All new/updated entries are appended to the back.
            if (m_listEntries.Count > 0)
                return m_listEntries[0];

            return null;
        }

        public void GetClosestTo(uint uMaxType, UInt128 uTarget, uint uMaxRequired, Dictionary<UInt128, Contact> pmapResult, bool bEmptyFirst = true, bool bInUse = false)
        {
            // Empty list if requested.
            if (bEmptyFirst)
                pmapResult.Clear();

            // Return 0 since we have no entries.
            if (m_listEntries.Count == 0)
                return;

            // First put results in sort order for uTarget so we can insert them correctly.
            // We don't care about max results at this time.
            foreach (var contact in m_listEntries)
            {
                if (contact.Type <= uMaxType && contact.IsIpVerified)
                {
                    UInt128 uTargetDistance = contact.ClientID;
                    uTargetDistance.Xor(uTarget);
                    pmapResult[uTargetDistance] = contact;

                    // This list will be used for an unknown time, Inc in use so it's not deleted.
                    if (bInUse)
                        contact.IncUse();
                }
            }

            // Remove any extra results by least wanted first.
            while (pmapResult.Count > uMaxRequired)
            {
                // Dec in use count.
                if (bInUse)
                    (--pmapResult->end())->second->DecUse();

                // remove from results
                pmapResult->erase(--pmapResult->end());
            }

            // Return result count to the caller.
            return;
        }

        protected void AdjustGlobalTracking(uint uIP, bool bIncrease)
        {
            // IP
            uint nSameIPCount = 0;
            s_mapGlobalContactIPs.Lookup(uIP, nSameIPCount);
            if (bIncrease)
            {
                if (nSameIPCount >= MAX_CONTACTS_IP)
                {
                    Debug.Assert(false);
                    //DebugLogError("RoutingBin Global IP Tracking inconsitency on increase (%s)", ipstr(ntohl(uIP)));
                }
                nSameIPCount++;
            }
            else if (!bIncrease)
            {
                if (nSameIPCount == 0)
                {
                    Debug.Assert(false);
                    //DebugLogError("RoutingBin Global IP Tracking inconsitency on decrease (%s)", ipstr(ntohl(uIP)));
                }
                else
                    nSameIPCount--;
            }
            if (nSameIPCount != 0)
                s_mapGlobalContactIPs.SetAt(uIP, nSameIPCount);
            else
                s_mapGlobalContactIPs.RemoveKey(uIP);

            // Subnet
            uint nSameSubnetCount = 0;
            s_mapGlobalContactSubnets.Lookup(uIP & 0xFFFFFF00, nSameSubnetCount);
            if (bIncrease)
            {
                if (nSameSubnetCount >= MAX_CONTACTS_SUBNET && !OtherFunctions.IsLANIP((uint)IPAddress.NetworkToHostOrder(uIP)))
                {
                    Debug.Assert(false);
                    //DebugLogError("RoutingBin Global Subnet Tracking inconsitency on increase (%s)", ipstr(ntohl(uIP)));
                }
                nSameSubnetCount++;
            }
            else if (!bIncrease)
            {
                if (nSameSubnetCount == 0)
                {
                    Debug.Assert(false);
                    //DebugLogError("RoutingBin Global IP Subnet inconsitency on decrease (%s)", ipstr(ntohl(uIP)));
                }
                else
                    nSameSubnetCount--;
            }
            if (nSameSubnetCount != 0)
                s_mapGlobalContactSubnets.SetAt(uIP & 0xFFFFFF00, nSameSubnetCount);
            else
                s_mapGlobalContactSubnets.RemoveKey(uIP & 0xFFFFFF00);
        }

        public bool ChangeContactIPAddress(Contact pContact, uint uNewIP)
        {
            // Called if we want to update a indexed contact with a new IP. We have to check if we actually allow such a change
            // and if adjust our tracking. Rejecting a change will in the worst case lead a node contact to become invalid and purged later, 
            // but it also protects against a flood of malicous update requests from on IP which would be able to "reroute" all
            // contacts to itself and by that making them useless
            if (pContact.IPAddress == uNewIP)
                return true;

            Debug.Assert(GetContact(pContact.ClientID) == pContact);

            // no more than 1 KadID per IP
            uint nSameIPCount = 0;
            s_mapGlobalContactIPs.Lookup(uNewIP, nSameIPCount);
            if (nSameIPCount >= MAX_CONTACTS_IP)
            {
                if (thePrefs.GetLogFilteredIPs())
                    AddDebugLogLine(false, "Rejected kad contact ip change on update (old IP=%s, requested IP=%s) - too many contacts with the same IP (global)", ipstr(ntohl(pContact.IPAddress)), ipstr(ntohl(uNewIP)));
                return false;
            }

            if ((pContact.IPAddress & 0xFFFFFF00) != (uNewIP & 0xFFFFFF00))
            {
                //  no more than 10 IPs from the same /24 netmask global, except if its a LANIP (if we don't accept LANIPs they already have been filtered before)
                uint nSameSubnetGlobalCount = 0;
                s_mapGlobalContactSubnets.Lookup(uNewIP & 0xFFFFFF00, nSameSubnetGlobalCount);
                if (nSameSubnetGlobalCount >= MAX_CONTACTS_SUBNET && !OtherFunctions.IsLANIP((uint)IPAddress.NetworkToHostOrder(uNewIP)))
                {
                    if (thePrefs.GetLogFilteredIPs())
                        AddDebugLogLine(false, "Rejected kad contact ip change on update (old IP=%s, requested IP=%s) - too many contacts with the same Subnet (global)", ipstr(ntohl(pContact.IPAddress)), ipstr(ntohl(uNewIP)));
                    return false;
                }

                // no more than 2 IPs from the same /24 netmask in one bin, except if its a LANIP (if we don't accept LANIPs they already have been filtered before)
                uint cSameSubnets = 0;
                // Check if we already have a contact with this ID in the list.
                foreach (var contact in m_listEntries)
                {
                    if ((uNewIP & 0xFFFFFF00) == (contact.IPAddress & 0xFFFFFF00))
                        cSameSubnets++;
                }

                if (cSameSubnets >= 2 && !OtherFunctions.IsLANIP((uint)IPAddress.NetworkToHostOrder(uNewIP)))
                {
                    if (thePrefs.GetLogFilteredIPs())
                        AddDebugLogLine(false, "Rejected kad contact ip change on update (old IP=%s, requested IP=%s) - too many contacts with the same Subnet (local)", ipstr(ntohl(pContact.IPAddress)), ipstr(ntohl(uNewIP)));
                    return false;
                }
            }

            // everything fine
            // LOGTODO REMOVE
            //DEBUG_ONLY(DebugLog(_T("Index contact IP change allowed %s -> %s"), ipstr(ntohl(pContact->GetIPAddress())), ipstr(ntohl(uNewIP))));
            AdjustGlobalTracking(pContact.IPAddress, false);
            pContact.IPAddress = uNewIP;
            AdjustGlobalTracking(pContact.IPAddress, true);
            return true;
        }

        public void PushToBottom(Contact pContact) // puts an existing contact from X to the end of the list
        {
            Debug.Assert(GetContact(pContact.ClientID) == pContact);
            RemoveContact(pContact, true);
            m_listEntries.Add(pContact);
        }

        public Contact GetRandomContact(uint nMaxType, uint nMinKadVersion)
        {
            if (m_listEntries.Count == 0)
                return null;

            Contact pLastFit = null;
            uint nRandomStartPos = GetRandomUInt16() % m_listEntries.Count;
            uint nIndex = 0;
            foreach (var contact in m_listEntries)
            {
                if (contact.Type <= nMaxType && contact.Version >= nMinKadVersion)
                {
                    if (nIndex >= nRandomStartPos)
                        return contact;
                    else
                        pLastFit = contact;
                }
                nIndex++;
            }

            return pLastFit;
        }

        public void SetAllContactsVerified()
        {
            foreach (var contact in m_listEntries)
            {
                contact.IsIpVerified = true;
            }
        }

        public static bool CheckGlobalIPLimits(uint uIP, ushort uPort, bool bLog)
        {
            // no more than 1 KadID per IP
            uint nSameIPCount = 0;
            s_mapGlobalContactIPs.Lookup(uIP, nSameIPCount);
            if (nSameIPCount >= MAX_CONTACTS_IP)
            {
                if (bLog && thePrefs.GetLogFilteredIPs())
                    AddDebugLogLine(false, "Ignored kad contact (IP=%s:%u) - too many contacts with the same IP (global)", ipstr(ntohl(uIP)), uPort);
                return false;
            }
            //  no more than 10 IPs from the same /24 netmask global, except if its a LANIP (if we don't accept LANIPs they already have been filtered before)
            uint nSameSubnetGlobalCount = 0;
            s_mapGlobalContactSubnets.Lookup(uIP & 0xFFFFFF00, nSameSubnetGlobalCount);
            if (nSameSubnetGlobalCount >= MAX_CONTACTS_SUBNET && !OtherFunctions.IsLANIP((uint)IPAddress.NetworkToHostOrder(uIP)))
            {
                if (bLog && thePrefs.GetLogFilteredIPs())
                    AddDebugLogLine(false, "Ignored kad contact (IP=%s:%u) - too many contacts with the same Subnet (global)", ipstr(ntohl(uIP)), uPort);
                return false;
            }
            return true;
        }

        public bool HasOnlyLANNodes()
        {
            foreach (var contact in m_listEntries)
            {
                if (!OtherFunctions.IsLANIP((uint)IPAddress.NetworkToHostOrder(contact.IPAddress)))
                    return false;
            }
            return true;
        }
    }
}
