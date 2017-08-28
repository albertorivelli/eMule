/*
Copyright (C)2003 Barry Dunne (http://www.emule-project.net)
Copyright (C)2007-2008 Merkur ( strEmail.Format("%s@%s", "devteam", "emule-project.net") / http://www.emule-project.net )
 
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
using System.Net;
using Windows.Storage;
using Windows.Storage.Streams;
/**
* The *Zone* is just a node in a binary tree of *Zone*s.
* Each zone is either an internal node or a leaf node.
* Internal nodes have "bin == null" and "subZones[i] != null",
* leaf nodes have "subZones[i] == null" and "bin != null".
* 
* All key unique id's are relative to the center (self), which
* is considered to be 000..000
*/
namespace Kademlia
{
    public class RoutingZone
    {
        private static string m_sFilename;
        private static UInt128 uMe = (ulong)0;

        public long m_tNextBigTimer;
        public long m_tNextSmallTimer;

        private RoutingZone[] m_pSubZones = new RoutingZone[2];
        private RoutingZone m_pSuperZone;
        /**
        * The level indicates what size chunk of the address space
        * this zone is representing. Level 0 is the whole space,
        * level 1 is 1/2 of the space, level 2 is 1/4, etc.
        */
        private uint m_uLevel;
        /**
        * This is the distance in number of zones from the zone at this level
        * that contains the center of the system; distance is wrt the XOR metric.
        */
        private UInt128 m_uZoneIndex;
        /** List of contacts, if this zone is a leaf zone. */
        private RoutingBin m_pBin;

        public RoutingZone()
        {
            // Can only create routing zone after prefs
            // Set our KadID for creating the contact tree
            uMe = Kademlia.GetPrefs().KadID;
            // Set the preference file name.
            m_sFilename = "nodes.dat";
            // Init our root node.
            Init(null, 0, new UInt128(0, 0));
        }

        public RoutingZone(string szFilename)
        {
            // Can only create routing zone after prefs
            // Set our KadID for creating the contact tree
            uMe = Kademlia.GetPrefs().KadID;
            m_sFilename = szFilename;
            // Init our root node.
            Init(null, 0, new UInt128(0, 0));
        }

        public RoutingZone(RoutingZone pSuper_zone, int iLevel, UInt128 uZone_index)
        {
            // Create a new leaf.
            Init(pSuper_zone, iLevel, uZone_index);
        }

        private void Init(RoutingZone pSuper_zone, int iLevel, UInt128 uZone_index)
        {
            // Init all Zone vars
            // Set this zones parent
            m_pSuperZone = pSuper_zone;
            // Set this zones level
            m_uLevel = (uint)iLevel;
            // Set this zones UInt128 Index
            m_uZoneIndex = uZone_index;
            // Mark this zone has having now leafs.
            m_pSubZones[0] = null;
            m_pSubZones[1] = null;
            // Create a new contact bin as this is a leaf.
            m_pBin = new RoutingBin();

            // Set timer so that zones closer to the root are processed earlier.
            m_tNextSmallTimer = DateTime.Now.Ticks + m_uZoneIndex.Get32BitChunk(3);

            // Start this zone.
            StartTimer();

            // If we are initializing the root node, read in our saved contact list.
            if ((m_pSuperZone == null) && (m_sFilename.Length > 0))
                ReadFile();
        }

        ~RoutingZone()
        {
            // Root node is processed first so that we can write our contact list and delete all branches.
            if ((m_pSuperZone == null) && (m_sFilename.Length > 0))
            {
                // Hide contacts in the GUI
                theApp.emuledlg.kademliawnd.StopUpdateContacts();
                WriteFile();
            }
            // If this zone is a leaf, delete our contact bin.
            if (IsLeaf())
            {
                //delete m_pBin;
            }
            else
            {
                // If this zone is branch, delete it's leafs.
                //delete m_pSubZones[0];
                //delete m_pSubZones[1];
            }

            // All branches are deleted, show the contact list in the GUI.
            if (m_pSuperZone == null)
                theApp.emuledlg.kademliawnd.StartUpdateContacts();
        }

        public async void ReadFile(string strSpecialNodesdate = "")
        {
            if (m_pSuperZone != null || (String.IsNullOrEmpty(m_sFilename) && String.IsNullOrEmpty(strSpecialNodesdate)))
            {
                Debug.Assert(false);
                return;
            }

            bool bDoHaveVerifiedContacts = false;

            // Read in the saved contact list.
            try
            {
                StorageFile file;
                file = await ApplicationData.Current.LocalFolder.GetFileAsync(String.IsNullOrEmpty(strSpecialNodesdate) ? m_sFilename : strSpecialNodesdate);
                var buff = await file.OpenSequentialReadAsync();

                using (DataReader dataReader = new DataReader(buff))
                {
                    // Get how many contacts in the saved list.
                    // NOTE: Older clients put the number of contacts here..
                    //       Newer clients always have 0 here to prevent older clients from reading it.
                    uint uNumContacts = dataReader.ReadUInt32();
                    uint uVersion = 0;
                    if (uNumContacts == 0)
                    {
                        var prop = await file.GetBasicPropertiesAsync();
                        if (prop.Size >= 8)
                        {
                            uVersion = dataReader.ReadUInt32();
                            if (uVersion == 3)
                            {
                                uint nBoostrapEdition = dataReader.ReadUInt32();
                                if (nBoostrapEdition == 1)
                                {
                                    // this is a special bootstrap-only nodes.dat, handle it in a seperate reading function
                                    ReadBootstrapNodesDat(file);
                                    return;
                                }
                            }
                            if (uVersion >= 1 && uVersion <= 3) // those version we know, others we ignore
                                uNumContacts = dataReader.ReadUInt32();
                        }
                        else
                            ;// AddDebugLogLine(false, GetResString(IDS_ERR_KADCONTACTS));
                    }

                    if (uNumContacts != 0 && uNumContacts * 25 <= dataReader.UnconsumedBufferLength)
                    {
                        // Hide contact list in the GUI
                        theApp.emuledlg.kademliawnd.StopUpdateContacts();

                        uint uValidContacts = 0;
                        UInt128 uID;
                        while (uNumContacts > 0)
                        {
                            uID = dataReader.ReadUInt128();
                            uint uIP = dataReader.ReadUInt32();
                            ushort uUDPPort = dataReader.ReadUInt16();
                            ushort uTCPPort = dataReader.ReadUInt16();
                            byte byType = 0;

                            byte uContactVersion = 0;
                            if (uVersion >= 1)
                                uContactVersion = dataReader.ReadUInt8();
                            else
                                byType = dataReader.ReadUInt8();

                            KadUDPKey kadUDPKey;
                            bool bVerified = false;
                            if (uVersion >= 2)
                            {
                                kadUDPKey.ReadFromFile(file);
                                bVerified = dataReader.ReadUInt8() != 0;
                                if (bVerified)
                                    bDoHaveVerifiedContacts = true;
                            }
                            // IP Appears valid
                            if (byType < 4)
                            {
                                uint uhostIP = ntohl(uIP);
                                if (::IsGoodIPPort(uhostIP, uUDPPort))
                                {
                                    if (theApp.ipfilter.IsFiltered(uhostIP))
                                    {
                                        if (thePrefs.GetLogFilteredIPs())
                                            AddDebugLogLine(false, "Ignored kad contact (IP=%s:%u)--read known.dat -- - IP filter (%s)", ipstr(uhostIP), uUDPPort, theApp.ipfilter.GetLastHit());
                                    }
                                    else if (uUDPPort == 53 && uContactVersion <= Opcodes.KADEMLIA_VERSION5_48a)  /*No DNS Port without encryption*/
                                    {
                                        if (thePrefs.GetLogFilteredIPs())
                                            AddDebugLogLine(false, "Ignored kad contact (IP=%s:%u)--read known.dat", ipstr(uhostIP), uUDPPort);
                                    }
                                    else
                                    {
                                        // This was not a dead contact, Inc counter if add was successful
                                        if (AddUnfiltered(uID, uIP, uUDPPort, uTCPPort, uContactVersion, kadUDPKey, bVerified, false, true, false))
                                            uValidContacts++;
                                    }
                                }
                            }
                            uNumContacts--;
                        }

                        //AddLogLine(false, GetResString(IDS_KADCONTACTSREAD), uValidContacts);

                        if (!bDoHaveVerifiedContacts)
                        {
                            //DebugLogWarning("No verified contacts found in nodes.dat - might be an old file version. Setting all contacts verified for this time to speed up Kad bootstrapping"));
                            SetAllContactsVerified();
                        }
                    }
                }
            }
            catch (Exception e)
            {
                //DebugLogError("CFileException in CRoutingZone::readFile");
            }

            // Show contact list in GUI
            theApp.emuledlg.kademliawnd.StartUpdateContacts();
        }

        private void ReadBootstrapNodesDat(DataReader dr)
        {
            // Bootstrap versions of nodes.dat files, are in the style of version 1 nodes.dats. The difference is that
            // they will contain more contacts 500-1000 instead 50, and those contacts are not added into the routingtable
            // but used to sent Bootstrap packets too. The advantage is that on a list with a high ratio of dead nodes,
            // we will be able to bootstrap faster than on a normal nodes.dat and more important, if we would deliver
            // a normal nodes.dat with eMule, those 50 nodes would be kinda DDOSed because everyone adds them to their routing
            // table, while with this style, we don't actually add any of the contacts to our routing table in the end and we
            // ask only one of those 1000 contacts one time (well or more untill we find an alive one).
            if (Kademlia.s_liBootstapList.Count > 0)
            {
                Debug.Assert(false);
                return;
            }

            uint uNumContacts = dr.ReadUInt32();
            if (uNumContacts != 0 && uNumContacts * 25 == dr.UnconsumedBufferLength)
            {
                uint uValidContacts = 0;
                UInt128 uID;
                while (uNumContacts > 0)
                {
                    uID = dr.ReadUInt128();
                    uint uIP = dr.ReadUInt32();
                    uint uhostIP = (uint)IPAddress.NetworkToHostOrder(uIP);
                    ushort uUDPPort = dr.ReadUInt16();
                    ushort uTCPPort = dr.ReadUInt16();
                    byte uContactVersion = dr.ReadByte();

                    if (IsGoodIPPort(uhostIP, uUDPPort))
                    {
                        if (theApp.ipfilter.IsFiltered(uhostIP))
                        {
                            if (thePrefs.GetLogFilteredIPs())
                                AddDebugLogLine(false, "Ignored kad contact (IP=%s:%u)--read known.dat -- - IP filter (%s)", ipstr(uhostIP), uUDPPort, theApp.ipfilter.GetLastHit());
                        }
                        else if (uUDPPort == 53 && uContactVersion <= Opcodes.KADEMLIA_VERSION5_48a)
                        {
                            if (thePrefs.GetLogFilteredIPs())
                                AddDebugLogLine(false, "Ignored kad contact (IP=%s:%u)--read known.dat", ipstr(uhostIP), uUDPPort);
                        }
                        else if (uContactVersion > 1) // only kad2 nodes
                        {
                            // we want the 50 nodes closest to our own ID (provides randomness between different users and gets has good chances to get a bootstrap with close Nodes which is a nice start for our routing table) 
                            UInt128 uDistance = uMe;
                            uDistance.Xor(uID);
                            uValidContacts++;
                            // don't bother if we already have 50 and the farest distance is smaller than this contact
                            if (Kademlia.s_liBootstapList.Count < 50 || Kademlia.s_liBootstapList[Kademlia.s_liBootstapList.Count -1].Distance > uDistance)
                            {
                                // look were to put this contact into the proper position
                                bool bInserted = false;
                                Contact pContact = new Contact(uID, uIP, uUDPPort, uTCPPort, uMe, uContactVersion, null, false);
                                for (int i = 0; i < Kademlia.s_liBootstapList.Count; i++)
                                {
                                    if (Kademlia.s_liBootstapList[i].Distance > uDistance)
                                    {
                                        Kademlia.s_liBootstapList.Insert(i, pContact);
                                        bInserted = true;
                                        break;
                                    }
                                }

                                if (!bInserted)
                                {
                                    Debug.Assert(Kademlia.s_liBootstapList.Count < 50);
                                    Kademlia.s_liBootstapList.Add(pContact);
                                }
                                else if (Kademlia.s_liBootstapList.Count > 50)
                                {
                                    Kademlia.s_liBootstapList.RemoveAt(Kademlia.s_liBootstapList.Count - 1);
                                }
                            }
                        }
                    }

                    uNumContacts--;
                }
                //AddLogLine(false, GetResString(IDS_KADCONTACTSREAD), Kademlia.s_liBootstapList.GetCount());
                //DebugLog("Loaded Bootstrap nodes.dat, selected %u out of %u valid contacts", Kademlia.s_liBootstapList.GetCount(), uValidContacts);
            }
        }

        private void WriteFile()
        {
            // don't overwrite a bootstrap nodes.dat with an empty one, if we didn't finished probing
            if (!Kademlia.s_liBootstapList.IsEmpty() && GetNumContacts() == 0)
            {
                DebugLogWarning("Skipped storing nodes.dat, because we have an unfinished bootstrap of the nodes.dat version and no contacts in our routing table");
                return;
            }
            try
            {
                // Write a saved contact list.
                UInt128 uID;
                CSafeBufferedFile file;
                CFileException fexp;
                if (file.Open(m_sFilename, CFile::modeWrite | CFile::modeCreate | CFile::typeBinary | CFile::shareDenyWrite, &fexp))
                {
                    setvbuf(file.m_pStream, NULL, _IOFBF, 32768);

                    // The bootstrap method gets a very nice sample of contacts to save.
                    List<Contact> listContacts = new List<Contact>();
                    GetBootstrapContacts(listContacts, 200);
                    // Start file with 0 to prevent older clients from reading it.
                    file.WriteUInt32(0);
                    // Now tag it with a version which happens to be 2 (1 till 0.48a).
                    file.WriteUInt32(2);
                    // file.WriteUInt32(0) // if we would use version >=3, this would mean that this is a normal nodes.dat
                    file.WriteUInt32((uint)listContacts.Count);
                    foreach (var contact in listContacts)
                    {
                        uID = contact.ClientID;
                        file.WriteUInt128(&uID);
                        file.WriteUInt32(contact.IPAddress);
                        file.WriteUInt16(contact.UDPPort);
                        file.WriteUInt16(contact.TCPPort);
                        file.WriteUInt8(contact.Version);
                        contact.UDPKey.StoreToFile(file);
                        file.WriteUInt8(contact.IsIpVerified ? 1 : 0);
                    }
                    file.Close();
                    //AddDebugLogLine(false, "Wrote %ld contact%s to file.", listContacts.size(), ((listContacts.size() == 1) ? "" : "s"));
                }
                else
                    ;//DebugLogError("Unable to store Kad file: %s", m_sFilename);
            }
            catch (Exception e)
            {
                //AddDebugLogLine(false, "CFileException in CRoutingZone::writeFile");
            }
        }

#if DEBUG
        private void DbgWriteBootstrapFile()
        {
            //DebugLogWarning("Writing special bootstrap nodes.dat - not intended for normal use");
            try
            {
                // Write a saved contact list.
                UInt128 uID;
                CSafeBufferedFile file;
                CFileException fexp;
                if (file.Open(m_sFilename, CFile::modeWrite | CFile::modeCreate | CFile::typeBinary | CFile::shareDenyWrite, &fexp))
                {
                    setvbuf(file.m_pStream, NULL, _IOFBF, 32768);

                    // The bootstrap method gets a very nice sample of contacts to save.
                    ContactMap mapContacts;
                    UInt128 uRandom(UInt128((ULONG)0), 0);
                    UInt128 uDistance = uRandom;
                    uDistance.Xor(uMe);
                    GetClosestTo(2, uRandom, uDistance, 1200, &mapContacts, false, false);
                    // filter out Kad1 nodes
                    for (ContactMap::iterator itContactMap = mapContacts.begin(); itContactMap != mapContacts.end();)
                    {
                        ContactMap::iterator itCurContactMap = itContactMap;
                        ++itContactMap;
                        Contact pContact = itCurContactMap.second;
                        if (pContact.Version <= 1)
                            mapContacts.erase(itCurContactMap);
                    }
                    // Start file with 0 to prevent older clients from reading it.
                    file.WriteUInt32(0);
                    // Now tag it with a version which happens to be 2 (1 till 0.48a).
                    file.WriteUInt32(3);
                    file.WriteUInt32(1); // if we would use version >=3, this would mean that this is not a normal nodes.dat
                    file.WriteUInt32((uint)mapContacts.size());
                    for (ContactMap::const_iterator itContactMap = mapContacts.begin(); itContactMap != mapContacts.end(); ++itContactMap)
                    {
                        Contact pContact = itContactMap.second;
                        uID = pContact.ClientID;
                        file.WriteUInt128(&uID);
                        file.WriteUInt32(pContact.IPAddress);
                        file.WriteUInt16(pContact.UDPPort);
                        file.WriteUInt16(pContact.TCPPort);
                        file.WriteUInt8(pContact.Version);
                    }
                    file.Close();
                    //AddDebugLogLine(false, "Wrote %ld contact to bootstrap file.", mapContacts.size());
                }
                else
                    ; // DebugLogError("Unable to store Kad file: %s", m_sFilename);
            }
            catch (Exception e)
            {
                //AddDebugLogLine(false, "CFileException in CRoutingZone::writeFile");
            }

        }
#else
void CRoutingZone::DbgWriteBootstrapFile() { }
#endif

        private bool CanSplit()
        {
            // Max levels allowed.
            if (m_uLevel >= 127)
                return false;

            // Check if this zone is allowed to split.
            if ((m_uZoneIndex < Defines.KK || m_uLevel < Defines.KBASE) && m_pBin.GetSize() == Defines.K)
                return true;
            return false;
        }

        // Returns true if a contact was added or updated, false if the routing table was not touched
        public bool Add(UInt128 uID, uint uIP, ushort uUDPPort, ushort uTCPPort, byte uVersion, KadUDPKey cUDPKey, bool bIPVerified, bool bUpdate, bool bFromNodesDat, bool bFromHello)
        {
            uint uhostIP = IPAddress.NetworkToHostOrder(uIP);
            if (::IsGoodIPPort(uhostIP, uUDPPort))
            {
                if (!theApp.ipfilter.IsFiltered(uhostIP) && !(uUDPPort == 53 && uVersion <= Opcodes.KADEMLIA_VERSION5_48a)  /*No DNS Port without encryption*/)
                {
                    return AddUnfiltered(uID, uIP, uUDPPort, uTCPPort, uVersion, cUDPKey, bIPVerified, bUpdate, bFromNodesDat, bFromHello);
                }
                else if (::thePrefs.GetLogFilteredIPs() && !(uUDPPort == 53 && uVersion <= Opcodes.KADEMLIA_VERSION5_48a))
                    AddDebugLogLine(false, "Ignored kad contact (IP=%s:%u) - IP filter (%s)", ipstr(uhostIP), uUDPPort, ::theApp.ipfilter->GetLastHit());
                else if (::thePrefs.GetLogFilteredIPs())
                    AddDebugLogLine(false, "Ignored kad contact (IP=%s:%u)", ipstr(uhostIP), uUDPPort);

            }
            else if (::thePrefs.GetLogFilteredIPs())
                AddDebugLogLine(false, "Ignored kad contact (IP=%s) - Bad IP", ipstr(uhostIP));
            return false;
        }

        // Returns true if a contact was added or updated, false if the routing table was not touched
        public bool AddUnfiltered(UInt128 uID, uint uIP, ushort uUDPPort, ushort uTCPPort, byte uVersion, KadUDPKey cUDPKey, ref bool bIPVerified, bool bUpdate, bool bFromNodesDat, bool bFromHello)
        {
            if (uID != uMe && uVersion > 1)
            {
                Contact pContact = new Contact(uID, uIP, uUDPPort, uTCPPort, uVersion, cUDPKey, bIPVerified);
                if (bFromHello)
                    pContact.ReceivedHelloPacket = true;

                if (Add(pContact, bUpdate, bIPVerified))
                {
                    Debug.Assert(!bUpdate);
                    return true;
                }
                else
                {
                    return bUpdate;
                }
            }
            return false;
        }

        public bool Add(Contact pContact, ref bool bUpdate, out bool bOutIPVerified)
        {
            // If we are not a leaf, call add on the correct branch.
            if (!IsLeaf())
            {
                return m_pSubZones[pContact.Distance.GetBitNumber(m_uLevel)].Add(pContact, bUpdate, bOutIPVerified);
            }
            else
            {
                // Do we already have a contact with this KadID?
                Contact pContactUpdate = m_pBin.GetContact(pContact.ClientID);
                if (pContactUpdate != null)
                {
                    if (bUpdate)
                    {
                        if (pContactUpdate.UDPKey.GetKeyValue(theApp.GetPublicIP(false)) != 0
                            && pContactUpdate.UDPKey.GetKeyValue(theApp.GetPublicIP(false)) != pContact.UDPKey.GetKeyValue(theApp.GetPublicIP(false)))
                        {
                            // if our existing contact has a UDPSender-Key (which should be the case for all > = 0.49a clients)
                            // except if our IP has changed recently, we demand that the key is the same as the key we received
                            // from the packet which wants to update this contact in order to make sure this is not a try to
                            // hijack this entry
                            //DebugLogWarning("Kad: Sender (%s) tried to update contact entry but failed to provide the proper sender key (Sent Empty: %s) for the entry (%s) - denying update"
                            //    , ipstr(ntohl(pContactIPAddress)), pContact.UDPKey.GetKeyValue(theApp.GetPublicIP(false)) == 0 ? "Yes" : "No"
                            //    , ipstr(ntohl(pContactUpdate.IPAddress)));
                            bUpdate = false;
                        }
                        else if (pContactUpdate.Version >= Opcodes.KADEMLIA_VERSION1_46c && pContactUpdate.Version < Opcodes.KADEMLIA_VERSION6_49aBETA
                            && pContactUpdate.ReceivedHelloPacket)
                        {
                            // legacy kad2 contacts are allowed only to update their RefreshTimer to avoid having them hijacked/corrupted by an attacker
                            // (kad1 contacts do not have this restriction as they might turn out as kad2 later on)
                            // only exception is if we didn't received a HELLO packet from this client yet
                            if (pContactUpdate.IPAddress == pContact.IPAddress && pContactUpdate.TCPPort == pContact.TCPPort
                                && pContactUpdate.Version == pContact.Version && pContactUpdate.UDPPort == pContact.UDPPort)
                            {
                                Debug.Assert(!pContact.IsIpVerified); // legacy kad2 nodes should be unable to verify their IP on a HELLO
                                bOutIPVerified = pContactUpdate.IsIpVerified;
                                m_pBin.SetAlive(pContactUpdate);
                                theApp.emuledlg.kademliawnd.ContactRef(pContactUpdate);
                                //DEBUG_ONLY(AddDebugLogLine(DLP_VERYLOW, false, "Updated kad contact refreshtimer only for legacy kad2 contact (%s, %u)"
                                //    , ipstr(ntohl(pContactUpdate.IPAddress)), pContactUpdate.Version));
                            }
                            else
                            {
                                //AddDebugLogLine(DLP_DEFAULT, false, "Rejected value update for legacy kad2 contact (%s -> %s, %u -> %u)"
                                //    , ipstr(ntohl(pContactUpdate.IPAddress)), ipstr(ntohl(pContact.IPAddress)), pContactUpdate.Version, pContact.Version);
                                bUpdate = false;
                            }

                        }
                        else
                        {
#if DEBUG
                            // just for outlining, get removed anyway
                            //debug logging stuff - remove later
                            if (pContact.UDPKey.GetKeyValue(theApp.GetPublicIP(false)) == 0)
                            {
                                if (pContact.Version >= Opcodes.KADEMLIA_VERSION6_49aBETA && pContact.Type < 2)
                                    AddDebugLogLine(DLP_LOW, false, "Updating > 0.49a + type < 2 contact without valid key stored %s", ipstr(ntohl(pContact->GetIPAddress())));
                            }
                            else
                                AddDebugLogLine(DLP_VERYLOW, false, "Updating contact, passed key check %s", ipstr(ntohl(pContact.IPAddress)));

                            if (pContactUpdate.Version >= Opcodes.KADEMLIA_VERSION1_46c && pContactUpdate.Version < Opcodes.KADEMLIA_VERSION6_49aBETA)
                            {
                                Debug.Assert(!pContactUpdate.ReceivedHelloPacket);
                                //AddDebugLogLine(DLP_VERYLOW, false, "Accepted update for legacy kad2 contact, because of first HELLO (%s -> %s, %u -> %u)"
                                //    , ipstr(ntohl(pContactUpdate.IPAddress)), ipstr(ntohl(pContact.IPAddress)), pContactUpdate.Version, pContact.Version);
                            }
#endif
                            // All other nodes (Kad1, Kad2 > 0.49a with UDPKey checked or not set, first hello updates) are allowed to do full updates
                            if (m_pBin.ChangeContactIPAddress(pContactUpdate, pContact.IPAddress)
                                && pContact.Version >= pContactUpdate.Version) // do not let Kad1 responses overwrite Kad2 ones
                            {
                                pContactUpdate.UDPPort = pContact.UDPPort;
                                pContactUpdate.TCPPort = pContact.TCPPort;
                                pContactUpdate.Version = pContact.Version;
                                pContactUpdate.UDPKey = pContact.UDPKey;
                                if (!pContactUpdate.IsIpVerified) // don't unset the verified flag (will clear itself on ipchanges)
                                    pContactUpdate.IsIpVerified = pContact.IsIpVerified;
                                bOutIPVerified = pContactUpdate.IsIpVerified;
                                m_pBin.SetAlive(pContactUpdate);
                                theApp.emuledlg.kademliawnd.ContactRef(pContactUpdate);
                                if (pContact.ReceivedHelloPacket)
                                    pContactUpdate.ReceivedHelloPacket = true;
                            }
                            else
                                bUpdate = false;
                        }
                    }
                    return false;
                }
                else if (m_pBin.GetRemaining() > 0)
                {
                    bUpdate = false;
                    // This bin is not full, so add the new contact.
                    if (m_pBin.AddContact(pContact))
                    {
                        // Add was successful, add to the GUI and let contact know it's listed in the gui.
                        if (theApp.emuledlg.kademliawnd.ContactAdd(pContact))
                            pContact.GuiRefs = true;
                        return true;
                    }
                    return false;
                }
                else if (CanSplit())
                {
                    // This bin was full and split, call add on the correct branch.
                    Split();
                    return m_pSubZones[pContact.Distance.GetBitNumber(m_uLevel)].Add(pContact, bUpdate, bOutIPVerified);
                }
                else
                {
                    bUpdate = false;
                    return false;
                }
            }
        }

        public Contact GetContact(UInt128 uID)
        {
            if (IsLeaf())
            {
                return m_pBin.GetContact(uID);
            }
            else
            {
                UInt128 uDistance;
                Kademlia.GetPrefs().GetKadID(&uDistance);
                uDistance.Xor(uID);
                return m_pSubZones[uDistance.GetBitNumber(m_uLevel)].GetContact(uID);
            }
        }

        public Contact GetContact(uint uIP, ushort nPort, bool bTCPPort)
        {
            if (IsLeaf())
            {
                return m_pBin.GetContact(uIP, nPort, bTCPPort);
            }
            else
            {
                Contact pContact = m_pSubZones[0].GetContact(uIP, nPort, bTCPPort);
                return (pContact != null) ? pContact : m_pSubZones[1].GetContact(uIP, nPort, bTCPPort);
            }
        }

        public Contact GetRandomContact(uint nMaxType, uint nMinKadVersion)
        {
            if (IsLeaf())
            {
                return m_pBin.GetRandomContact(nMaxType, nMinKadVersion);
            }
            else
            {
                uint nZone = GetRandomUInt16() % 2;
                Contact pContact = m_pSubZones[nZone].GetRandomContact(nMaxType, nMinKadVersion);
                return (pContact != null) ? pContact : m_pSubZones[nZone == 1 ? 0 : 1].GetRandomContact(nMaxType, nMinKadVersion);
            }
        }

        public void GetClosestTo(uint uMaxType, ref UInt128 uTarget, ref UInt128 uDistance, uint uMaxRequired, ContactMap pmapResult, bool bEmptyFirst = true, bool bInUse = false)
        {
            // If leaf zone, do it here
            if (IsLeaf())
            {
                m_pBin.GetClosestTo(uMaxType, uTarget, uMaxRequired, pmapResult, bEmptyFirst, bInUse);
                return;
            }

            // otherwise, recurse in the closer-to-the-target subzone first
            int iCloser = uDistance.GetBitNumber(m_uLevel);
            m_pSubZones[iCloser].GetClosestTo(uMaxType, uTarget, uDistance, uMaxRequired, pmapResult, bEmptyFirst, bInUse);

            // if still not enough tokens found, recurse in the other subzone too
            if (pmapResult->size() < uMaxRequired)
                m_pSubZones[1 - iCloser].GetClosestTo(uMaxType, uTarget, uDistance, uMaxRequired, pmapResult, false, bInUse);
        }

        public void GetAllEntries(List<Contact> pmapResult, bool bEmptyFirst = true)
        {
            if (IsLeaf())
            {
                m_pBin.GetEntries(pmapResult, bEmptyFirst);
            }
            else
            {
                m_pSubZones[0].GetAllEntries(pmapResult, bEmptyFirst);
                m_pSubZones[1].GetAllEntries(pmapResult, false);
            }
        }

        private void TopDepth(int iDepth, List<Contact> pmapResult, bool bEmptyFirst = true)
        {
            if (IsLeaf())
            {
                m_pBin.GetEntries(pmapResult, bEmptyFirst);
            }
            else if (iDepth <= 0)
            {
                RandomBin(pmapResult, bEmptyFirst);
            }
            else
            {
                m_pSubZones[0].TopDepth(iDepth - 1, pmapResult, bEmptyFirst);
                m_pSubZones[1].TopDepth(iDepth - 1, pmapResult, false);
            }
        }

        private void RandomBin(List<Contact> pmapResult, bool bEmptyFirst = true)
        {
            if (IsLeaf())
                m_pBin.GetEntries(pmapResult, bEmptyFirst);
            else
                m_pSubZones[new Random().Next() & 1].RandomBin(pmapResult, bEmptyFirst);
        }

        private uint GetMaxDepth()
        {
            if (IsLeaf())
                return 0;
            return 1 + Math.Max(m_pSubZones[0].GetMaxDepth(), m_pSubZones[1].GetMaxDepth());
        }

        private void Split()
        {
            StopTimer();

            m_pSubZones[0] = GenSubZone(0);
            m_pSubZones[1] = GenSubZone(1);

            List<Contact> listEntries = new List<Contact>();
            m_pBin.GetEntries(listEntries);
            m_pBin.m_bDontDeleteContacts = true;
            m_pBin = null;

            foreach (var contact in listEntries)
            {
                int iSuperZone = contact.Distance.GetBitNumber(m_uLevel);
                if (!m_pSubZones[iSuperZone].m_pBin.AddContact(contact))
                    ; // delete* itContactList;
            }
        }

        public uint Consolidate()
        {
            uint uMergeCount = 0;
            if (IsLeaf())
                return uMergeCount;
            Debug.Assert(m_pBin == null);
            if (!m_pSubZones[0].IsLeaf())
                uMergeCount += m_pSubZones[0].Consolidate();
            if (!m_pSubZones[1].IsLeaf())
                uMergeCount += m_pSubZones[1].Consolidate();
            if (m_pSubZones[0].IsLeaf() && m_pSubZones[1].IsLeaf() && GetNumContacts() < Defines.K / 2)
            {
                m_pBin = new RoutingBin();
                m_pSubZones[0].StopTimer();
                m_pSubZones[1].StopTimer();

                List<Contact> list0 = new List<Contact>();
                List<Contact> list1 = new List<Contact>();
                m_pSubZones[0].m_pBin.GetEntries(list0);
                m_pSubZones[1].m_pBin.GetEntries(list1);

                m_pSubZones[0].m_pBin.m_bDontDeleteContacts = true;
                m_pSubZones[1].m_pBin.m_bDontDeleteContacts = true;
                m_pSubZones[0] = null;
                m_pSubZones[1] = null;

                foreach (var contact in list0)
                {
                    if (!m_pBin.AddContact(contact))
                        ; // delete* itContactList;
                }
                foreach (var contact in list1)
                {
                    if (!m_pBin.AddContact(contact))
                        ; // delete* itContactList;
                }

                StartTimer();
                uMergeCount++;
            }
            return uMergeCount;
        }

        private bool IsLeaf()
        {
            return (m_pBin != null);
        }

        private RoutingZone GenSubZone(int iSide)
        {
            UInt128 uNewIndex = m_uZoneIndex;
            uNewIndex.ShiftLeft(1);
            if (iSide != 0)
                uNewIndex.Add(1);
            return new RoutingZone(this, m_uLevel + 1, uNewIndex);
        }

        private void StartTimer()
        {
            // Start filling the tree, closest bins first.
            m_tNextBigTimer = DateTime.Now.Ticks + Opcodes.SEC(10);
            Kademlia.AddEvent(this);
        }

        private void StopTimer()
        {
            Kademlia.RemoveEvent(this);
        }

        public bool OnBigTimer()
        {
            if (IsLeaf() && (m_uZoneIndex < Defines.KK || m_uLevel < Defines.KBASE || m_pBin.GetRemaining() >= (Defines.K * .8)))
            {
                RandomLookup();
                return true;
            }

            return false;
        }

        //This is used when we find a leaf and want to know what this sample looks like.
        //We fall back two levels and take a sample to try to minimize any areas of the
        //tree that will give very bad results.
        public uint EstimateCount()
        {
            if (!IsLeaf())
                return 0;
            if (m_uLevel < Defines.KBASE)
                return (uint)(Math.Pow(2.0F, (int)m_uLevel) * Defines.K);
            RoutingZone pCurZone = m_pSuperZone.m_pSuperZone.m_pSuperZone;
            // Find out how full this part of the tree is.
            float fModify = ((float)pCurZone.GetNumContacts()) / (float)(Defines.K * 2);
            // First calculate users assuming the tree is full.
            // Modify count by bin size.
            // Modify count by how full the tree is.

            // LowIDModififier
            // Modify count by assuming 20% of the users are firewalled and can't be a contact for < 0.49b nodes
            // Modify count by actual statistics of Firewalled ratio for >= 0.49b if we are not firewalled ourself
            // Modify count by 40% for >= 0.49b if we are firewalled outself (the actual Firewalled count at this date on kad is 35-55%)
            const float fFirewalledModifyOld = 1.20F;
            float fFirewalledModifyNew = 0;
            if (UDPFirewallTester.IsFirewalledUDP(true))
                fFirewalledModifyNew = 1.40F; // we are firewalled and get get the real statistic, assume 40% firewalled >=0.49b nodes
            else if (Kademlia.GetPrefs().StatsGetFirewalledRatio(true) > 0)
            {
                fFirewalledModifyNew = 1.0F + (Kademlia.GetPrefs().StatsGetFirewalledRatio(true)); // apply the firewalled ratio to the modify
                Debug.Assert(fFirewalledModifyNew > 1.0F && fFirewalledModifyNew < 1.90F);
            }
            float fNewRatio = Kademlia.GetPrefs().KadV8Ratio;
            float fFirewalledModifyTotal = 0;
            if (fNewRatio > 0 && fFirewalledModifyNew > 0) // weigth the old and the new modifier based on how many new contacts we have
                fFirewalledModifyTotal = (fNewRatio * fFirewalledModifyNew) + ((1 - fNewRatio) * fFirewalledModifyOld);
            else
                fFirewalledModifyTotal = fFirewalledModifyOld;
            Debug.Assert(fFirewalledModifyTotal > 1.0F && fFirewalledModifyTotal < 1.90F);

            return (uint)((Math.Pow(2.0F, (int)m_uLevel - 2)) * (float)Defines.K * fModify * fFirewalledModifyTotal);
        }

        public void OnSmallTimer()
        {
            if (!IsLeaf())
                return;

            DateTime tNow = DateTime.Now;
            List<Contact> listEntries = new List<Contact>();
            // Remove dead entries
            m_pBin.GetEntries(listEntries);
            foreach (var contact in listEntries)
            {
                if (contact.Type == 4)
                {
                    if (((contact.ExpireTime > DateTime.MinValue) && (contact.ExpireTime <= tNow)))
                    {
                        if (!contact.InUse())
                        {
                            m_pBin.RemoveContact(contact);
                        }
                        continue;
                    }
                }
                if (contact.ExpireTime == DateTime.MinValue)
                    contact.ExpireTime = tNow;
            }

            Contact pContact = m_pBin.GetOldest();
            if (pContact != null)
            {
                if (pContact.ExpireTime >= tNow || pContact.Type == 4)
                {
                    m_pBin.PushToBottom(pContact);
                    pContact = null;
                }
            }
            if (pContact != null)
            {
                pContact.CheckingType();
                if (pContact.Version >= 6)
                { /*48b*/
                    if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                        DebugSend("KADEMLIA2_HELLO_REQ", pContact.IPAddress, pContact.UDPPort);
                    UInt128 uClientID = pContact.ClientID;
                    Kademlia.GetUDPListener().SendMyDetails(Opcodes.KADEMLIA2_HELLO_REQ, pContact.IPAddress, pContact.UDPPort, pContact.Version, pContact.UDPKey, &uClientID, false);
                    if (pContactVersion >= Opcodes.KADEMLIA_VERSION8_49b)
                    {
                        // FIXME:
                        // This is a bit of a work arround for statistic values. Normally we only count values from incoming HELLO_REQs for
                        // the firewalled statistics in order to get numbers from nodes which have us on their routing table,
                        // however if we send a HELLO due to the timer, the remote node won't send a HELLO_REQ itself anymore (but
                        // a HELLO_RES which we don't count), so count those statistics here. This isn't really accurate, but it should
                        // do fair enough. Maybe improve it later for example by putting a flag into the contact and make the answer count
                        Kademlia.GetPrefs().StatsIncUDPFirewalledNodes(false);
                        Kademlia.GetPrefs().StatsIncTCPFirewalledNodes(false);
                    }
                }
                else if (pContact.Version >= 2/*47a*/)
                {
                    if (thePrefs.GetDebugClientKadUDPLevel() > 0)
                        DebugSend("KADEMLIA2_HELLO_REQ", pContact.IPAddress, pContact.UDPPort);
                    Kademlia.GetUDPListener().SendMyDetails(Opcodes.KADEMLIA2_HELLO_REQ, pContact.IPAddress, pContact.UDPPort, pContact.Version, 0, null, false);
                    Debug.Assert(new KadUDPKey(0) == pContact.UDPKey);
                }
                else
                    Debug.Assert(false);
            }
        }

        private void RandomLookup()
        {
            // Look-up a random client in this zone
            UInt128 uPrefix = m_uZoneIndex;
            uPrefix.ShiftLeft(128 - m_uLevel);
            UInt128 uRandom(uPrefix, m_uLevel);
            uRandom.Xor(uMe);
            SearchManager.FindNode(uRandom, false);
        }

        public uint GetNumContacts()
        {
            if (IsLeaf())
                return m_pBin.GetSize();
            else
                return m_pSubZones[0].GetNumContacts() + m_pSubZones[1].GetNumContacts();
        }

        public void GetNumContacts(ref uint nInOutContacts, ref uint nInOutFilteredContacts, byte byMinVersion)
        {
            if (IsLeaf())
            {
                m_pBin.GetNumContacts(ref nInOutContacts, ref nInOutFilteredContacts, byMinVersion);
            }
            else
            {
                m_pSubZones[0].GetNumContacts(ref nInOutContacts, ref nInOutFilteredContacts, byMinVersion);
                m_pSubZones[1].GetNumContacts(ref nInOutContacts, ref nInOutFilteredContacts, byMinVersion);
            }
        }

        public uint GetBootstrapContacts(List<Contact> plistResult, uint uMaxRequired)
        {
            Debug.Assert(m_pSuperZone == null);
            plistResult.Clear();
            uint uRetVal = 0;
            try
            {
                List<Contact> top = new List<Contact>();
                TopDepth(Defines.LOG_BASE_EXPONENT, top);
                if (top.Count > 0)
                {
                    foreach (var contact in top)
                    {
                        plistResult.Add(contact);
                        uRetVal++;
                        if (uRetVal == uMaxRequired)
                            break;
                    }
                }
            }
            catch (Exception)
            {
                //AddDebugLogLine(false, "Exception in CRoutingZone::getBoostStrapContacts");
            }
            return uRetVal;
        }

        public bool VerifyContact(ref UInt128 uID, uint uIP)
        {
            Contact pContact = GetContact(uID);
            if (pContact == null)
            {
                return false;
            }
            else if (uIP != pContact.IPAddress)
            {
                return false;
            }
            else
            {
                if (pContact.IsIpVerified)
                    ; // DebugLogWarning("Kad: VerifyContact: Sender already verified (sender: %s)", ipstr(ntohl(uIP));
            else
            {
                    pContact.IsIpVerified = true;
                    theApp.emuledlg.kademliawnd.ContactRef(pContact);
                }
                return true;
            }
        }

        private void SetAllContactsVerified()
        {
            if (IsLeaf())
            {
                m_pBin.SetAllContactsVerified();
            }
            else
            {
                m_pSubZones[0].SetAllContactsVerified();
                m_pSubZones[1].SetAllContactsVerified();
            }
        }

        public bool IsAcceptableContact(Contact pToCheck)
        {
            // Check if we know a conact with the same ID or IP but notmatching IP/ID and other limitations, similar checks like when adding a node to the table except allowing duplicates
            // we use this to check KADEMLIA_RES routing answers on searches
            if (pToCheck.Version <= 1)    // No Kad1 Contacts allowed
                return false;

            Contact pDuplicate = GetContact(pToCheck.ClientID);
            if (pDuplicate != null)
            {
                if (pDuplicate.IsIpVerified
                    && (pDuplicate.IPAddress != pToCheck.IPAddress || pDuplicate.UDPPort != pToCheck.UDPPort))
                {
                    // already existing verfied node with different IP
                    return false;
                }
                else
                {
                    return true; // node exists already in our routing table, thats fine
                }
            }
            // if the node is not yet know, check if we out IP limitations would hit
#if DEBUG
            return RoutingBin.CheckGlobalIPLimits(pToCheck.IPAddress, pToCheck.UDPPort, true);
#else
            return RoutingBin.CheckGlobalIPLimits(pToCheck.IPAddress, pToCheck.UDPPort, false);
#endif
        }

        public bool HasOnlyLANNodes()
        {
            if (IsLeaf())
                return m_pBin.HasOnlyLANNodes();
            else
                return m_pSubZones[0].HasOnlyLANNodes() && m_pSubZones[1].HasOnlyLANNodes();
        }
    }
}
