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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace eMule
{
    public static class OtherFunctions
    {
        public static bool IsLANIP(uint nIP)
        {
            // LAN IP's
            // -------------------------------------------
            //	0.*								"This" Network
            //	10.0.0.0 - 10.255.255.255		Class A
            //	172.16.0.0 - 172.31.255.255		Class B
            //	192.168.0.0 - 192.168.255.255	Class C

            byte nFirst = (byte)nIP;
            byte nSecond = (byte)(nIP >> 8);

            if (nFirst == 192 && nSecond == 168) // check this 1st, because those LANs IPs are mostly spreaded
                return true;

            if (nFirst == 172 && nSecond >= 16 && nSecond <= 31)
                return true;

            if (nFirst == 0 || nFirst == 10)
                return true;

            return false;
        }

        public static byte GetMyConnectOptions(bool bEncryption, bool bCallback)
        {
            // Connect options Tag
            // 4 Reserved (!)
            // 1 Direct Callback
            // 1 CryptLayer Required
            // 1 CryptLayer Requested
            // 1 CryptLayer Supported
            const byte uSupportsCryptLayer = (thePrefs.IsClientCryptLayerSupported() && bEncryption) ? 1 : 0;
            const byte uRequestsCryptLayer = (thePrefs.IsClientCryptLayerRequested() && bEncryption) ? 1 : 0;
            const byte uRequiresCryptLayer = (thePrefs.IsClientCryptLayerRequired() && bEncryption) ? 1 : 0;
            // direct callback is only possible if connected to kad, tcp firewalled and verified UDP open (for example on a full cone NAT)
            const byte uDirectUDPCallback = (bCallback && theApp.IsFirewalled() && Kademlia.Kademlia.IsRunning() && !Kademlia.UDPFirewallTester.IsFirewalledUDP(true) && Kademlia.UDPFirewallTester.IsVerified()) ? 1 : 0;

            const byte byCryptOptions = (uDirectUDPCallback << 3) | (uRequiresCryptLayer << 2) | (uRequestsCryptLayer << 1) | (uSupportsCryptLayer << 0);
            return byCryptOptions;
        }
    }
}
