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

namespace Kademlia
{
    public static class Defines
    {
        public const int SEARCHTOLERANCE = 16777216;
        public const int K = 10;
        public const int KBASE = 4;
        public const int KK = 5;
        public const int ALPHA_QUERY = 3;
        public const int LOG_BASE_EXPONENT = 5;
        public const int HELLO_TIMEOUT = 20;
        public const int SEARCH_JUMPSTART = 1;
        public const int SEARCH_LIFETIME = 45;
        public const int SEARCHFILE_LIFETIME = 45;
        public const int SEARCHKEYWORD_LIFETIME = 45;
        public const int SEARCHNOTES_LIFETIME = 45;
        public const int SEARCHNODE_LIFETIME = 45;
        public const int SEARCHNODECOMP_LIFETIME = 10;
        public const int SEARCHSTOREFILE_LIFETIME = 140;
        public const int SEARCHSTOREKEYWORD_LIFETIME = 140;
        public const int SEARCHSTORENOTES_LIFETIME = 100;
        public const int SEARCHFINDBUDDY_LIFETIME = 100;
        public const int SEARCHFINDSOURCE_LIFETIME = 45;
        public const int SEARCHFILE_TOTAL = 300;
        public const int SEARCHKEYWORD_TOTAL = 300;
        public const int SEARCHNOTES_TOTAL = 50;
        public const int SEARCHSTOREFILE_TOTAL = 10;
        public const int SEARCHSTOREKEYWORD_TOTAL = 10;
        public const int SEARCHSTORENOTES_TOTAL = 10;
        public const int SEARCHNODECOMP_TOTAL = 10;
        public const int SEARCHFINDBUDDY_TOTAL = 10;
        public const int SEARCHFINDSOURCE_TOTAL = 20;
    }
}
