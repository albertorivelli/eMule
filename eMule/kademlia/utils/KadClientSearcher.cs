using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Kademlia
{
    public enum EKadClientSearchRes
    {
        KCSR_SUCCEEDED,
        KCSR_NOTFOUND,
        KCSR_TIMEOUT
    }

    public abstract class KadClientSearcher
    {
        public abstract void KadSearchNodeIDByIPResult(EKadClientSearchRes eStatus, byte[] pachNodeID);

        public abstract void KadSearchIPByNodeIDResult(EKadClientSearchRes eStatus, uint dwIP, ushort nPort);
	}
}
