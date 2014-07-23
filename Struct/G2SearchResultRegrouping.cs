using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ActionInnocence.P2PScan.Plugins.Gnutella2.Struct
{
    public class G2SearchResultRegrouping : SearchResultRegrouping
    {
        public event CompletResultHandler CompletResult;
        private SearchResult result_;

        public SearchResult GlobalResult
        {
            get { return result_; }
        }
        private SearchTransaction searchTransaction_;

        public SearchTransaction SearchTransaction
        {
            get { return searchTransaction_; }
        }
        private int waitResultTermined_;

        public int WaitResultTermined
        {
            get { return waitResultTermined_; }
        }

        private int idTransaction_;

        private bool peerFileCountFilterEnable_;

        public G2SearchResultRegrouping(SearchTransaction searchTransaction, int waitResultTermined, bool peerFileCountFilterEnable) : base(searchTransaction,waitResultTermined,peerFileCountFilterEnable)
        {
            searchTransaction_ = searchTransaction;

            result_ = new SearchResult(null, searchTransaction);
            waitResultTermined_ = waitResultTermined;
            peerFileCountFilterEnable_ = peerFileCountFilterEnable;
        }

        public void Clear()
        {
            result_.Clear();
        }

        public void AddGlobalResult(SearchResult result)
        {
            foreach (Peer peer in result.PeerCollection)
            {
                System.Threading.Thread.Sleep(0);

                if (peer.Files.Count < searchTransaction_.MinFileFromPeerFilter && peerFileCountFilterEnable_) continue;

                // Country filter
                if (searchTransaction_.IpAcceptRangeCollection != null)
                {
                    IpRange iprang = searchTransaction_.IpAcceptRangeCollection.Accept(IpRange.addrToNum(System.Net.IPAddress.Parse(peer.Ip)));

                    if (iprang == null && !peer.Ip.StartsWith("192.168")) continue;
                    if (iprang != null) peer.Country = iprang.CountryCode.ToLower();
                }

                Peer pe = result_.PeerCollection.Find(peer);

                if (pe == null) result_.PeerCollection.Add(peer);
                else
                {
                    foreach (File f in peer.Files)
                    {
                        pe.Files.Add(f);
                    }
                }
            }

            foreach (File file in result.FileCollection)
            {
                System.Threading.Thread.Sleep(0);
                result_.FileCollection.Add(file);
            }

            waitResultTermined_--;
            result = null;

            if (waitResultTermined_ <= 0) if (CompletResult != null) CompletResult(result_);
        }

    }
}
