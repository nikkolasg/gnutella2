using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using System.Timers;
using System.Threading;
using ActionInnocence.P2PScan;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Struct;
using ActionInnocence.P2PScan.Plugins.Gnutella2.G2Packets;

namespace ActionInnocence.P2PScan.Plugins.Gnutella2.Search
{
	public class G2SearchResults
	{

        

        private PacketBuffer Buffer;
        private Object LockBuffer = new Object();

        public G2SearchResultRegrouping SearchRegrouping;
        private Object LockRegrouping = new Object();
        private volatile Boolean ContinueRegrouping;

        private DateTime StartSearchTime;
        private System.Timers.Timer StopSearchTimer;

        private Thread RegroupingThread;

        public string SearchedWord;

        private HashSet<Peer> PeersBrowsed; // contains all peers browsed for this search
        private SearchTransaction Transaction;
		private List<G2PacketQA> ACKPacket;
		private G2SearchManager SearchManager;

        public GUID SearchGUID;

        public volatile int TotalFiles;
        public volatile int SharedTotalFiles;

		public G2SearchResults (SearchTransaction transaction, GUID guid)
		{
			SearchManager = G2SearchManager.Instance;
			ACKPacket = new List<G2PacketQA>();
            Transaction = transaction;
            SearchGUID = guid;
			TotalFiles = 0;
            SharedTotalFiles = 0;
            PeersBrowsed = new HashSet<Peer>();

            SearchedWord = transaction.Keywords[0].KeywordName;
            Buffer = new PacketBuffer();
            SearchRegrouping = new G2SearchResultRegrouping(transaction, 0, false);
            ContinueRegrouping = true;
            StartSearchTime = DateTime.Now;
            StopSearchTimer = new System.Timers.Timer((double)Settings.SEARCH_TIME_OUT_MS);
            StopSearchTimer.AutoReset = false;
            StopSearchTimer.Elapsed += new ElapsedEventHandler(SearchTimeOut);
            

            RegroupingThread = new Thread(new ThreadStart(SearchResultThread));
            
		}
        /**
         * Simply start the analytic thread and the timer
         * */
        public void StartSearchResult()
        {
            StopSearchTimer.Start();
            RegroupingThread.Start();
            G2Log.Write("G2Search Result (" + SearchedWord + ") => STARTING....");
        }
        /**
         * Just store the resquest acknolwdgement received
         * */
        public void SetAcknowledgement(G2PacketQA ack)
        {
            ACKPacket.Add(ack);
        }
        /**
         * When the search must stop
         * */
        private void SearchTimeOut(Object e, EventArgs args)
        {
            ContinueRegrouping = false;
            lock (LockBuffer)
            {
                Monitor.Pulse(LockBuffer); // wakes up the main searh result thread
            }
            if(!RegroupingThread.Join(100))
                RegroupingThread.Abort();
            // pass the results to the upper layer of the application
            lock(LockRegrouping){
                G2SearchManager.Instance.getResultsFromSearchResults(SearchRegrouping.GlobalResult);
            }
            G2SearchManager.Instance.FinishSearch(this);

        }
        private void SearchResultThread()
        {
            while(ContinueRegrouping)
            {
                // take a packet from the buffer
                G2PacketQH2 resultPack = PollResultPacket();
                if (resultPack == null) continue;
                // append it to the global result of this search
                AppendResult(resultPack);
            }
            G2Log.Write("SearchResult (" + SearchedWord + ") STOPPING .....");
        }

		private void AppendResult(G2PacketQH2 res) {
            

			G2Peer g2peer = G2Peer.ParseG2Peer (res);
			if (g2peer == null)
				return;

            /** Create a new search result from the hub ip  and the search transaction */
            SearchResult Results = new SearchResult(new System.Net.IPEndPoint(res.RemotePeer.Address,res.RemotePeer.Port),Transaction);
           
            bool PeerBrowsable = false;
            bool isFirewalled = false;
			int fileCount = 0;
            List<G2File> files = new List<G2File>();
            // add the files to the collections.
            foreach (G2Packet child in res.children)
            {
                if (child.type.Equals(G2PacketType.BH))
                {
                    PeerBrowsable = true;
                    continue;
                }
                if (child.type.Equals(G2PacketType.FW))
                {
                    isFirewalled = true;
                    continue;
                }
                if (!child.type.Equals(G2PacketType.H))
                    continue;
                

                G2PacketH hit = child as G2PacketH;
                G2File file = G2File.ParseHit(hit,FileLocationFound.ServerIndex);
                if (file == null) continue;
                files.Add(file);
                
                fileCount += 1;

            }
            if (fileCount == 0) return; // may have some hosts having only partial file,so no file for the application ...

            Results.PeerCollection.Add(g2peer);
            Peer p = Results.PeerCollection.Find(g2peer); // to get the right object reference may not be needed .. ?
			if (p.Ip.StartsWith ("192.168")) {
				return ;
			}
			foreach (G2File file in files)
            {
                p.Files.Add(file);
                file.PeerDiffusedFiles.Add(p); // ?? necessary or wrong ? 
                Results.FileCollection.Add(file);
            }
            files.Clear();
            files = null;

            TotalFiles += fileCount;


            G2Log.Write("SearchResults : New result from " + res.RemotePeer.ToString() + " for " + SearchedWord + " ==> " + fileCount + " files");

            // try to see if we already have launched an browsing research on this peer or not
            bool notAlreadySearched = !PeersBrowsed.Contains(p);
            // make sure that the browsing will not increase the waiting time of the application for the result
            bool notTooLate = StartSearchTime.AddMilliseconds(Settings.WAIT_TIME_BROWSING_MS)
                < StartSearchTime.AddMilliseconds(Settings.SEARCH_TIME_OUT_MS + 100); // +100 to make sure browsing has time to regroup all 
            bool notConnectedHub = res.RemotePeer.Address.ToString() != p.Ip;

            // verify that we dont search the hub, taht the peer is browsable and NOT firewalled
            // TODO can send a PUSH packet to the hub that will bring the peer to establish a connection to us
            if ( notConnectedHub && PeerBrowsable && !isFirewalled && notAlreadySearched && notTooLate)
            {
                    
                    PeersBrowsed.Add(p);
                    G2BrowseSearch browser = new G2BrowseSearch(p,Results);
                    browser.EndSearch += new BrowseSearchEnd(BrowsingTerminated);
                    browser.StartBrowsing();
            }
            else // sends results to application
            {
                RegroupResults(Results);
            }
            
		}
        /**
         * Get the results from browsing and put it into the sharedFileList folder of the peer.
         * Should maybe change the key to a Peer , but since implementation is unknown
         * no assurance that hashcode will be the same ...
         * */
        public void BrowsingTerminated(Peer peer, SearchResult Results, List<G2PacketQH2> resultPackets)
        {

            if (resultPackets.Count == 0)
            {
                RegroupResults(Results); // if no results from browsing directly sends results
                return;
            }
            Results.PeerCollection.Add(peer);
            Peer p = Results.PeerCollection.Find(peer);
            

            int fileCount = 0;
            // add results !!
            foreach(G2PacketQH2 qh2 in resultPackets)
            {
                foreach(G2Packet child in qh2.children)
                {
                    if (!child.type.Equals(G2PacketType.H))
                        continue;
                    G2PacketH hit = child as G2PacketH;
                    G2File file = G2File.ParseHit(hit,FileLocationFound.SharedLocalComputer);
                    if (file == null) continue;
                    p.SharedLocalfilesList.Add(file);
                    file.PeerDiffusedFiles.Add(p);
                    SharedTotalFiles++;
                    fileCount++;
                }
            }

            G2Log.Write("SearchResults : New Browsing Result from " + p.Ip + ":" + p.Port + " ==> " + p.Files.Count + " files && " + p.SharedLocalfilesList.Count + " shared files ...");

            RegroupResults(Results);

        }
        /**
         * Simply regroup the local result into the searchresultregrouping class
         * */
        private void RegroupResults(SearchResult results)
        {
            lock (LockRegrouping)
            {
                if(SearchRegrouping!= null)
                    SearchRegrouping.AddGlobalResult(results);
            }
        }
        /**
         * Call this when you have a result packet belonging to this search result object
         * */
        public void PushResultPacket(G2PacketQH2 pack)
        {
            lock (LockBuffer)
            {
                Buffer.PushPacketToReceive(pack);
                Monitor.Pulse(LockBuffer);
            }
        }

        private G2PacketQH2 PollResultPacket()
        {
            G2PacketQH2 resultPack;
            lock (LockBuffer)
            {
                // not while because we can terminate the thread with the timer
                if (Buffer.ReceiveBufferCount == 0)
                    Monitor.Wait(LockBuffer);

                G2Packet pack = Buffer.PollPacketToReceive();
                resultPack = pack as G2PacketQH2;
            }
            return resultPack;
        }
        /**
         * Simply set all to null so the Garbage Manager will collect it
         * */
        public void Clean()
        {
            Buffer = null;
            this.SearchRegrouping = null;
            this.PeersBrowsed.Clear();
            this.PeersBrowsed = null;
            this.ACKPacket.Clear();
            this.ACKPacket = null;
           
        }
	}



}
