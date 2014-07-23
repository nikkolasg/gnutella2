using System;
using System.Collections;
using System.Collections.Generic;
using System.Net;
using System.IO;

using ActionInnocence.P2PScan.Plugins.Gnutella2.Struct;
namespace ActionInnocence.P2PScan.Plugins.Gnutella2
{
	public class GWebCache
	{
		private static GWebCache instance_ = null;
		public static GWebCache Instance {
			get {
				if (instance_ == null)
					instance_ = new GWebCache ();
				return instance_;
			}
		}


		private const  string sep = "&";
		private const string Net = "net=gnutella2";
		private const string Client = "client=SHLN";
		private const string Version = "version=0.2.2";
		private const string Operation ="get=1";

		private  string[] gwebcacheUrls = { 
            "http://cache.peernix.com/gwc.php?"
			,"http://cache.trillinux.org/g2/bazooka.php?"
			,"http://buriti2.serveftp.com:8080/skulls.php?"
			,"http://tenafly5k.com/gwc/skulls.php?"
			,"http://g2.uk.dyslexicfish.net:33559/"
			,"http://webcache.peerproject.org/"
			,"http://fascination77.free.fr/cachechu/"};

		private const string gwebcacheProvider = "http://gwc.dyndns.info:28960/gwc.php?data=Peers";
		/* where Peer file will be downloaded */
		private const string FileName ="bootstrap.dat";
		private const int RefreshTimeOutMinutes = 10;
        public bool ForceRefresh { get; set; }
		private DateTime LastRefreshed;
		private List<NodePeer> pList; 

		/** EMpty constructor */
		private GWebCache() {
			LastRefreshed = DateTime.MinValue; // never refreshed yet
            ForceRefresh = false;
		}


        public List<NodePeer> PeersList
        {
            get{
                if(pList == null) {
                    pList = new List<NodePeer>();
                }
				pList = GetPeerList();
                return pList;
            }
        }    
		private ArrayList getUrlList() {
			ArrayList constructedUrls = new ArrayList (gwebcacheUrls.Length);
			foreach(string gwcurl in gwebcacheUrls) {
				string baseUrl = 
					gwcurl + Net + sep
					+ Operation + sep 
					+ Client + sep
					+ Version ;
				constructedUrls.Add (baseUrl);
			} 
			return constructedUrls;
		}
		/**
		 * Download the file associated with the GWebCache url
		 * return false if error
		 * true if went well
		 * ATTENTION : true doesn't mean file content is right
		 * server can respond with an error, to check with parse file
		 * */
		private  bool downloadPeerListFile(string url) {

            try
            {
                var client = new WebClient();
                client.DownloadFile(url, FileName);
            }
            catch (Exception e)
            {
                G2Log.Write("GWebCache : " + e.ToString());
            }
            finally
            {
                
            }
			if (fileExists ())
				return true;

			Console.Error.WriteLine ("GWebCache : Could not retrieve Peer file");
			return false;
		}

		private  bool fileExists() {
			if (System.IO.File.Exists (FileName) && new System.IO.FileInfo (FileName).Length > 0) { 
				return true;
			}
			return false;
		}
		/**
		 * Returns wether the file is outdated and must be refreshed i.e. redownlaeded
		 * */
		private bool MustRefresh() {
            FileInfo info = new FileInfo(FileName);
            if (info.LastWriteTime.AddMinutes(RefreshTimeOutMinutes) < DateTime.Now)
                return true;
			if (LastRefreshed.AddMinutes (RefreshTimeOutMinutes) < DateTime.Now)
				return true;
			if (pList != null && pList.Count > 0)
				return false;
			return true;
		}
        /**
         * Basically, retrieve new peer list from gwebcache
         * */
		private  void RefreshPeerList() 
        {
			try{
				System.IO.File.Delete(FileName);
				using(FileStream stream = System.IO.File.Create(FileName)) {};
			} catch (Exception e) {
			}
			LastRefreshed = DateTime.Now;
        }
		public List<NodePeer> GetPeerList() {
			if (!MustRefresh ())
				return pList;
			else
				RefreshPeerList ();

			List<NodePeer> PeerList = null;
			foreach (string url in getUrlList()) {
				G2Log.Write ("GWebCache: Try retrieve from " + url + "...");
				bool DownloadSuccess = downloadPeerListFile (url);
				if (!DownloadSuccess) {
					RefreshPeerList (); // delete file and update datetime
					continue;
				}
				PeerList = ParsePeerList ();
				if (PeerList != null)
					break; 
			}
			return PeerList;
		}
		/**
		 * Return a list of peer in G2 network (simple leaf or ultra peer)
		 * from the file downloaded precedently
		 * */
		private  List<NodePeer> ParsePeerList() 
		{
			if (!fileExists ())
				return null;

			List<NodePeer> peers = new List<NodePeer> ();
			StreamReader file = new StreamReader(FileName);
			string line = "";
			int count = 0;
			while( (line = file.ReadLine()) != null) {
				try {
					NodePeer h = NodePeer.Parse (line);
					peers.Add(h);
					count++;
				} catch (FormatException e) {
					#if DEBUG
					//Console.Error.WriteLine (e);
					#endif
				}
			}
			if (peers.Count == 0) {
				Console.Error.WriteLine ("No peer found");
				return null;
			} 

			G2Log.Write ("GWebCache : Found " + peers.Count + " peers ...");
			return peers;
		}

	}
}

