using System;
using System.Collections;
using System.Collections.Generic;
using System.Net;
using System.Linq;
using System.Threading;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Struct;
using ActionInnocence.P2PScan.Plugins.Gnutella2.G2Packets;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Network;
namespace ActionInnocence.P2PScan.Plugins.Gnutella2
{
	public class G2Network
	{

		private static G2Network singleton;

		public IPAddress _selfAddress;
		public  IPAddress SelfAddress { 
			set { 
				_selfAddress = value;
				//StartNetwork (); // as soon
			} 
			get {
				if (_selfAddress == null)
					return null;
				return _selfAddress;
			}
		}
		public GUID SelfGuid { set; get; }

		public ushort SelfPort { get; set; }
		private bool Continue = true;

		private ProcessingThread process;
		private GHubCache cache;
		

		private readonly object NewActionLock = new object();
		private readonly object StopNetworkLock = new object ();

		private G2Network ()
		{
            Settings.ReadSettings();

            SelfPort = (ushort)Settings.Port;
			
			//SelfAddress = GetIP ();
		}
    
		/**
		 * Launch the sockets thread and the processing threads 
		 * */
		public void StartNetwork() {
			G2Log.Write ("G2Network : Starting network processes ... ");
			process = ProcessingThread.Instance;
            
			cache = GHubCache.Instance;
			process.Start();
            // start a few connections 
            for (int i = 0; i < Settings.PEER_DISPATCH_QUERY; i++)
            {
                ConnectToRandomHub();
            }
		}
		private IPAddress GetIP()
		{
			string strHostName = "";
			strHostName = System.Net.Dns.GetHostName();

			IPHostEntry ipEntry = System.Net.Dns.GetHostEntry(strHostName);

			IPAddress[] addr = ipEntry.AddressList;

			return addr[addr.Length - 1];

		}
		/** Calls that when you ewant to end all operations pending on the network
		 * */
		public void StopNetwork() {
			lock(StopNetworkLock) { 
				Continue = false;
				cache.CloseHubConnections ();
				process.Stop ();

				//datagrams.Stop ();

				//Monitor.Pulse (StopNetworkLock);
			}
		}
		/**
		 * The main thread waits for the end of the network operations
		 * */
		public void WaitStopNetwork() {
			lock (StopNetworkLock) {
				while (Continue == true)
					Monitor.Wait (StopNetworkLock);
			}
		}

		// Is there something to do, to process by ProcessingThread ?
		private bool newActions = false;
		public void WaitNewActions() {
			lock (NewActionLock) {
				while (newActions == false)
					Monitor.Wait (NewActionLock);
				newActions = false; // actions will be consumed
			}
		}
		/*
		 * Notify when something has to be analyzed or stg need to be done
		 * IE: peer receiving a packet
		 * OR a search action to dispatch to peers
		 * */
		public void NewActionAvailable() {
			lock (NewActionLock) {
				newActions = true;
				Monitor.Pulse (NewActionLock);
			}
		}


		/**
		 * Call the gwebcache to get a list of peer
		 * try to connect to them , see if it is 
		 * a hub , IF NOT : 
		 * parse the try hubs header 
		 * */
		public NodePeer Bootstrap() {
            
			List<NodePeer> hosts = GWebCache.Instance.PeersList;
			int count = 0;
            foreach(NodePeer p in hosts) {
                GHandshake hand = new GHandshake(p);
				var succ = hand.TryConnect();
				count++;
				// we have a hub
				if (succ) {
					p.AttachTo (hand);
					return p;
				}
				if(GHubCache.Instance.HubCacheSize > 0 && count > 10) {
                    break;
                }
            }
			return null;
        }

		private NodePeer ConnectToHubInCache() {

			List<NodePeer> GoodHubs = GHubCache.Instance.HubCache.Where (foo => foo.isHub && foo.Queryable).ToList ();
			GHandshake hand;
			foreach (NodePeer p in GHubCache.Instance.HubCache) {
				hand = new GHandshake (p);
				var succ = hand.TryConnect ();
				if (succ) { // we established a connection !
					p.AttachTo (hand);
					return p;
				} else {
					cache.RemoveHub (p); // could not connect hub so we remove it from the case
				}
			}
			return null;
		}
		/** TODO prefere call CRAWL packet to get a fresh list 
		 * FIrst check in the cache if we have something
		 * If not , call the Gwebcache service to bootstrap into gnutella2 network
		 * */
		public NodePeer ConnectToRandomHub() {
			NodePeer p = null;
			do {
				while (GHubCache.Instance.HubCacheSize > 0 && (p = ConnectToHubInCache ()) == null ) {}
				if (p != null)
					break;
				p = Bootstrap ();
                if(p == null)
                    GWebCache.Instance.ForceRefresh = true; // if we have bootstrap one time and no answer is good, we force the refresh
			} while (p == null);
			if (p != null)
				G2Log.Write ("G2Network : Connected to " + p.ToString ());
			return p;
		}
        /**
         * Return a HUB that is CONNECTED and that is NOT being queried
         * */
        public NodePeer getQueryableHub()
        {
            foreach (NodePeer p in cache.ConnectedHubs)
            {
                if (p.Queryable)
                    return p;
            }
            return ConnectToRandomHub();

        }
		public static G2Network Instance
		{
			get {
				if (singleton == null)
					singleton = new G2Network ();
				return singleton;
			}

		}

		public  String toString() {
			return "G2Network :\n\t" + GHubCache.Instance.ToString() + "\n\tSelf IP : " +SelfAddress.ToString(); 
		}
	}
}

