using System;
using System.Collections;
using System.Collections.Generic;
using System.Net;
namespace gnutella2
{
	public class HubCache
	{
		private static HubCache singleton;
		public  SortedList HubList { get; set; }
		private List<NodePeer> connectedHubs;

		private HubCache ()
		{
			HubList = new SortedList (new ReverseDateTimeComparer());
			connectedHubs = new List<NodePeer> ();
		}
    
		public String toString() {
			return "List of cached hubs : \n" + HubList.ToString ();
		}
		public void AddConnectedHub(NodePeer p) {
			lock (connectedHubs) {
				connectedHubs.Add (p);
			}
		}
		public void RemoveConnectedHub(NodePeer p) {
			lock (connectedHubs) {
				connectedHubs.Remove (p);
			}
		}
		public IEnumerable<NodePeer> ConnectedHubs {
			get { 
				IEnumerable<NodePeer> l;
				lock (connectedHubs) {
					l = connectedHubs.ToArray ();
				}
				return l;
			}
		}
		/** Terminates connection with each connected peers */
		public void CloseHubConnections() {
			lock (connectedHubs) {
				Console.WriteLine ("Cache : Closing connections ... ");
				foreach (NodePeer p in connectedHubs) {
					p.connection.Close ();
				}
			}
		}
		/**
		 * Dummy function returning a connected hub from cache */
		public NodePeer getFirstConnectedHub() {
			if (connectedHubs.Count > 0)
				return connectedHubs [0];
			return null;
		}
        public void AddHubs(List<NodePeer> hubs) {
			HubList.AddRange(hubs);
        }
        public void AddHub(NodePeer h) {
			HubList.Add(h);
        }
        public void RemoveHub(NodePeer h) {
			HubList.Remove(h);
        }
        public NodePeer GetHub() {
            foreach (NodePeer h in HubList) {
                if(h.isHub && h.AcceptQuery)
                    return h;
            }
			return null;
        }
		public static HubCache Instance
		{
			get {
				if (singleton == null)
					singleton = new HubCache ();
				return singleton;
			}

		}
	}
}

