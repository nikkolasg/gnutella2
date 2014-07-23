using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Collections.Concurrent;
using System.Linq;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Struct;
namespace ActionInnocence.P2PScan.Plugins.Gnutella2
{
	public class GHubCache
	{
		private static GHubCache instance_ = null;
		public static GHubCache Instance { 
			get {
				if (instance_ == null)
					instance_ = new GHubCache ();
				return instance_;
			}
		}
		private  GHubCache ()
		{
			HubCache_ = new SortedSet<NodePeer> (new NodePeerComparer());
			ConnectedHub_ = new HashSet<NodePeer> ();
		}
		private const int MAX_HUB = 100;
		/** hubs are sorted from the more recent one to the oldest one (longst time seen)
		 * */
		private SortedSet<NodePeer> HubCache_;
		public IReadOnlyList<NodePeer> HubCache {
			get { 
				IReadOnlyList<NodePeer> r;
				lock(HubCache_) {
					r = HubCache_.ToList();
				}
				return r;
			}
		}

		private HashSet<NodePeer> ConnectedHub_;
		public IReadOnlyList<NodePeer> ConnectedHubs {
			get {
				IReadOnlyList<NodePeer> r = ConnectedHub_.ToList ();
				return r;
			}
		}
		/**
		 * Check if there is not too much hub in the cache, as it is not needed
		 * and could take up too much memory in long time 
		 * */
		private void EnsureHubCache() {
			if (HubCache_.Count > MAX_HUB) {
				HubCache_ = new SortedSet<NodePeer> (HubCache_.Take (MAX_HUB / 2));
			}
		}
		/**
		 * Add a hub to the global hub cache
		 * */
		public void AddHub(NodePeer hub) {
			lock(HubCache_) {

				bool added = HubCache_.Add (hub);
				
				EnsureHubCache ();
			}
		}
		public void RemoveHub(NodePeer hub) {
			lock (HubCache_) {
				bool succ = HubCache_.Remove (hub);

			}
		}
		public int HubCacheSize {
			get {
				int c = 0; 
				lock(HubCache_) {
					c = HubCache_.Count;
				}
				return c;
			}
		}
		/**
		 * Add the hub to the list of connected hub
		 * and remove it from the list of available hubs
		 * */
		public void AddConnectedHub(NodePeer hub) {
			lock (ConnectedHub_) {
				RemoveHub (hub);
				ConnectedHub_.Add (hub);
				G2Log.Write ("GHUBCACHE : ADDED CONNECTED HUB " + hub.ToString ());
			}
		}
		/** Remove the hub from the connected hub cache and close its connection */
		public void RemoveConnectedHub(NodePeer hub) {
			lock (ConnectedHub_) {
				ConnectedHub_.Remove (hub);
				hub.Close ();
				G2Log.Write ("Cache : Removing hub " + hub.ToString() + " ... ");

			}
		}
		public bool isConnected(NodePeer peer) {
			bool ret = false;
			lock (ConnectedHub_) {
				ret = ConnectedHub_.Contains (peer);
			}
			return ret;
		}
		
		/** Terminates connection with each connected peers */
		public void CloseHubConnections() {
			lock (ConnectedHub_) {
				G2Log.Write ("Cache : Closing  HUB connections ... ");
				foreach (NodePeer p in ConnectedHub_) {
					p.Close ();
				}
				ConnectedHub_.Clear ();
			}
		}

	}
}

