using System;
using System.Collections.Generic;
using System.Threading;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Search;
using ActionInnocence.P2PScan.Plugins.Gnutella2.G2Packets;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Struct;
namespace ActionInnocence.P2PScan.Plugins.Gnutella2
{
	/**
	 * THread that will process all actions to take
	 * => responds to incoming message
	 * => Send new message to peers
	 * */
	public class ProcessingThread
	{

		private static ProcessingThread instance ;
		public static ProcessingThread Instance {
			get {
				if (instance == null)
					instance = new ProcessingThread ();
				return instance;
			}
		}

		private G2Network network;
		private GHubCache cache;
		private G2SearchManager SearchManager;
		private Thread processThread;
		private bool continueProcess = true;

		public ProcessingThread ()
		{
			network = G2Network.Instance;
			cache = GHubCache.Instance;
			SearchManager = G2SearchManager.Instance;
			processThread = new Thread (new ThreadStart (Process));
            processThread.Name = "Processing Thread ";

		}
		public void Start() {
			processThread.Start ();
		}
		public void Stop() {
			lock (this) {
				continueProcess = false;
				network.NewActionAvailable (); // to wake up the thread
			}

		}
		private void Process()
		{
			while (continueProcess) {
				// wait 'till there is something to do
				network.WaitNewActions ();
                if (!continueProcess)
                    break;

				// check actions to take for each connected peers 
				// TO UPGRADE TO MORE EFFIENCY VERSION
				foreach (NodePeer hub in cache.ConnectedHubs) {
					//if new message received
					OnNewMessage (hub);
					// HERE put search actions
				}

			}
			G2Log.Write("ProcessingThread : Stopping thread ...");
		}
		/**
		 * CHeck incoming message for this peer, and push a response if needed
		 * */
		private void OnNewMessage(NodePeer p) {
			G2Packet pack = null;
			G2Packet response = null;
			while ((pack = p.Buffer.PollPacketToReceive ()) != null) {
				
				response = HandlePacket (p,pack); // network related packets (ping/pong/etc)
				if(response != null) {
					p.SendPacket (response);
					response = null;
				}

                if (pack.type == G2PacketType.QA || pack.type == G2PacketType.QH2)
                {// search related packets
                    SearchManager.EnqueueResultPacket(p, pack);
                    continue;
                }
				pack = null;
			}
		}
        public G2Packet HandlePacket(NodePeer p, G2Packet pack)
        {
            switch (pack.type)
            {
                case G2PacketType.PI:

                    return HandlePacketPI(p, pack as G2PacketPI);
                   
                case G2PacketType.UPROC:
                    return HandlePacketUPROC(p, pack as G2PacketUPROC);
                    
                case G2PacketType.LNI:
                    return HandlePacketLNI(p, pack as G2PacketLNI);
                case G2PacketType.KHL:
                    return HandlePacketKHL(p, pack as G2PacketKHL);
                case G2PacketType.QA:
                    return HandlePacketQA(p, pack as G2PacketQA);
                default:
                    return HandleDefault(p, pack);
            }
        }
        // parse the many hubs data there are in a ack packet
        private G2Packet HandlePacketQA(NodePeer p, G2PacketQA pack)
        {
            foreach (G2Packet child in pack.children)
            {
                if(child.type == G2PacketType.S) // search hubs data
                {
                    G2PacketS s = child as G2PacketS;
                    if(s == null) continue;
                    
                    if(s.Timestamp != -1) {
                        DateTime lastSeen = BinaryUtils.UnixTimeStampToDateTime(s.Timestamp);
                        cache.AddHub(new NodePeer(s.Node.ipv4, s.Node.port,lastSeen,true));
                    }
                    else
                        cache.AddHub(new NodePeer(s.Node.ipv4, s.Node.port,DateTime.Now, true));
                        
                }
                else if(child.type == G2PacketType.RA)
                {
                    G2PacketRA ra = child as G2PacketRA;
                    if (ra == null || ra.Seconds == 0) continue;
                    p.DontQueryBefore(ra.Seconds * 1000);
                }
                else if (child.type == G2PacketType.D)
                {
                    G2PacketD d = child as G2PacketD;
                    if (d.Node != null)
                        cache.AddHub(new NodePeer(d.Node, true));
                }
            }
            return null;
        }
        /** 
         * Parse the neighbours hubs contained in this packet
         * and adds them to the cache
         * */
        private G2Packet HandlePacketKHL(NodePeer p, G2PacketKHL pack)
        {
            foreach (G2Packet child in pack.children)
            {
                if (child.type != G2PacketType.NH)
                    continue;

                G2PacketNH nh = child as G2PacketNH;
                if (nh != null && nh.node != null)
                {
                    GHubCache.Instance.AddHub(new NodePeer(nh.node,true));

                }
                    
            }
            return null;

        }

        private G2Packet HandlePacketUPROC(NodePeer p, G2PacketUPROC pack)
        {
            G2UserProfile profile = Settings.SmartUserProfile();

            G2Packet resp = new G2PacketUPROD();
            resp.AddChild(new G2PacketXML(profile));
            resp.FinalizePacket();
            return resp;
        }


        /**
         * Analyse packet and return a packet to send (if there is one)
         * or null
         * */

        private G2Packet HandleDefault(NodePeer p,G2Packet pack)
        {
            return null;
        }
        private G2Packet HandlePacketLNI(NodePeer peer,G2PacketLNI pack)
        {
            G2Packet p = pack.getFirstChildPacket(G2PacketType.NA);
            if (p != null)
                peer.ListeningNode = ((G2PacketNA)p).node;

            p = pack.getFirstChildPacket(G2PacketType.GU);
            if (p != null)
                peer.Guid = ((G2PacketGU)p).nodeGuid;

            // can handle vendor code etc etc
            return null;
        }
        private G2Packet HandlePacketPI(NodePeer p,G2PacketPI pack)
        {
            p.ResetPingTimer();
            G2Packet udp = pack.getFirstChildPacket(G2PacketType.UDP);
            G2Packet response = new G2PacketPO();
            // PING relayed but we dont act as hub for now
            if (udp != null)
            {

            }
            response.FinalizePacket();
            return response;

        }
	}
}

