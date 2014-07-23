using System;
using System.Net;
using System.IO;
using System.Timers;
using System.Collections.Generic;
using System.Collections;
using ActionInnocence.P2PScan.Plugins.Gnutella2.G2Packets;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Network;
namespace ActionInnocence.P2PScan.Plugins.Gnutella2.Struct
{
	public class NodePeer : IEquatable<NodePeer>, IProtocolServers, IComparable<NodePeer>
	{
        /**
         * Ping / Pong related members
         * */
		private Timer PingTimer;
        private DateTime LastPing; // when peers has last responded to our ping / or sent a ping to us.
        public const int MAX_PING_ATTEMPT = 2; // we try to ping the peer x times before killing connection
		public const int PING_TIMEOUT_MS = 1000 * 30; 
        /**
         * Search related members
         * how much time we reserve a peer for a search before asking it again
         * */
        private volatile bool isQueryable_ = true;
        public bool Queryable { get { return isQueryable_; } }
        public const int SEARCH_TIMEOUT = 1000 * 35; // 35 sec
        private Timer SearchTimer ;

        /** Volatile member to tell our threads (hubsocket, timers etc) that we are to stop doing anything */
        private volatile bool closed;
		public IPAddress Address { get; set; }
		public ushort Port { get; set; }

		private DateTime lastSeen_;
		public DateTime LastSeen { get { return lastSeen_; }}

		public bool isHub { get; set; }
		public PacketBuffer Buffer { get; set; }
		public NodeAddress ListeningNode = null; // address where this peers listen for UDP packets
		public GUID Guid = null;



		public HubSocket connection = null;


		public NodePeer(IPAddress addr, ushort port, string t, bool ishub_) {
			Initialize (addr, port);
			setLastSeenDate (t);
			isHub = ishub_;
		}
		public NodePeer (IPAddress addr,ushort port,int t,bool isHub_)
		{
			Initialize (addr, port);
			setLastSeenDate (t);
			isHub = isHub_;
		}
        public NodePeer(IPAddress addr, ushort port, DateTime last, bool isHub_)
        {
            Initialize(addr, port);
            lastSeen_ = last;
            isHub = isHub_;
        }
        /**
         * Constructor used by browse search , not registered in the cache
         * */
        public NodePeer(NodeAddress addr,bool isHub_)
        {
            Initialize(addr.ipv4, addr.port);
            lastSeen_ = DateTime.Now;
            this.isHub = isHub_;
        }

		public void Initialize(IPAddress addr, ushort port) {
			Port = port;
			Address = addr;
			Buffer = new PacketBuffer ();

            SearchTimer = new Timer();
            SearchTimer.Elapsed += new ElapsedEventHandler(QueryStop);
            SearchTimer.AutoReset = false;

            PingTimer = new Timer(PING_TIMEOUT_MS);
            PingTimer.Elapsed += new ElapsedEventHandler(PingTimerOut);
            PingTimer.AutoReset = true;

		}

		private void setLastSeenDate(string t) {
			bool succ = DateTime.TryParse (t, out lastSeen_);
			if (!succ)
				lastSeen_ = DateTime.MinValue;
		}
		/**
		 * Comes from GWC with seconds equals to number of seconds it has last seen this peer
		 * */
		private void setLastSeenDate(int t) {
			lastSeen_ = DateTime.Now.AddSeconds (-t);
		}

		/**
		 * Parse infos from the Gnutella Web Cache response
		 * */
		public static NodePeer Parse(string infos) {
			string[] split_line = infos.Split ('|');
			if (split_line.Length < 3)
				throw new FormatException ("Peer.ParseHandshake() : not a valid format " + infos);
			if (!split_line [0].ToUpper().Equals ("H"))
				throw new FormatException ("PeerParse() : not a host => " + infos);

			IPAddress _ip = IPAddress.Parse(split_line [1].Split (':') [0]);
			ushort _port = Convert.ToUInt16(split_line [1].Split (':') [1]);
			int time = Convert.ToInt32(split_line [2]);
			return new NodePeer (_ip, _port, time,false);

		}

		public override string ToString ()
		{
			string peer = isHub ? "Hub" : "Peer";
			string seen = LastSeen.ToString();
			//connection == null ? "Connection Not Set" : (connection.Connected ? "Connected " : "Non Connected");
			return "[" + peer + ": " + Address + ":" + Port + " " +  seen + " ]";
		}
	

		/**
		 * Connection is made , handshake done
		 * => change the connection type
		 * => register itself in the connectedhub cache
		 * => start timers
		 * => send startup packets
		 * */
		public void AttachTo(GHandshake hand) {
			this.connection = new HubSocket (this, hand.tcp.sock);
            this.connection.Start();
			GHubCache.Instance.AddConnectedHub (this);
			this.isHub = true;
			//StartTimers ();
			SendStartPackets ();
		}
		public void SendPacket(G2Packet pack) {
			pack.FinalizePacket ();
            pack.RemotePeer = this;
			Buffer.PushPacketToSend (pack);
		}
		public void GotPacket(G2Packet pack) {
			Buffer.PushPacketToReceive (pack);
            if(isHub) G2Network.Instance.NewActionAvailable(); // signal processing thread only for connected hubs ( != browsable peer )
		}
		/**
		 * Send LNI And PI packets
		 * */
		public void SendStartPackets() {
			G2Packet lni = Settings.SmartLNIPacket();
			SendPacket (lni);
			G2Packet PI = new G2PacketPI ();
			SendPacket (PI);
		}
		/** Start timer to know if connection is still connected and 
		 * send a PI if long time 
		 * */
		public void StartPingTimer () {

            PingTimer.Start();
		}
		public void PingTimerOut(Object sender,EventArgs e) {
            
                // Peers doesn't respond to our ping , so we close the connection
                if(closed || LastPing.AddMilliseconds(MAX_PING_ATTEMPT*PING_TIMEOUT_MS) < DateTime.Now) 
                {
                    G2Log.Write("PEER Does not respond ... Disconnecting");
                    PingTimer.AutoReset = false;
                    PingTimer.Enabled = false;
                    PingTimer.Stop();
                    GHubCache.Instance.RemoveConnectedHub(this);
                }
                else 
                {   
                    // Here are two cases :
                    // 1 - we just send a new ping to assure us that peer is still up
                    // 2 - we still leave some time to the peer to respond to a previous ping packet
                    SendPacket (new G2PacketPI ());
                }
		}
        public void ResetPingTimer() {
            LastPing = DateTime.Now; // refresh the timestamp
            PingTimer.Start();
        }

        /* Becomes queriable again 
         * */
        private void QueryStop(Object sender,EventArgs e) {

            isQueryable_ = true;
            SearchTimer.Stop();
            G2Log.Write(this.ToString() + " is queryable free again ...");
        }

		public void Close() {
            if (closed) return;
			// we haven't done a handshake or it is a leaf
			if (connection == null)
				TCPConnection.CloseConnection (this);
			else
			    connection.Close();
            this.Buffer.Clear();
            this.SearchTimer.Stop();
            this.PingTimer.Stop();
            this.closed = true;
		}

        /**
         * Call this when u dont want this peer to be queried again 
         * before a certain amount of time in ms
         * set the isQueriable to false
         * */
        public void DontQueryBefore(int ms)
        {
            SearchTimer.Interval = ms;
            SearchTimer.Start();

            this.isQueryable_ = false;
        }

		public bool Equals(NodePeer p) {
			if (!p.Address.Equals (this.Address))
				return false;
			if (!p.Port.Equals (this.Port))
				return false;
			return true;
		}
		public override bool Equals(Object p) {
			if (p == null)
				return false;
			if (p.GetType () != this.GetType ())
				return false;
		
			return Equals ((NodePeer)p);
		}

		public override int GetHashCode() {
			return this.Address.GetHashCode() + this.Port.GetHashCode();
		}
        public int CompareTo(NodePeer p)
        {
            if (this.lastSeen_ < p.lastSeen_)
                return -1;
            else if (this.lastSeen_ > p.lastSeen_)
                return +1;
            else
            {
                if (Equals(p))
                    return 0;
                return this.Address.ToString().CompareTo(p.Address.ToString()); // order by address number ...
            }

        }
        string IProtocolServers.GetInfoServer()
        {
            return "";
        }

        string IProtocolServers.GetIpAddress()
        {
            return this.Address.ToString();
        }

        string IProtocolServers.GetMessageServer()
        {
            return "";
        }

        int IProtocolServers.GetPort()
        {
            return (int)this.Port;
        }

        string IProtocolServers.GetServerName()
        {
            return "";
        }
    }
	public class NodePeerComparer : IComparer<NodePeer> {
		public int Compare(NodePeer a, NodePeer b) {
			if (a.Equals (b))
				return 0;
			int date = -a.LastSeen.CompareTo (b.LastSeen); // return the most recent peers
			if (date == 0)
				return -1; // always put the first added  like the most recent
			return date; // order according to their respective date
		}
	}
}

