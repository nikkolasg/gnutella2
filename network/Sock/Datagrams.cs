using System;
using System.Collections;
using System.Collections.Generic;
using System.Threading;
using System.Net.Sockets;
using System.Net;
using System.IO;
using System.Text;
using ActionInnocence.P2PScan.Plugins.Gnutella2.G2Packets;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Struct;

namespace ActionInnocence.P2PScan.Plugins.Gnutella2.Network
{
	public class Datagrams
	{
		private G2Network network;
		private GHubCache cache;
		private Dictionary<NodePeer,List<G2Packet>> data;
		private Thread Receiver;

		private UdpClient udp;
		public const int BUFF_SIZE = 1024;

		private static Datagrams _instance = null;
		public static Datagrams Instance {
			get {
				if(_instance == null)
					_instance = new Datagrams();
				return _instance;
			}
		}
		private  Datagrams ()
		{
			network = G2Network.Instance;
			cache = GHubCache.Instance;
			data = new Dictionary<NodePeer,List<G2Packet>> ();
			udp = new UdpClient (network.SelfPort);
		}

		public void Start() {
			Receiver = new Thread (new ThreadStart (ReceiveThread));
			Receiver.Start ();
		}
		public void Stop() {
			if (Receiver != null)
				Receiver.Abort ();
			G2Log.Write (ToString ());
		}
		public void ReceiveThread() {
			IPEndPoint any = new IPEndPoint (IPAddress.Any,0);
			byte[] bytes;
			while (true) {
				try{
					bytes = udp.Receive(ref any);
					if (bytes.Length > 0) {
						G2Log.Write("UDP : Received " + bytes.Length + " bytes ..." );
						//StorePacket (bytes, any);
						bytes = new byte[BUFF_SIZE];
					}
					Thread.Sleep (1);
				} catch(IOException e) {
					G2Log.Write ("Datagrams: Receive : " + e.ToString ());
				}
			}
		}

		public override string ToString ()
		{
			StringBuilder b = new StringBuilder ();
			b.Append ("UDP RESULTS ..................");
			foreach (NodePeer p in data.Keys) {
				b.Append ("Packets from " + p.ToString () +"\n");
				foreach(G2Packet pack in data[p]) {
					b.Append (pack.ToString ()+"\n");
				}
			}
			b.Append ("-----------------------------------------");
			return b.ToString ();
		}
	}
}

