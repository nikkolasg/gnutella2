using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;

using System.Runtime.InteropServices;
using ActionInnocence.P2PScan.Plugins.Gnutella2.G2Packets;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Struct;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Network;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Search;
namespace ActionInnocence.P2PScan.Plugins.Gnutella2.Test
{


	class G2MainTest
	{
		

		public static void Test() {
			G2PacketTest test = new G2PacketTest ("/home/nico/prog/gnutella/hex_good_lni");
			test.ReadPackets ();
			
		}
		public static void TestNetwork() {
			G2Network network = G2Network.Instance;
			network.StartNetwork ();
			NodePeer p = new NodePeer (IPAddress.Parse ("127.0.0.1"), 11000,0,false);
			Socket s = new Socket (AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
			s.Connect (p.Address, p.Port);
			GHandshake hand = new GHandshake (p);
			hand.tcp.sock = s;
			p.AttachTo (hand);
			Thread.Sleep (10000);
			network.StopNetwork ();
		}
		public static void Network() {


//            G2Network network = G2Network.Instance;
//            network.StartNetwork ();

//            //G2SearchManager manager = G2SearchManager.Instance;
//            //manager.NewSearch ("madonna");
////			while (true) {
////				string line = Console.ReadLine ();
////				if (line == null)
////					break;
////				switch(line) :
////			}

//            network.WaitStopNetwork ();
//            G2Log.Write(manager.ToString ());
//            G2Log.Write ("END OF MAIN");
		}
        public static void Metadata()
        {
            MetadataTest.Test();
        }
		public static void Main (string[] args)
		{
			
			//Network ();
			//Test ();
            Metadata();
            Thread.Sleep(1000 * 10);
		}
	}
}
