using System;
using System.IO;
using System.Linq;
using System.Net;
using ActionInnocence.P2PScan.Plugins.Gnutella2.G2Packets;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Struct;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Network;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Search;
namespace ActionInnocence.P2PScan.Plugins.Gnutella2
{
	public class G2PacketTest
	{
		public string fileToRead { get; set;}
		public G2PacketTest (string f)
		{
			fileToRead = f;
		}


		public void ReadPackets() 
		{
			using (StreamReader fileStream = new StreamReader(fileToRead))
			{
				var str = fileStream.ReadToEnd ();
				G2Log.Write ("File : " + str);
				byte[] bytes = StringToByteArray (str);

				NodePeer p = new NodePeer (IPAddress.Parse ("127.0.0.1"), 16546, 0,false);
				G2PacketReader reader = new G2PacketReader (p);
				reader.Read (bytes, bytes.Length);
				G2Log.Write ("G2PacketTest: ReadPacket file " + fileToRead);
				G2Packet pack = p.Buffer.PollPacketToReceive ();
				G2Log.Write(pack.ToString ());
				//if(pack.type == G2PacketType.LNI) testLNI (pack);
			}
		}

		public void testReader() {
			G2Network.Instance.SelfAddress = System.Net.IPAddress.Parse("127.0.0.1");
            G2Packet lni = Settings.SmartLNIPacket();
			G2Packet na = new G2PacketNA(new NodeAddress(System.Net.IPAddress.Parse("127.0.0.1"),6345));
			for(int i = 0; i < 300; i++){
				lni.AddChild(na);
			}
			lni.FinalizePacket ();
			G2Log.Write (lni.ToString ());
			ByteBuffer b = lni.ToBuffer();
			G2PacketReader reader = new G2PacketReader (new NodePeer (System.Net.IPAddress.Parse ("127.0.0.1"), 6346,0,false));
			int nb = 3;
			byte[][] bytes = new byte[nb][];
			int start = 0;
			int div = b.Length / nb;
			for (int i = 0; i < nb; i++) {
				if (i == nb - 1)
					div += b.Length % nb;
				bytes [i] = new byte[div];
				Array.Copy (b.Bytes, start, bytes [i], 0, div);
				start += div;
			}


			for (int i = 0; i < nb; i++) {

				bool enough = reader.Read (bytes [i],bytes[i].Length);
				if (enough) {
					G2Log.Write("PacketReader Test Success");
					break;
				}

			}
            G2Packet lni2 = Settings.SmartLNIPacket();
			ByteBuffer b2 = lni2.ToBuffer ();
			bool succ = reader.Read (b2.Bytes, b2.DataOffset);
			if (succ)
				G2Log.Write ("PacketReader Test Unit Packet Success");
			else
				G2Log.Write ("PacketReader Test Unit Packet FAILED");


			b.Append (b2);
			succ = reader.Read (b.Bytes, b.DataOffset);
			if (succ)
				G2Log.Write ("PacketReader Test Sequential Packet Success");
			else
				G2Log.Write ("PacketReader TEst Sequential Packet FAILED");
		}

		public void testLNI(G2Packet packTest) {

			G2PacketLNI rLNI = (G2PacketLNI)packTest;
			G2PacketGU rGU = (G2PacketGU) rLNI.getFirstChildPacket (G2PacketType.GU);
			G2PacketNA rNA = (G2PacketNA) rLNI.getFirstChildPacket (G2PacketType.NA);
			G2PacketV rV = (G2PacketV)rLNI.getFirstChildPacket (G2PacketType.V);

			G2Packet lni = new G2PacketLNI();
			lni.AddChild (new G2PacketNA (rNA.node));
			lni.AddChild (new G2PacketGU (rGU.nodeGuid));
			lni.AddChild (new G2PacketV (rV.Str));
			lni.FinalizePacket ();
			G2Log.Write(lni.ToString());
			MemoryStream s1 = new MemoryStream ((int)rLNI.getTotalPacketLength ());
			MemoryStream s2 = new MemoryStream ((int)lni.getTotalPacketLength ());
			rLNI.Write (s1);
			lni.Write (s2);

			byte[] b1 = s1.ToArray ();
			byte[] b2 = s2.ToArray ();

			if (b1.Length != b2.Length) {
				G2Log.Write (" NOT EQUAL");
				return;
			}
			for (int i = 0; i < b1.Length; i++) {
				if (b1 [i] != b2 [i]) {
					G2Log.Write ("NOT EQUAL");
					return;
				}
			}
			G2Log.Write ("EQUAL !!");

		}
		public static byte[] StringToByteArray(string hex) {
			
			hex = hex.TrimEnd ('\n', '\r');
			int NumberChars = hex.Length;
			byte[] bytes = new byte[NumberChars / 2];
			for (int i = 0; i < NumberChars; i += 2)
				bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
			return bytes;
		}
		public void PrintStatistics()
		{

		}
	}
}