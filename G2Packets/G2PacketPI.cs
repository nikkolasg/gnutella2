using System;
using System.IO;
using System.Diagnostics;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Struct;
namespace ActionInnocence.P2PScan.Plugins.Gnutella2.G2Packets
{
	public class G2PacketPI : G2Packet
	{
		public G2PacketPI (Header h ) : base(h)
		{
			this.type = G2PacketType.PI;
		}
		public G2PacketPI() : base()
		{
			this.type = G2PacketType.PI;
		}

		public override int ReadPayload (System.IO.MemoryStream stream, int length)
		{
            //Debug.Assert(length == 0, "G2PacketPI supposed to read nothing but have to read " + length);
			// nothing to do
			return 0;
		}
		public override int WritePayload (System.IO.MemoryStream stream)
		{
			// nothing to do
			return 0;
		}
		public override int getPayloadLength ()
		{
			return 0;
		}
		protected override string PayloadToString ()
		{
			return "";
		}
	}

	public class G2PacketUDP : G2Packet 
	{
		public NodeAddress EndPoint {get;set;}
		public G2PacketUDP(Header h) : base(h)
		{
			this.type = G2PacketType.UDP;
			EndPoint = null;
		}
		public G2PacketUDP(NodeAddress addr) : base()
		{
			EndPoint = addr;
		}
		public override int ReadPayload (System.IO.MemoryStream stream, int length)
		{
            //Debug.Assert(NodeAddress.LEN == length, "G2PacketUDP supposed to read " + NodeAddress.LEN + " but has to read " + length);
			EndPoint = NodeAddress.ReadNodeAddress (stream);
			return 6;
		}
		public override int WritePayload(MemoryStream Stream) {
			return EndPoint.Write (Stream);
		}
		public override int getPayloadLength() {
			return 6;
		}
		protected override string PayloadToString ()
		{
			return EndPoint.ToString();
		}
	}

	public class G2PacketPO : G2Packet
	{
		public G2PacketPO(Header h) : base(h)
		{
			this.type = G2PacketType.PO;
		}
		public G2PacketPO() : base()
		{
			this.type = G2PacketType.PO;
		}
		public override int ReadPayload (System.IO.MemoryStream stream, int length)
		{
            //Debug.Assert(length == 0, "G2PacketPO supposed to read 0 but has to read " + length);
			//nothing to do
			return 0;
		}
		public override int WritePayload (System.IO.MemoryStream stream)
		{
			//nothing to do
			return 0;
		}
		public override int getPayloadLength ()
		{
			return 0;
		}
		protected override string PayloadToString ()
		{
			return "";
		}
	}
}

