using System;
using System.IO;
using System.Diagnostics;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Struct;
namespace ActionInnocence.P2PScan.Plugins.Gnutella2.G2Packets
{
	public class G2PacketQKR : G2Packet
	{
		public G2PacketQKR (Header h) : base(h) 
		{
			this.type = G2PacketType.QKR;
		}
		public G2PacketQKR() : base()
		{
			this.type = G2PacketType.QKR;
		}
		public override int ReadPayload (System.IO.MemoryStream stream, int length)
		{
            //Debug.Assert(length == 0, "G2PacketQKR supposed to read nothing but has to read " + length);
			return 0;
		}
		public override int WritePayload (MemoryStream stream)
		{
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
	public class G2PacketQNA : G2PacketNA
	{
		public G2PacketQNA(Header h) : base(h)
		{
			this.type = G2PacketType.QNA;
		}
		public G2PacketQNA(NodeAddress a) : base(a)
		{
			this.type = G2PacketType.QNA;
		}


	}
	public class G2PacketSNA : G2PacketNA
	{
		public G2PacketSNA(Header h) :base(h)
		{
			this.type = G2PacketType.SNA;
		}
		public G2PacketSNA(NodeAddress a) : base(a) {
			this.type = G2PacketType.SNA;
		}
	}

}

