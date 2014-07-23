using System;
using System.Diagnostics;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Struct;
namespace ActionInnocence.P2PScan.Plugins.Gnutella2.G2Packets
{
	public class G2PacketQKA : G2Packet
	{
		public G2PacketQKA (Header h) : base(h)
		{
			this.type = G2PacketType.QKA; 
		}
		public G2PacketQKA () : base()
		{
			this.type = G2PacketType.QKA; 
		}
		public override int ReadPayload (System.IO.MemoryStream stream, int length)
		{
            //Debug.Assert(length == 0, "G2PacketQKA supposed to read nothing but has to read " + length);
			return 0;
		}
		public override int WritePayload (System.IO.MemoryStream stream)
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
	public class G2PacketQK : G2Packet
	{
		public QueryKey QKey;
		public G2PacketQK(Header h) : base(h)
		{
			this.type = G2PacketType.QK;
		}
		public G2PacketQK(QueryKey k) : base()
		{
			this.type = G2PacketType.QK;
			QKey = k;
		}
		public override int ReadPayload (System.IO.MemoryStream stream, int length)
		{
            //Debug.Assert(length == QueryKey.LEN, "G2PacketQK supposed to read " + QueryKey.LEN + " but has to read " + length);
			QKey = QueryKey.ReadQueryKey (stream);
			return QueryKey.LEN;
		}
		public override int WritePayload (System.IO.MemoryStream stream)
		{
			QKey.Write (stream);
			return QueryKey.LEN;
		}
		public override int getPayloadLength ()
		{
			return QueryKey.LEN;
		}
		protected override string PayloadToString ()
		{
			return QKey.ToString ();
		}
	}
}

