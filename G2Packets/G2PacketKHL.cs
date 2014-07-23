using System;
using System.Diagnostics;
namespace ActionInnocence.P2PScan.Plugins.Gnutella2.G2Packets
{
	/**
	 * Packet giving info on neighbour hubs
	 * */
	public class G2PacketKHL : G2Packet
	{
		public G2PacketKHL (Header h) : base(h)
		{
			this.type = G2PacketType.KHL;
		}
		public G2PacketKHL() : base() {
			this.type = G2PacketType.KHL;
		}
		public override int getPayloadLength ()
		{
			return 0;
		}
		protected override string PayloadToString ()
		{
			return "Known Hub List";
		}
		public override int ReadPayload (System.IO.MemoryStream stream, int length)
		{
            //Debug.Assert(length == 0, "G2PacketKHL : supposed read 0 but have to read " + length);
			return 0;
		}
		public override int WritePayload (System.IO.MemoryStream stream)
		{
			throw new NotImplementedException ();
		}
	}

	public class G2PacketTS : G2Packet{
		Int32 TimeStamp;
		public int LEN = 4;
		public G2PacketTS(Header h) : base(h)
		{
			this.type = G2PacketType.TS;
		}
		public G2PacketTS(Int32 time) : base()
		{
			this.type = G2PacketType.TS;
			this.TimeStamp = time;
		}
		public override int ReadPayload (System.IO.MemoryStream stream, int length)
		{
            //Debug.Assert(length == LEN, "G2PacketTS : supposed read " + LEN + " but have to read " + length);
			TimeStamp = (Int32)BinaryUtils.getVariableIntLE (stream, 4);
			return (int)LEN;
		}
		public override int WritePayload (System.IO.MemoryStream stream)
		{
			throw new NotImplementedException ();
		}
		protected override string PayloadToString ()
		{
			return  "TimeStamp = " + TimeStamp.ToString ();
		}
		public override int getPayloadLength ()
		{
			return (int)LEN;
		}

	}

}

