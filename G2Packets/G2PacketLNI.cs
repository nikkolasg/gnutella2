using System;
using System.Linq;
using System.Diagnostics;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Struct;
namespace ActionInnocence.P2PScan.Plugins.Gnutella2.G2Packets
{
	public class G2PacketLNI : G2Packet
	{


		public G2PacketLNI (Header h) : base(h)
		{
			this.type = G2PacketType.LNI;
		}
		public G2PacketLNI() {
			this.type = G2PacketType.LNI;
		}
		public override int ReadPayload (System.IO.MemoryStream stream, int length)
		{
            //Debug.Assert(length == 0, " G2PacketLNI supposed read 0 but have to read " + length);
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

	/**
	 * Vendor Code
	 * */
	public class G2PacketV : G2PacketString 
	{
		public G2PacketV(Header h) : base(h) {
			this.type = G2PacketType.V;
		}
		public G2PacketV(string str) :base(str) {
			this.type = G2PacketType.V;
		}
		protected override string PayloadToString ()
		{
			return "Vendor Code : " + Str;
		}
	}

//	public class G2PacketV : G2Packet
//	{
//		public byte[] Code;
//		public int LEN = 4;
//		public G2PacketV(Header h) : base(h)
//		{
//			type = G2PacketType.V;
//			Code = new byte[LEN];
//		}
//		public G2PacketV(byte[] c) :base()
//		{
//			if (c.Length == LEN)
//				Code = c;
//			type = G2PacketType.V;
//		}
//		public override int ReadPayload (System.IO.MemoryStream stream, int length)
//		{
//			int lenRead = stream.Read (Code, 0, LEN);
//			//Debug.Assert (lenRead == LEN,"G2PacketV : Read Payload " + lenRead + " bytes vs " + LEN + " supposed");
//			return (int)LEN;
//		}
//		public override int WritePayload (System.IO.MemoryStream stream)
//		{
//			stream.Write (Code, 0, LEN);
//			return (int)LEN;
//		}
//		public override int getPayloadLength ()
//		{
//			return (int)LEN;
//		}
//		protected override string PayloadToString ()
//		{
//			return "Vendor Code = " + string.Join ("", Code.Select (x => x.ToString ()));
//		}
//
//	}
	/**
	 * Library statistics
	 * */
	public class G2PacketLS : G2Packet {
		public Int32 NumberOfFiles;
		public Int32 SizeKB;
        public const int LEN = 4 * 2; // 2 times 4 four bytes (int32)
		public G2PacketLS(Header h) : base(h) {
			this.type = G2PacketType.LS;
		}
		public G2PacketLS(Int32 n, Int32 s) : base() {
			this.type = G2PacketType.LS;
			NumberOfFiles = n;
			SizeKB = s;
		}
		protected override string PayloadToString ()
		{
			return "# Files = " + NumberOfFiles + " => " + SizeKB + " KB ";
		}
		public override int getPayloadLength ()
		{
			return LEN; 
		}
		public override int ReadPayload (System.IO.MemoryStream stream, int length)
		{
            //Debug.Assert(length == LEN, "G2PacketLS supposed read " + LEN + " but have to read " + length);
			NumberOfFiles = (Int32)BinaryUtils.getVariableIntLE (stream,4);
			SizeKB = (Int32) BinaryUtils.getVariableIntLE (stream,4);
			return LEN;
		}
		public override int WritePayload (System.IO.MemoryStream stream)
		{
			BinaryUtils.WriteVariableIntLE (stream, (int)NumberOfFiles, 4);
			BinaryUtils.WriteVariableIntLE (stream, (int)SizeKB, 4);
			return 4 * 2;
		}
	}
	/**
	 * Hub Status Packet 
	 * */
	public class G2PacketHS : G2Packet {
		public Int16 LeafCount;
		public Int16 MaxLeafCount;
		public const int  LEN = 4;
		public G2PacketHS(Header h) : base(h) {
			type = G2PacketType.HS;
		}
		public G2PacketHS (Int16 count, Int16 maxCount) :base()
		{
			type = G2PacketType.HS;
			LeafCount = count;
			MaxLeafCount = maxCount;
		}
		protected override string PayloadToString ()
		{
			return "Leaf Count = " + LeafCount + " / " + MaxLeafCount;
		}
		public override int ReadPayload (System.IO.MemoryStream stream, int length)
		{
            //Debug.Assert(LEN == length, "G2PacketHS supposed read " + LEN + " but have to read " + length);
			LeafCount = (Int16)BinaryUtils.getVariableIntLE (stream, 2);
			MaxLeafCount = (Int16)BinaryUtils.getVariableIntLE (stream, 2);
			return LEN;
		}
		public override int WritePayload (System.IO.MemoryStream stream)
		{
			BinaryUtils.WriteVariableIntLE (stream, (int)LeafCount, 2);
			BinaryUtils.WriteVariableIntLE (stream, (int)MaxLeafCount, 2);
			return LEN;
		}
		public override int getPayloadLength ()
		{
			return LEN;
		}

	}


	public class G2PacketTLS : G2Packet 
	{
		public G2PacketTLS(Header h) : base(h) {
			this.type = G2PacketType.TLS;
		}
		public G2PacketTLS() : base() {
			this.type = G2PacketType.TLS;
		}
		public override int getPayloadLength ()
		{
			return 0;
		}
		protected override string PayloadToString ()
		{
			return "";
		}
		public override int ReadPayload (System.IO.MemoryStream stream, int length)
		{
            //Debug.Assert(length == 0, " G2PacketTLS supposed to read nothing but have to read " + length);
			return 0;
		}
		public override int WritePayload (System.IO.MemoryStream stream)
		{
			return 0;
		}
	}
    /**
     * Represent a neighbouring hub
     * simply a node address
     * */
	public class G2PacketNH : G2PacketNA {
		public G2PacketNH(Header h) : base(h)
		{
			this.type = G2PacketType.NH;
		}
	}



}

