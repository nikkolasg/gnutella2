using System;
using System.IO;
using System.Diagnostics;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Struct;
namespace ActionInnocence.P2PScan.Plugins.Gnutella2.G2Packets {
    /*
     * Query acknowledgement packet 
     * in response to a Q2 packet 
     * */
	public class G2PacketQA : G2Packet {

        public GUID guid {get;set;}

        public G2PacketQA(Header packHeader) : base(packHeader) {
            type = G2PacketType.QA;
        }
		public G2PacketQA(GUID g) : base() {
			type = G2PacketType.QA;
			this.guid = g;
		}

		public override int WritePayload(MemoryStream stream) {
            throw new NotSupportedException("G2PacketQA: Write Payload not implemented");
        }

		public override int ReadPayload(MemoryStream stream, int length) {
            //Debug.Assert(GUID.GUID_LEN == length, "G2PacketQA supposed to read " + GUID.GUID_LEN + " but have to read " + length);
			guid = GUID.ReadGUID(stream);
			return (int)guid.bytes.Length;
        }
        /**
         * Should always be 16 (GUID_LEN)
         * */
		public override int getPayloadLength() {
			return (int)guid.bytes.Length;
        }
		protected override string PayloadToString ()
		{
			return "Guid: " + guid.ToString();
		}
    }
    
    public class G2PacketD : G2Packet 
    {
        public NodeAddress Node;
        public short leafCount = 0;
        public G2PacketD(Header h): base(h)
        {
            this.type = G2PacketType.D;
            Node = null;
        }
        public G2PacketD(NodeAddress n,short leafC)
        {
            this.Node = n;
            this.leafCount = leafC;
        }
        public override int ReadPayload(MemoryStream stream, int length)
        {
            //Debug.Assert(length == NodeAddress.LEN + sizeof(short), "G2PacketD : supposed to read " + (NodeAddress.LEN + sizeof(short)) + " but has to read " + length);
            Node = NodeAddress.ReadNodeAddress(stream);
            length = (short)BinaryUtils.getVariableIntLE(stream, 2);
            return NodeAddress.LEN + 2;
        }
        public override int getPayloadLength()
        {
            return NodeAddress.LEN + 2;
        }
        public override int WritePayload(MemoryStream stream)
        {
            byte[] bytes = BitConverter.GetBytes(leafCount);
            Node.Write(stream);
            stream.Write(bytes, 0, bytes.Length);
            return NodeAddress.LEN + 2; 
        }
        protected override string PayloadToString()
        {
            return "Done Hub : " + this.Node.ToString() + " | " + leafCount + " leaves.";
        }
    }

    /**
     * Search Hub, hub to search for more infos
     * */
    public class G2PacketS : G2Packet
    {
        public NodeAddress Node;
        public int Timestamp;
        public G2PacketS(Header h)
            : base(h)
        {
            this.type = G2PacketType.S;
            Node = null;
            Timestamp = -1;
        }
        public override int ReadPayload(MemoryStream stream, int length)
        {
            int timestampLength = (int)(length - NodeAddress.LEN);
            //Debug.Assert(timestampLength == 4 || timestampLength == 0, "G2PacketS  : timestamp 0 or 4 bytes but here has to read " + timestampLength);
            Node = NodeAddress.ReadNodeAddress(stream);
            if (timestampLength == 4)
            {
                Timestamp = (int)BinaryUtils.getVariableIntLE(stream, timestampLength);
            }
           
            return length;
        }
        public override int getPayloadLength()
        {
            int v = 0;
            if (Node != null) v += NodeAddress.LEN;
            if (Timestamp != -1) v += 4;
            return v;
        }
        protected override string PayloadToString()
        {
            return "Search Hub " + this.Node;
        }
        public override int WritePayload(MemoryStream stream)
        {
            throw new NotImplementedException();
        }
    }
    /*
     * CHILD
     * Retry after, specified by a hub
     * to not be quried before the delay given
     * otherwise to be banned
     *
	 */
	public class G2PacketRA : G2Packet {
        public byte[] timeDelay;
        public int Seconds;
        public G2PacketRA(Header h) : base(h) {
            timeDelay = null;
			this.type = G2PacketType.RA;
        }
		public G2PacketRA(byte[] d) :base() {
			this.type = G2PacketType.RA;
			timeDelay = d;
		}

		public override int WritePayload(MemoryStream stream) {
            throw new NotSupportedException("G2PacketRA : WritePayload not implemented");

        }

        public override int ReadPayload(MemoryStream stream, int length) {
			//Debug.Assert (length == 4 || length == 2, "G2PacketRA: Must read " + length + " vs 4 or 2 supposed ");
            timeDelay = new byte[length];
            stream.Read(timeDelay, 0, (int)length);
            int sec = (int)BinaryUtils.getVariableIntLE(timeDelay, (int)length);
            return length;
        }

        public override int getPayloadLength()
        {
			return (int)timeDelay.Length;
        }
		protected override string PayloadToString ()
		{
			return "";
		}
    }

}
