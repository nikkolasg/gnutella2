using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Diagnostics;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Struct;
namespace ActionInnocence.P2PScan.Plugins.Gnutella2.G2Packets {

	public abstract class G2Packet {

        public Header packetHeader {get;set;}
        public List<G2Packet> children {get;set;}

        

        public string type {get;set;}
		public NodePeer RemotePeer;
       // to be called when creating a new packet 
        public G2Packet() {
			children = new List<G2Packet>();
            packetHeader = null;
			RemotePeer = null;
         }
        // to be called when reading packet from stream
        public G2Packet(Header h)  {
			this.children = new List<G2Packet> ();
			this.packetHeader = h;
			RemotePeer = null;
        } 



        
		public void Write(MemoryStream stream) {
            if(packetHeader == null)
               packetHeader = new Header(this);

           packetHeader.Write(stream);
           WriteChildren(stream);
		   WritePayload(stream);

        }
        private void WriteChildren(MemoryStream stream) {
            if (children.Count == 0)
                return;
            foreach(G2Packet child in children)
                child.Write(stream);
            
			WriteTerminationStream(stream);
        }

        private void WriteTerminationStream(MemoryStream stream) {
			if (getPayloadLength () == 0)
				return;
			stream.WriteByte(0);
        }
		/**
		 * This includes CHILDREN packet
		 * + payload of the packet
		 * */
		public int getTotalPayloadLength() {
			int length = getPayloadLength ();
			foreach (G2Packet child in children) {
				length += child.packetHeader.HeaderLength + child.getTotalPayloadLength ();
			}
			// Termination code 
			if (children.Count > 0 && getPayloadLength() > 0)
				length += 1;

			return length;
		}
		/**
		 * This is called when we are done crafting our packet (adding children etc etc)
		 * This creates the header, and set the right values for payload length etc etc
		 * */
		public void FinalizePacket() {

			foreach (G2Packet child in children)
				child.FinalizePacket ();

			packetHeader = new Header(this);
		}
		public int getTotalPacketLength() {
			if (packetHeader == null)
				FinalizePacket ();
			
			return packetHeader.HeaderLength + getTotalPayloadLength();
		}

		public G2Packet getFirstChildPacket(string type) {
			G2Packet p = null;
			foreach (G2Packet cp in children) {
				if (cp.type.Equals (type)) {
					p = cp;
					break;
				}
			}
			return p;
		}

		public abstract int WritePayload(MemoryStream stream);
		public abstract int ReadPayload(MemoryStream stream,int length);
        public abstract int getPayloadLength();
		protected abstract string PayloadToString ();

		public override string ToString() {
			StringBuilder str = new StringBuilder ();
			str.Append("\tHeader ") ;//+ packetHeader.HeaderLength +"\t Payload " + packetHeader.PayloadLength;
			if(packetHeader != null) str.Append("( " + packetHeader.ToString () + " ) ");
			str.Append( "Payload = " + PayloadToString());
			str.Append ("\n");
			foreach (G2Packet child in children)
				str.Append ("\t" + child.ToString () + "\n");

			//str.Append ("Bytes: " + BitConverter.ToString (this.ToBuffer ().bytes) + "\n");
			return str.ToString();
        }

		public ByteBuffer ToBuffer() {
			MemoryStream str = new MemoryStream ((int)getTotalPacketLength ());
			Write (str);
			return new ByteBuffer (str.ToArray ());
		}
        
        
		public void AddChild(G2Packet p) {
			children.Add(p);
        }

		public string getStringFromChildType(string type) {
			G2Packet pack = getFirstChildPacket (type);
			if (pack == null)
				return "";
			G2PacketString strPack = pack as G2PacketString;
			if (strPack == null)
				return "";
			return strPack.Str;
		}

    }
	/**
	 * A default packet when we don't recognize packet sent
	 * i.e. Shaeraza send packet QK ... ??
	 * */
	public class G2PacketDefault : G2Packet
	{
		byte[] payload;
		public G2PacketDefault(Header h) : base(h)
		{
			this.type = G2PacketType.DEFAULT;
			payload = new byte[h.PayloadLength];
		}
		public override int getPayloadLength ()
		{
			return packetHeader.PayloadLength;
		}
		public override int ReadPayload (MemoryStream stream,int length)
		{
			int bRead  = stream.Read (payload, 0, payload.Length);
			return (int)bRead;
		}
		protected override string PayloadToString ()
		{
			return BitConverter.ToString (payload);
		}
		public override int WritePayload (MemoryStream stream)
		{
			throw new NotSupportedException ("G2PacketDefault : Write Payload Not Supported");
		}
	}
	/**
	 * A generic packet containing only a string as a payload
	 * Derived class only have to implement PayloadToString() method.
	 * */
	public abstract class G2PacketString : G2Packet {
		public string Str { get; set; }
		public byte[] bytes {get;set;} // sometimes the parsing depends on other packets so we store bytes 
		public G2PacketString(Header h) : base(h) {
			Str = "";
			bytes = null;
		}
        public G2PacketString() : base()
        {
            // empty because depends on actual implementations
        }
		public G2PacketString(string s ) : base() {
			Str = s;
			bytes = BinaryUtils.getNullTerminatedBytesFromString (Str);
		}
		public override int getPayloadLength ()
		{
			if (bytes == null)
				return 0;
			return (int)bytes.Length;
		}

		public override int ReadPayload (MemoryStream stream, int length)
		{
            if (length == 0)
				return 0; // url can be empty

			bytes = new byte[length];
			int bRead = stream.Read(bytes,0,bytes.Length);
			Str = BinaryUtils.getStringFromBytes(bytes,(int)bRead);
			return (int)bRead;
		}
		public override int WritePayload (MemoryStream stream)
		{
			stream.Write (bytes, 0, bytes.Length);
			return (int)bytes.Length;
		}

	}

}
