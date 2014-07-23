using System;
using System.IO;
using System.Diagnostics;
using System.Linq;
using System.Text;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Struct;
namespace ActionInnocence.P2PScan.Plugins.Gnutella2.G2Packets {
    /**
     * Search result packet
     * contains many children
     * here searchguid is the guid of the requested search
     * */
    public class G2PacketQH2 : G2Packet {
        public byte hopCount {get;set;}
        public GUID searchGuid {get;set;}       

        public G2PacketQH2(Header h) : base(h) {
			this.type = G2PacketType.QH2;
			this.hopCount = 0;
			this.searchGuid = null;
        }
		public G2PacketQH2(byte h,GUID g) : base() {
			this.type = G2PacketType.QH2;
			this.hopCount = h;
			this.searchGuid = g;
		}
		public override int WritePayload(MemoryStream stream) {
            throw new NotSupportedException("QH2 Packet : Write Payload not implemented");
        }
        public override int ReadPayload(MemoryStream stream,int length) {
			hopCount = Convert.ToByte(stream.ReadByte());
            searchGuid = GUID.ReadGUID(stream);
			//Debug.Assert (length == 1 + GUID.GUID_LEN, "QH2 ReadPayload : Length supposed " + (1+GUID.GUID_LEN) + " vs actually has to read " + length);
			return (int) (1 + searchGuid.bytes.Length);
        }
        public override int getPayloadLength() {
            return 1 + GUID.GUID_LEN;
        }
		protected override string PayloadToString ()
		{
			return "Hop: " + hopCount + " | GUID: " + searchGuid.ToString();
		}
    }

    /*
     * GUID of sending node
     * */
    public class G2PacketGU : G2Packet {
        public GUID nodeGuid {get;set;}

        public G2PacketGU(Header h) : base(h) {
			type = G2PacketType.GU;
        }
		public G2PacketGU(GUID g) : base() {
			type = G2PacketType.GU;
			nodeGuid = g;
		}
		public override int WritePayload(MemoryStream stream) {
			stream.Write (nodeGuid.bytes, 0, nodeGuid.bytes.Length);
			return (int)nodeGuid.bytes.Length;
        }
        public override int ReadPayload(MemoryStream stream,int length) {
            //Debug.Assert(length == GUID.GUID_LEN, "G2PacketGU supposed to read " + GUID.GUID_LEN + " but has to read " + length);
            nodeGuid = GUID.ReadGUID(stream);
			return (int)nodeGuid.bytes.Length;
        }
        public override int getPayloadLength() {
            return GUID.GUID_LEN;
        }
		protected override string PayloadToString ()
		{
			return "GUID: " + nodeGuid.ToString ();
		}
    }
    /**
     * Address of sender
     * */
    public class G2PacketNA : G2Packet {
        public NodeAddress node;
        
        public G2PacketNA(Header h) : base(h) {
            type = G2PacketType.NA;
			node = null;
        }
		public G2PacketNA(NodeAddress n) : base() {
			type = G2PacketType.NA;
			node = n;
		}
        public override int WritePayload(MemoryStream stream) {
			node.Write (stream);
			return NodeAddress.LEN;
        }

        public override int ReadPayload(MemoryStream stream, int length) {
            //Debug.Assert(NodeAddress.LEN == length, "G2PacketNA supposed to read " + NodeAddress.LEN + " but have to read " + length);
            node = NodeAddress.ReadNodeAddress(stream);
			if (node == null) return 0;
			return NodeAddress.LEN;
        }
        // 4 byte ip + 2 byte port
        public override int getPayloadLength() {
			return NodeAddress.LEN;
        }
		protected override string PayloadToString ()
		{
			return "NodeAddress: " + node.ToString();
		}
    }
    /**
     * If packet present, user browse flag enable.
     * possible to browse the user
     */
    public class G2PacketBUP : G2Packet {
        public G2PacketBUP(Header h) : base(h) {
			this.type = G2PacketType.BUP;
        }
		public G2PacketBUP() : base() {
			this.type = G2PacketType.BUP;
		}
        public override int WritePayload(MemoryStream stream) {
            throw new NotSupportedException("BUP packet : Write Payload not implemented");
        }
        public override int ReadPayload(MemoryStream stream, int length) {
            //Debug.Assert(length == 0, "G2PacketBUP supposed to read nothing but has to read " + length);
			return 0;
        }
        public override int getPayloadLength() {
            return 0;
        }
		protected override string PayloadToString ()
		{
			return "";
		}
    }
    /*
     * Hit Descriptor packet, one for each matching object
     * info is contained in children
     */
    public class G2PacketH : G2Packet {
        
        public G2PacketH(Header h) : base(h) {
			this.type = G2PacketType.H;
		}
		public G2PacketH() : base() {
			this.type = G2PacketType.H;
		}
		public override int WritePayload(MemoryStream stream) {
			throw new NotSupportedException ("G2PacketH : Writepayload not implemented");
		}
		public override int ReadPayload(MemoryStream stream,int length) {
            //Debug.Assert(length == 0, "G2PacketH supposed to read nothing but has to read " + length);
			return 0;
		}
        public override int getPayloadLength() { return 0; }
		protected override string PayloadToString ()
		{
			return "";
		}
    }

    /**
     * Universal Resource Name
     * */
    public class G2PacketURN : G2Packet {
       public URN urn {get;set;}
       public G2PacketURN(Header h) : base(h) {
			this.type = G2PacketType.URN;
       }
		public G2PacketURN(URN u) : base() {
			this.type = G2PacketType.URN;
			this.urn = u;
		}

       public override int WritePayload(MemoryStream stream) {
            throw new NotSupportedException("URN Packet : write payload not implemented");
       }
       public override int ReadPayload(MemoryStream stream,int length) {
           this.urn = URN.ReadURN(stream,length);
			//Debug.Assert (urn.Size == length, "G2PacketURN ReadPayload length " + urn.Size + " vs " + length + " supposed ( urn type " + urn.HashAlgo + " )");
			return urn.Size;
       }
       public override int getPayloadLength() {
           return urn.Size;
       }
		protected override string PayloadToString ()
		{
			return "URN: " + urn.ToString();
		}
    }

	/**
	 * Firewall indicator packet
	 * */
	public class G2PacketFW : G2Packet {
		public G2PacketFW(Header h) : base(h) {
			this.type = G2PacketType.FW;
		}
		public override int getPayloadLength ()
		{
			return 0;
		}
		protected override string PayloadToString ()
		{
			return "";
		}
		public override int ReadPayload (MemoryStream stream, int length)
		{
            //Debug.Assert(length == 0, "G2PacketFW supposed to read nothing but has to read " + length);
			return 0;
		}
		public override int WritePayload (MemoryStream stream)
		{
			throw new NotImplementedException ();
		}
	}
	/**
	 * Hit Group id 
	 * */
	public class G2PacketHG : G2Packet {
		public byte ID;
		public G2PacketHG(Header h) : base(h) {
			this.type = G2PacketType.HG;
		}
		public override int getPayloadLength ()
		{
			return 1;
		}
		protected override string PayloadToString ()
		{
			return "Group ID : " + ID.ToString ();
		}
		public override int ReadPayload (System.IO.MemoryStream stream, int length)
		{
            //Debug.Assert(length == 1, "G2PacketHG supposed to read 1 byte but has to read " + length);
			ID = (byte)stream.ReadByte ();
			return 1;
		}
		public override int WritePayload (System.IO.MemoryStream stream)
		{
			throw new NotImplementedException ();
		}
	}
	/*
	 * State of the servent 
	 * */
	public class G2PacketSS : G2Packet {
		public Int16 QueueLength;
		public byte MaxConcurrentTransfer;
		public Int32 MaxUploadSpeed; /* Kilobits / sec */
		public int LEN = 4 + 2 + 1; /* 32 bit + 16 bit + 8 bit = bytes */
		public G2PacketSS(Header h) : base(h) {
			this.type = G2PacketType.SS;
		}
		public override int getPayloadLength ()
		{
			return LEN;
		}
		protected override string PayloadToString ()
		{
			return "Queue : " + QueueLength + " MaxTransfer : " + MaxConcurrentTransfer + " MaxSpeed " + MaxUploadSpeed;
		}
		public override int ReadPayload (MemoryStream stream, int length)
		{
            //Debug.Assert(length == LEN, "G2PacketSS supposed to read " + LEN + "but has to read " + length);
			QueueLength = (Int16)BinaryUtils.getVariableIntLE (stream, 2);
			MaxConcurrentTransfer = (byte)stream.ReadByte ();
			MaxUploadSpeed = (Int32)BinaryUtils.getVariableIntLE (stream, 4);
			return LEN;
		}
		public override int WritePayload (MemoryStream stream)
		{
			throw new NotImplementedException ();
		}
	}

    /*
     * Universal Resource Location
     * i.e. where the file can be acquired
     * */
	public class G2PacketURL : G2PacketString {
        public bool HttpRequest;
         public G2PacketURL(Header h) : base(h) {
			this.type = G2PacketType.URL;
		}
		public G2PacketURL(string u) : base(u) {
			this.type = G2PacketType.URL;
		}
        public override int ReadPayload(MemoryStream stream, int length)
        {
            if (length == 0)
            {
                HttpRequest = true;
                return 0;
            }
            else
            {
                HttpRequest = false;
                return base.ReadPayload(stream, length);
            }
        }
		protected override string PayloadToString ()
		{
			return "URL: " + base.Str.ToString();
		}
     }
    
     /**
      * User profile 
      * NO PAYLOAD
      * */
     public class G2PacketUPRO : G2Packet {
         public G2PacketUPRO(Header h) : base(h) {
			this.type = G2PacketType.UPRO;
		}
		public G2PacketUPRO() : base() {
			this.type = G2PacketType.UPRO;
		}
        public override int WritePayload(MemoryStream stream) {
			throw new NotSupportedException ("G2PacketUPRO : Writepayload not inmplemented");
        }
        public override int ReadPayload(MemoryStream stream, int length) {
            //Debug.Assert(length == 0, "G2PacketUPRO supposed to read nothing but has to read " + length);
			return 0;
        }
        public override int getPayloadLength() {return 0;}
		protected override string PayloadToString ()
		{
			return "";
		}
     }
	/**
	 * Nick name of the host
	 * */
	public class G2PacketNICK : G2PacketString {
         public G2PacketNICK(Header h) : base(h) {
			this.type = G2PacketType.NICK;
		}
		public G2PacketNICK(string n) : base(n) {
			this.type = G2PacketType.NICK;

		}
		protected override string PayloadToString ()
		{
			return "Nick: " + base.Str.ToString();
		}
     }
     
     /** 
      * Browsable host
      * */
     public class G2PacketBH : G2Packet {
         public G2PacketBH(Header h) : base(h) {
			this.type = G2PacketType.BH;
         }
		public G2PacketBH() : base() {
			this.type = G2PacketType.BH;
		}
         public override int WritePayload(MemoryStream stream) {
			throw new NotSupportedException ("G2PacketBH : write payload not supported");
		}
         public override int ReadPayload(MemoryStream stream, int length) {
             //Debug.Assert(length == 0, "G2PacketBH supposed to read nothing but has to read " + length);
			return 0;
		}
         public override int getPayloadLength() {return 0;}
		protected override string PayloadToString ()
		{
			return "";
		}
     }
	/**
	 * Metadata information 
	 * in xml format 
	 * */
	public class G2PacketMD : G2PacketString{

		public G2PacketMD(Header h) : base(h) {
			this.type = G2PacketType.MD;
		}
		public G2PacketMD(string xml) : base(xml) {
			this.type = G2PacketType.MD;
		}

		protected override string PayloadToString ()
		{
			return "MetaData: " + base.Str.ToString();
		}
	}
	/**
	 * Object Size
	 * */
	public class G2PacketSZ : G2Packet {

		public Int64 Size;
		public G2PacketSZ(Header h) : base(h) {
			this.type = G2PacketType.SZ;
			Size = 0;
		}
		public override int ReadPayload (MemoryStream stream, int length)
		{
            //Debug.Assert(length == 4 || length == 8, "G2PacketSZ supposed to read 4/8 but has to read " + length);
			Size = BinaryUtils.getVariableIntLE (stream, (int)length);
			return length;
		}
		public override int WritePayload (MemoryStream stream)
		{
			throw new NotImplementedException ();
		}
		/** only 32 bit or 64 bit size allowed */
		public override int getPayloadLength ()
		{
			int TheorySize =  (int) BinaryUtils.getSizeForInt (Size);
            int realSize = TheorySize <= 4 ? 4 : 8;
            return realSize;
		}
		protected override string PayloadToString ()
		{
			return "Object Size = " + Size.ToString() + " bytes?Mb?";
		}
	}

	/**
	 * User comment of the file described in Hit
	 * in xml format
	 * */
	public class G2PacketCOM : G2PacketString
	{
		public G2PacketCOM(Header h) : base(h) {
			this.type = G2PacketType.COM;
		}
		protected override string PayloadToString ()
		{
			return "User Comment : " + Str;
		}
	}
	/**
	 * Preview URL 
	 * b direct url or http request
	 * */
	public class G2PacketPVU : G2PacketString {
		public bool HttpRequest;
		public G2PacketPVU(Header h ) : base(h) {
			this.type = G2PacketType.PVU;
			HttpRequest = false;
		}
		public override int ReadPayload (MemoryStream stream, int length)
		{
			if (length == 0) {// i.e. no payload == http request
				HttpRequest = true;
				return 0;
			}
			else
				return base.ReadPayload (stream, length);

		}
		protected override string PayloadToString ()
		{
			return "Preview URL : " + Str;
		}
	}
	/**
	 * Alternate locations wher file is hosted
	 * */
	public class G2PacketALT : G2Packet
	{
		public NodeAddress[] Addresses;
		public G2PacketALT(Header h) : base(h) {
			this.type = G2PacketType.ALT;
			Addresses = null;
		}
		public override int ReadPayload (MemoryStream stream, int length)
		{
			////Debug.Assert (length % 6 == 0, "G2PacketALT alternate locations bytes not multiple of 6 bytes");
			int size = (int)(length / 6);
			Addresses = new NodeAddress[size];
			for (int i = 0; i < size; i++) {
				Addresses [i] = NodeAddress.ReadNodeAddress (stream);
			}
			return length;
		}
		public override int WritePayload (MemoryStream stream)
		{
			throw new NotImplementedException ();
		}
		public override int getPayloadLength ()
		{
			return (int) (Addresses.Length * NodeAddress.LEN);
		}
		protected override string PayloadToString ()
		{
			StringBuilder b = new StringBuilder ();
			foreach (NodeAddress n in Addresses) {
				b.Append (n);
				b.Append (", ");
			}
			return b.ToString ();
		}
	}
	/**
	 * Creation time as timestamp unix format 
	 * */
	public class G2PacketCT : G2Packet {

		public int Timestamp;
		public G2PacketCT(Header h) : base(h) {
			this.type = G2PacketType.CT;
			Timestamp = 0;
		}
		public override int ReadPayload (MemoryStream stream, int length)
		{
            //Debug.Assert(length == 4, "G2packetCT supposed to read 4 but has to read " + length);
			Timestamp = (int)BinaryUtils.getVariableIntLE (stream, (int)length);
			return length;
		}
		public override int WritePayload (MemoryStream stream)
		{
			throw new NotImplementedException ();
		}
		public override int getPayloadLength ()
		{
			return 4;
		}
		protected override string PayloadToString ()
		{
			return "Creation Time " + BinaryUtils.UnixTimeStampToDateTime (Timestamp).ToShortTimeString ();
		}
	}

    public class G2PacketPART : G2PacketDefault
    {
        public G2PacketPART(Header h) : base(h)
        {
            this.type = G2PacketType.PART;
        }
    }

	/**
	 * DNS Name of the servent 
	 * */
	public class G2PacketDNS : G2PacketString
	{
		public G2PacketDNS(Header h) : base(h) {
			this.type = G2PacketType.DNS;
		}
		protected override string PayloadToString ()
		{
			return "DNS : " + Str;
		}
	}

    
}
