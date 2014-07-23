using System;
using System.IO;
using System.Diagnostics;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Struct;
namespace ActionInnocence.P2PScan.Plugins.Gnutella2.G2Packets {

	public class G2PacketQ2 : G2Packet {
    
        public GUID guid {get;set;}
        
        public G2PacketQ2(Header h) : base(h) {
			this.type = G2PacketType.Q2;
			this.guid = null;            
        }        
        public G2PacketQ2(GUID d) : base() {
			this.type = G2PacketType.Q2;
			this.guid = d;
        }
        
		public override int WritePayload(MemoryStream stream) {
            byte[] guidBytes = guid.bytes;
            // length should be 16, as guid is an array of 16 bytes
			stream.Write(guidBytes,0,guidBytes.Length);
			return (int)guidBytes.Length;
        }

        public override int ReadPayload(MemoryStream stream,int length) {
            //Debug.Assert(length == GUID.GUID_LEN, "G2PacketQ2 supposed to read " + GUID.GUID_LEN + " but have to read " + length);
                
            guid = GUID.ReadGUID(stream);
			return (int)guid.bytes.Length;
        }

        public override int getPayloadLength(){
			return (int) guid.bytes.Length;
        }

 
		protected override string PayloadToString ()
		{
			return guid.ToString();
		}
    }


    /*
     * Descriptive Name Query Packet 
     * i.e. the search terms in simple descriptive language
     * => string
     * */
	public class G2PacketDN : G2PacketString {

		public G2PacketDN(Header h) : base(h) {
			this.type = G2PacketType.DN;
		}
		public G2PacketDN(string search) : base(search) {
            type = G2PacketType.DN;
        }

		protected override string PayloadToString ()
		{
			return "search: " + base.Str;
		}
       
    }

}
