using System;
using System.IO;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Struct;
namespace ActionInnocence.P2PScan.Plugins.Gnutella2.G2Packets {

	public class Header {

        public byte controlByte {get;set;}
		public int HeaderLength {get;set;}
        // payload length
		public int PayloadLength {get;set;}
        public string type {get;set;}
        public bool compound {get;set;}
        // EXACT byte length of the name of packet 
        // when you write , do minus one.
        public byte nLenLen {get;set;}
        public byte nTypeLen {get;set;}

        public Header(byte c, int packLen, string type, bool comp,int headerL, byte LenLen, byte TypeLen) {
            initialize(packLen,type,comp,LenLen,TypeLen) ;
            controlByte = c;
         }

		private void initialize(int packLen,string type, bool comp, byte LenLen, byte TypeLen) {
			PayloadLength = packLen;
            this.type = type;
            compound = comp;
            nLenLen = LenLen;
            nTypeLen = TypeLen;
            // +1 for control byte
			HeaderLength = (int)(nLenLen + nTypeLen + 1); 
        }
        public Header(G2Packet packet) {
			int totalPayloadLength = packet.getTotalPayloadLength ();
			initialize(totalPayloadLength,
                        packet.type,
                        packet.children.Count > 0 ? true : false,
				getLenLen(totalPayloadLength),
				(byte)System.Text.Encoding.UTF8.GetBytes(packet.type).Length) ; 
            
			controlByte = ComputeControlByte();
        }
		public static Header Read(MemoryStream stream) {

			byte nInput = Convert.ToByte(stream.ReadByte());
           
            if ( nInput == 0 ) throw new EndOfStreamException("Control byte empty");

			byte nLenLen = Convert.ToByte(( nInput & 0xC0 ) >> 6);
			byte nTypeLen = Convert.ToByte((( nInput & 0x38 ) >> 3)  + 1);
			byte  nFlags = Convert.ToByte( nInput & 0x07 );

			bool bBigEndian = ( nFlags & 0x02 ) == 0x02 ? true : false;
			bool bIsCompound = ( nFlags & 0x04 ) == 0x04 ? true : false;
            
			//  handle bigendian packet in a better way... maybe handle or reject it but can read further.
			if (bBigEndian)
				throw new BigEndianPacketException ("Big Endianness detected");


			int headerLength = (int) (1 + nLenLen + nTypeLen);
			int dataSize = (int)BinaryUtils.getVariableIntLE(stream,nLenLen);
            string type = BinaryUtils.getString(stream,nTypeLen);

			if (dataSize < 0)
				throw new UnknownPacketException ("Payload lenght negative ",dataSize);

            return new Header(nInput,dataSize,type,bIsCompound,headerLength,nLenLen,nTypeLen);

        }
        /**
         * Write the header to the stream according
         * to the gnutella2 spec 
         * */
        public void Write(MemoryStream stream) {
           stream.WriteByte(controlByte);

			if(PayloadLength > 0)
				BinaryUtils.WriteVariableIntLE(stream,PayloadLength,nLenLen);
            
            BinaryUtils.WriteSimpleString(stream,type);
        }

        /**
         * Return number of byte needed to store that int value
         * */
        private static  byte getLenLen(int payloadLength) {
			if (payloadLength == 0)
				return (byte)0;
            byte[] byteLength = BitConverter.GetBytes(payloadLength);
            bool foundNonNull = false;
            byte nLenLen = 0;
            for(int i = 0 ; i < byteLength.Length; i++){
                byte b = byteLength[i];
                if(b != 0) {
                    foundNonNull = true;
                }
                if( b == 0 && foundNonNull == true)
                    break;
                nLenLen += 1;
            }
            return nLenLen;
        }

		public static Header ReadHeader(MemoryStream stream) {
            Header h;
            h = Read(stream);
            return h;

        }


        private byte ComputeControlByte() {
			byte _typeLen = Convert.ToByte(nTypeLen - 1);
            byte bOut = 0;

            if (nLenLen == 1)
                bOut += 0x40;
            else if (nLenLen == 2)
                bOut += 0x80;
            else if (nLenLen == 3)
                bOut += 0xC0;

            if(_typeLen == 1)
                bOut += 0x08;
            else if (_typeLen == 2)
                bOut += 0x10;
            else if (_typeLen == 3)
                bOut += 0x18;
            else if (_typeLen == 4)
                bOut += 0x20;
            else if (_typeLen == 5)
                bOut += 0x28;
            else if (_typeLen == 6)
                bOut += 0x30;
            else if (_typeLen == 7)
                bOut += 0x38;

            if (compound)
                bOut += 0x04;

            return bOut;

        }
		public override string ToString ()
		{
			var str = "";

			str += "Hlen = " + HeaderLength +" Plen=" + PayloadLength + " Type=" + type;
			return str;
		}
		private string printControlByte() {
			char[] chararr = Convert.ToString (controlByte, 2).ToCharArray ();
			string outStr = "";
			for (int i = chararr.Length; i < 8; i++) {
				outStr += "0 : ";
			}
			for (int i = 0; i < chararr.Length; i++) {
				outStr += chararr [i].ToString () + " : ";
			}
			return outStr;
		}

    }

}
