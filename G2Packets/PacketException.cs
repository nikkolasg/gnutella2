using System;

namespace ActionInnocence.P2PScan.Plugins.Gnutella2 {

	public abstract class PacketException : Exception {
		public string error;
        public PacketException(string msg){
            error = msg;
        }
        public override string ToString() {
            return error;
        }
    }
	public class UnknownPacketException : PacketException 
	{
		public int size;
		public UnknownPacketException(string msg,int size) : base(msg) {this.size = size;}
	}
	public class NotEnoughDataException : PacketException
	{
		public NotEnoughDataException(string msg) : base(msg) {}
	}

    public class EndOfStreamException : PacketException
    {
        public EndOfStreamException(string msg) : base(msg) {}
    }
    public class BigEndianPacketException : PacketException {
		public BigEndianPacketException(string msg) : base(msg) {}
    }
    public class GUIDPacketException : PacketException 
    {
        public GUIDPacketException(string msg) : base(msg) {}
    }
}
