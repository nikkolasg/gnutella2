using System;
using System.Net;
using System.IO;
namespace ActionInnocence.P2PScan.Plugins.Gnutella2.Struct
{
	public class NodeAddress {
		public static int LEN = 6;
		public IPAddress ipv4 { get; private set;}
		public ushort port {get; private set;}
		public NodeAddress(IPAddress ip, ushort p) {
			ipv4 = ip;
			port = p;
		}

		public static NodeAddress ReadNodeAddress(MemoryStream stream) {
			byte[] addressNode = new byte[4];
			int byteRead = stream.Read(addressNode,0,4);

			if (byteRead != 4) return null;


			IPAddress ipv4 = new IPAddress(addressNode);
			byte b1 = Convert.ToByte(stream.ReadByte ());
			byte b2 = Convert.ToByte (stream.ReadByte ());
			ushort port = 0;
			ushort u1= Convert.ToUInt16(b1);
			ushort u2 = (ushort)(Convert.ToUInt16(b2) << 8);    
			port = (ushort)(u1 + u2);       
			return new NodeAddress(ipv4,port);
		}
		public int Write(MemoryStream stream) {
			byte[] ipbytes = ipv4.GetAddressBytes ();
			stream.Write (ipbytes, 0, ipbytes.Length);
			byte b1 = (byte)(port & 0x00FF);
			byte b2 = (byte)((port & 0xFF00)>>8);
			stream.WriteByte (b1);
			stream.WriteByte (b2);
			return NodeAddress.LEN;
		}
		public override string ToString ()
		{
			return ipv4.ToString () + ":" + port.ToString();
		}
	}

}

