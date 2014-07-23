using System;
using System.Collections;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.IO;
namespace ActionInnocence.P2PScan.Plugins.Gnutella2.Struct
{

	public class GUID : IEquatable<GUID> {

		public static HashSet<GUID> guidSet = new HashSet<GUID> ();
        public static int GUID_LEN = 16; // in bytes
        public byte[] bytes;

        public GUID(byte[] bytesGUID) {
            bytes = bytesGUID;
        }
        public GUID(string guid)
        {
            bytes = System.Guid.Parse(guid).ToByteArray();
        }
        
		public static GUID  generateGuid() {

			GUID g;
			g = new GUID (System.Guid.NewGuid().ToByteArray());

			return g;
        }        

		public static GUID ReadGUID(MemoryStream stream) {
            byte[] guidBytes = new byte[GUID_LEN];
			int byteRead = stream.Read(guidBytes,0,(int)GUID_LEN);
            if(byteRead != GUID_LEN)
                throw new GUIDPacketException("GUID read " +byteRead+" only");
            return new GUID(guidBytes);
        }

		public override string ToString() {
            StringBuilder builder = new StringBuilder();
            int count = 1;
            foreach(byte b in bytes) {
                builder.Append(b.ToString());
                if (count == 4 || count == 6 || count == 8 || count == 10)
                    builder.Append("-");
                    
            }
            return builder.ToString();
        }

		public bool Equals(GUID g) {
			if (g.bytes.Length != bytes.Length)
				return false;
			for (int i = 0; i < bytes.Length; i++) {
				if (g.bytes [i] != bytes [i])
					return false;
			}
			return true;
		}
		public override bool Equals (object obj)
		{
			if (this.GetType () != obj.GetType ())
				return false;
			GUID g = (GUID)obj;
			return Equals (g);
		}
		public override int GetHashCode ()
		{
			int hash = 0;
			foreach (byte b in bytes) {
				hash += (b.GetHashCode ()) % Int32.MaxValue;
			}
			return hash;
		}
	}
}

