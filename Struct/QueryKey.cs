using System;
using System.IO;
namespace ActionInnocence.P2PScan.Plugins.Gnutella2.Struct
{
	public class QueryKey
	{
		public Int32 key;
		public const int LEN = 4;
		public QueryKey (Int32 k)
		{
			key = k;
		}

		public static QueryKey ReadQueryKey(MemoryStream stream) 
		{
			byte[] bytes = new byte[4];
			int bread  = stream.Read (bytes, 0, 4);
			Int32 k = BitConverter.ToInt32 (bytes, 0);
			return new QueryKey (k);
		}
		public void Write(MemoryStream stream) {
			byte[] b = BitConverter.GetBytes (key);
			stream.Write (b, 0, b.Length);
		}
		public override string ToString ()
		{
			return "QueryKey : " + key.ToString ();
		}
	}
}

