using System;
using System.IO;
using System.Diagnostics;
namespace ActionInnocence.P2PScan.Plugins.Gnutella2.Struct {
    
    public struct G2Hash {
		public const string MD5 = "md5";
		public const string SHA1 = "sha1";
		public const string ED2K = "ed2k";
		public const string TREE_TIGER = "tree:tiger/";
		public const string TTR = "ttr";
		public const string BP = "bp";
		public const string BITPRINT = "bitprint";
		public const string BTIH = "btih";

        public static int Size(string hash) {
            switch(hash) {
                case MD5:
                    return 16;
                    
                case SHA1 :
                    return 20;
                    
                case ED2K :
                    return 16;
                    
                case BP:
                    return 20 + 24;
                    
                case BITPRINT :
                    return 20 + 24;
                    
                case TREE_TIGER :
                    return 24;
                    
                case TTR:
                    return 24;
				case BTIH:
					return 20;

                default :
                    return 0;
            }
        }
    }

	public class  URN {
        public string HashAlgo {get;set;}
		public byte[] Digest {get;set;}
        // total size of the URN (algo + digest)
        public int Size {get;set;}
		private URN(string algo,byte[] hash,int s) {
            HashAlgo = algo;
            Digest = hash;
            Size = s;
        }
		public override string ToString ()
		{
			return string.Format ("HashAlgo={0},  Size={2}, Digest={1}", HashAlgo, Digest.Length, Size);
		}
        public static URN ReadURN(MemoryStream stream,int length) {
            byte[] bytes = new byte[12];
            int endIndex = 0;
            for(int i = 0; i < 12; i++) {
				byte b = Convert.ToByte(stream.ReadByte());
                if(b == '\0') {
                    endIndex = i;
                    break;
                }
                bytes[i] = b;
            }    
            if(endIndex == 0)
                return null;
            
            byte[] algo = new byte[endIndex];
            Array.Copy(bytes,algo,endIndex);

			string algoStr = BinaryUtils.getStringFromBytes(algo,(int)algo.Length);
            int size = G2Hash.Size(algoStr);
            byte[] digest = new byte[size];
			stream.Read(digest,0,(int)size);
            string hex = BitConverter.ToString(digest).Replace("-", string.Empty).ToLower();
			int TotalSize = (int)(endIndex + 1 + size);

			return new URN(algoStr,digest,(int)TotalSize); 

        }
    }

}
