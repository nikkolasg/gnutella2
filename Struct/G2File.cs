using System;
using System.Collections.Generic;
using System.Text;
using ActionInnocence.P2PScan;
using ActionInnocence.P2PScan.Plugins.Gnutella2.G2Packets;

namespace ActionInnocence.P2PScan.Plugins.Gnutella2.Struct
{
	public class G2File : File
	{
		public override string ToString ()
		{
			return "File:" + base.Name + ", " + base.Size/1024 + " Ko, Length = "  + Metadata.Length + " secs ";
		}

		public List<URN> Hashes;
		public Metadata Metadata; // xml format
		public string UserComment; // xml format
		public string PreviewUrl; 
		public DateTime CreationTime; 
		public G2File (String name, String hash, byte[] hashByte, TypeHash typeHash
			, long size, FileType fileType, String codecInfo
			, FileLocationFound filelocation, int lenghtMedia
			, String protocolName, String linkFile) 
			: base (name,hash,hashByte,typeHash,size,fileType,codecInfo,filelocation,lenghtMedia,protocolName,linkFile)  {
		
		}


		/**
		 * Return a File for the application plugin
		 * from a Hit Packet
		 * */
		public static G2File 
            ParseHit(G2PacketH hit,FileLocationFound location) {
            // for now we dont take into accounts host of partial files
            if (isPartialFile(hit) && !Settings.ACCEPT_PARTIAL_FILE)
                return null;

			string FileName = "";
			long size = getNameAndSizeFromHit (hit, out FileName);
			if (size == 0)
				return null; // no size, no name or bug

			List<URN> Hashes = getHashesFromHit (hit);
			TypeHash type = TypeHash.Md4EDonkey;
			URN SingleHash = Hashes.Find (FindED2KHash);
			if (SingleHash == null) {
				SingleHash = Hashes.Find (FindSHA1Hash);
				type = TypeHash.Sha1;
			}
            // if there is not the hashes we want , we dont want this packet 
            // for now. ActionInnoncence DLL needs to take care of more hashes
            if (SingleHash == null)
                return null;
            // gives a text representation of the hash
            string strHash = BitConverter.ToString(SingleHash.Digest).Replace("-", string.Empty).ToLower();


			string link = getDownloadLink (hit);
            Metadata meta = Metadata.ParseMetadata(hit.getStringFromChildType(G2PacketType.MD));

            
            G2File f = new G2File(FileName, strHash, SingleHash.Digest, type, size, 
				FileType.Unknow, meta.Codec, location, meta.Length, Settings.PROTOCOL_NAME, link);
            
			f.Hashes = Hashes;
			f.CreationTime = getCreationTimeFromHit(hit);
			f.Metadata = meta;
			f.UserComment = hit.getStringFromChildType(G2PacketType.COM);
			f.PreviewUrl = hit.getStringFromChildType( G2PacketType.PVU);
			return f;
		}

        private static bool isPartialFile(G2PacketH hit)
        {
            
            G2Packet part = hit.getFirstChildPacket(G2PacketType.PART);
            if (part != null)
                return true;
            return false;

        }
		/**
		 * Return creation time in DateTime format if present
		 * otherwise return current time
		 * */
		private static DateTime getCreationTimeFromHit(G2PacketH hit) {
			G2Packet pack = hit.getFirstChildPacket (G2PacketType.CT);
			if (pack == null)
				return DateTime.Now;
			G2PacketCT ct = pack as G2PacketCT;
			return BinaryUtils.UnixTimeStampToDateTime (ct.Timestamp);
		}
		/**
		 * Get a URL link if present
		 * IF not present , it has to beretrieved by HTTP request
		 * */
		private static string getDownloadLink(G2PacketH hit) {
			G2Packet pack = hit.getFirstChildPacket (G2PacketType.URL);
			if (pack == null)
				return "";
			G2PacketURL url = pack as G2PacketURL;
			if (url == null)
				return "";
            
			return url.Str;
		}

		/**
		 * Parse all hashes contained for this file
		 * */
		private static List<URN> getHashesFromHit(G2PacketH hit) {
			List<URN> hashes = new List<URN> ();
			foreach (G2Packet child in hit.children) {
				if (child.type != G2PacketType.URN)
					continue;
				G2PacketURN UrnPacket = child as G2PacketURN;
				if (UrnPacket == null)
					continue;
				hashes.Add (UrnPacket.urn);
			}
			return hashes;
		}
		private static bool FindHashType(URN urn, string type) {
			if (urn.HashAlgo.Equals (type))
				return true;
			return false;
		}
		private static bool FindED2KHash(URN urn) {
			return FindHashType(urn,G2Hash.ED2K);
		}
		private static bool FindMD5Hash(URN urn) {
			return FindHashType(urn,G2Hash.MD5);
		}
		private static bool FindSHA1Hash(URN urn) {
			return FindHashType(urn,G2Hash.SHA1);
		}


		/**
		 * Return the size of the file and the name with the out parameters name
		 * */
		private static long getNameAndSizeFromHit(G2PacketH hit, out string name) {
			G2Packet SZ,DN;
			DN = hit.getFirstChildPacket (G2PacketType.DN);
			SZ = hit.getFirstChildPacket (G2PacketType.SZ);
			name = "";
			if (DN == null) // no name
				return 0;
			// object size packet is not present
			// so we parse DN with a 32 bit integer before
			if ( SZ == null) {
				byte[] bytes = ((G2PacketDN)DN).bytes;
				byte[] bName = bytes.SubArray (4, bytes.Length - 4);
				long size = BinaryUtils.getVariableIntLE (bytes, 4);
				name = BinaryUtils.getStringFromBytes (bName, (int)(bytes.Length - 4));
				return size;

			} else {
				name = ((G2PacketDN)DN).Str;
				return ((G2PacketSZ)SZ).Size;

			}
		}
	}

}

