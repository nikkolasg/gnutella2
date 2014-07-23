using System;
using System.Linq;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Collections;
using System.Collections.Generic;
namespace ActionInnocence.P2PScan.Plugins.Gnutella2 {

	class ReverseDateTimeComparer : IComparer<DateTime> {
		public int Compare(DateTime x, DateTime y) {
			return -DateTime.Compare (x, y);
		}
	}

	public static class BinaryUtils {
        /*
         * Return size in bytes for this value
         * */
		public static int getSizeForInt(Int64 value) {
            if (value == 0) return 0;
			for (int i = 1; i <= 8; i++) {
                int max = (int)Math.Pow(2, (i * 8));
				if (value < max)
					return i;
			}
			return 8; // ... 
		}


		/**
		 * Get the value associated in ths byte array
		 * in little endian order
		 * byte array length cannot be more than 3 (packet header)
		 * */
		public static int getInt(byte[] byt,int loc,int num) {
			int b0, b1, b2;
			b0 = byt[loc] & 0x000000FF;
			if (num > 1)
				b1 = (byt[loc+1]<<8) & 0x0000FF00;
			else
				b1 = 0;
			if (num > 2)
				b2 = (byt[loc+2]<<16) & 0x00FF0000;
			else
				b2 = 0;
			return (int)(b0|b1|b2);

        }
        public static string getString(byte[] buff, int offset,int length) {
            char[] charValue = new char[length];
            for(int i = 0; i < length; i++) {
                charValue[i] = (char)buff[i + offset];
            }
            return new String(charValue);
        }
		/** Simply return an integer from the stream */
		public static Int32 GetInt32(MemoryStream stream) {
			Int32 v;
			using (BinaryReader reader = new BinaryReader (stream, System.Text.Encoding.UTF8, true)) {
				v = reader.ReadInt32 ();
			}
			return v;
		}
		public static Int64 getVariableIntLE(byte[] bytes, int length) {
			return getVariableIntLE (new MemoryStream (bytes), length);
		}
		/** Return the integer variable length encoded */
		public static Int64 getVariableIntLE(MemoryStream stream, int length) {
			Int64 intValue = 0;
			long streamCursor = stream.Position;
			if (length >= 1)
				intValue |= (Int64) stream.ReadByte ();
			if (length >= 2)
				intValue |= (Int64)(stream.ReadByte () << 8);
			if (length >= 3)
				intValue |= (Int64)(stream.ReadByte () << 16);
			if (length >= 4)
				intValue |= (Int64)(stream.ReadByte () << 24);
			if (length >= 5)
				intValue |= (Int64)(stream.ReadByte () << 32);
			if (length >= 6)
				intValue |= (Int64)(stream.ReadByte () << 40);
			if (length >= 7)
				intValue |= (Int64)(stream.ReadByte () << 48);
			if (length >= 8)
				intValue |= (Int64)(stream.ReadByte () << 56);

			long difference = stream.Position - streamCursor;
			////Debug.Assert ((int)(difference) == length, "BinaryUtils : ReadPacket " + difference + " vs " + length + " supposed ");
            return intValue;
        }
		/**
		 * Return a stream from the stream
		 * length is the supposed length we have to read
		 * ZeroTerminated tells us if the string is zeroterminated or not
		 * if not we read length bytes
		 * if yes, we read length -1 bytes + 1 bytes for the cursor
		 * */
		public static string getString(MemoryStream stream, int length) {

			byte[] strByte = new byte[length];
			stream.Read (strByte, 0, strByte.Length);
			string str = Encoding.UTF8.GetString (strByte);

			return str;
			//char[] charValue = new char[length];
//            for(int i = 0; i < length; i++) {
//                charValue[i] = (char) stream.ReadByte();
//            }
//            return new String(charValue);
        }
		/** Write the int in a variable length format */
			public static void WriteVariableIntLE(MemoryStream stream,int integer, byte byteLen) {
			byte[] b = new byte[byteLen];
			if(byteLen >= 1) b[0] = (byte)integer;
			if(byteLen>= 2) b[1] = (byte)(((int)integer >> 8) & 0xFF);
			if(byteLen >=3) b[2] = (byte)(((int)integer >> 16) & 0xFF);
			if(byteLen >=4) b[3] = (byte)(((int) integer >> 24) & 0xFF);
			stream.Write(b,0,byteLen);
        }

        public static int WriteSimpleString(MemoryStream stream,string t){
			byte[] byteArr = System.Text.Encoding.UTF8.GetBytes(t);
            
			stream.Write(byteArr,0,byteArr.Length);
            return byteArr.Length;
        }

        public static byte[] getSimpleBytesFromString(string str)
        {
            return System.Text.Encoding.UTF8.GetBytes(str);
        }
        /**
         * Simply transforms array of bytes into utf-8 characters
         * Looks for the final byte if it is null , then remove it
         * */
        public static string getStringFromBytes(byte[] bytes,int length) {
			if(bytes[length-1] == 0x00)
				bytes = bytes.SubArray(0,(int)length-1);

			return System.Text.Encoding.UTF8.GetString(bytes);
        }
		/**
		 * Return a byte array from a string
		 * Contains the termination code for string 0x00 at the end
		 * */
        public static byte[] getNullTerminatedBytesFromString(string str) {
			byte[] toBytes = System.Text.Encoding.UTF8.GetBytes(str);
            byte[] termination = {0x00};
            return toBytes.Concat(termination).ToArray();
        }
        public static int WriteNullTerminatedString(MemoryStream stream, string str)
        {
            byte[] bytes = getNullTerminatedBytesFromString(str);
            stream.Write(bytes, 0, bytes.Length);
            return (bytes.Length);
            
        }
		/**extension method to get a array starting at index of length
		 * */
		public static byte[] SubArray(this byte[] data, int index, int length)
		{
			byte[] result = new byte[length];
			Array.Copy(data, index, result, 0, length);
			return result;
		}

		public static DateTime UnixTimeStampToDateTime( int unixTimeStamp )
		{
			// Unix timestamp is seconds past epoch
			System.DateTime dtDateTime = new DateTime(1970,1,1,0,0,0,0,System.DateTimeKind.Utc);
			dtDateTime = dtDateTime.AddSeconds( unixTimeStamp ).ToLocalTime();
			return dtDateTime;
		}
    }
}
