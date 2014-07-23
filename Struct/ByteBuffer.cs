using System;
using System.Collections;
using System.IO;
namespace ActionInnocence.P2PScan.Plugins.Gnutella2.Struct
{
	public class ByteBuffer
	{
		public  byte[] Bytes;
		public int DataOffset {get;set;} // where data stops in the buffer
		public int CurrentOffset { get; set; } // where our pointer is currently when reading from the buffer
		public int Length { // the actual length of the underlying array
			get {
				return Bytes.Length;
			}
		}
		public bool Empty {
			get { return DataOffset == 0 ? true : false; }
		}
		public byte this[int indexer] {
			get { 
				if (indexer < Length)
					return Bytes [indexer];
				else
					throw new IndexOutOfRangeException ();
			}
		}
		private const int BUFF_LEN = 1024;
		public ByteBuffer ()
		{
			Bytes = null;
			DataOffset = 0;
			CurrentOffset = 0;
		}
		public ByteBuffer(int LEN) {
			Bytes = new byte[LEN];
			DataOffset = 0;
			CurrentOffset = 0;
		}
		public ByteBuffer (byte[] b) {
			Bytes = b;
			DataOffset = b.Length;
			CurrentOffset = 0;
		}


		public void Flush() {
			Reset ();
		}
		// return a stream which contains exactly the number of data bytes
		public MemoryStream ToStream() {
			byte[] b = new byte[DataOffset];
			Array.Copy (Bytes, b, DataOffset);
			return new MemoryStream (b);
		}
		// Append length bytes to the buffer at the end of already stored data
		public void Append(byte[] app,int length) {
			Append (app, 0, length);
		}
		// Append bytes from the specified offset and of length length
		public void Append(byte[] app,int boffset,int length) {
			if (Bytes == null)
				Reset ();

			if (DataOffset + length > Bytes.Length)
				Array.Resize (ref Bytes, DataOffset + 2 * length);

			for (int i = 0; i < length; i++)
				Bytes [DataOffset + i] = app [i+boffset];

			DataOffset = DataOffset + length;
		}
		public void Append(ByteBuffer b) {
			Append (b.Bytes, 0, b.DataOffset);
		}
		/**
		 * Remove len bytes starting from the beginning of the buffer
		 * Set offset accordingly
		 * */
		public void Dequeue(int length) {
			if (length >= DataOffset) {
				Flush ();
				return;
			}
			int diff = DataOffset - length;
//			try {
//				// copy the remaining bytes to the beginning
//				Array.Copy (bytes, length, bytes, 0, diff);
//			} catch (Exception e) {
//				Log.Write ("Buffer : Copy error " + e.ToString ());
//			}
			byte[] newBytes = new byte[diff];
			Array.Copy (Bytes, length, newBytes, 0, diff);
			Bytes = newBytes;
			this.DataOffset = diff;
		}
		public void Reset() {
			Bytes = new byte[BUFF_LEN];
			DataOffset = 0;
		}
	}
}

