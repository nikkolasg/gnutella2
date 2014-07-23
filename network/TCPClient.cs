using System;
using System.Net;
using System.IO;
using System.Text;
using System.IO.Compression;
using System.Net.Sockets;
using System.Collections.Generic;
using System.Threading;
using ActionInnocence.P2PScan.Plugins.Gnutella2.G2Packets;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Struct;
namespace ActionInnocence.P2PScan.Plugins.Gnutella2.Network
{
	public class NetException : Exception
	{
		private string msg;
		public NetException (string msg) : base(msg)
		{
			this.msg = msg;
		}
		public override string ToString ()
		{
			return msg;
		}
	}
    

	public class TCPConnection  {

        // STATIC MEMBERS
		private static Dictionary<NodePeer,TCPConnection> Sock = new Dictionary<NodePeer,TCPConnection>();
        /**
         * Centralized connections with all peers
         * Get an existing connection 
         * OR create one and register it with the peer
         * */
		public static TCPConnection getPeerConnection(NodePeer p) {
            TCPConnection con;
            Sock.TryGetValue(p,out con);
            if(con != null)
                return con;
            
            con = new TCPConnection(p.Address,p.Port);
            Sock.Add(p,con);
            return con;
        }
		public static bool CloseConnection(NodePeer p) {
			getPeerConnection(p).Close();
			return Sock.Remove(p);
        }

        ////////////////////
		private Exception exception;
		public Socket sock;
		private string _encoding;
		public  string  Encoding { 
			get {
				return _encoding;
			}
			set {
				if (value == HttpHeader.ENCODING_DEFLATE)
					_encoding = HttpHeader.ENCODING_DEFLATE;
			}
		} 
        private IPAddress ip;
        private ushort port;
        private NetworkStream stream;
		// timeout in msg
		private const int CONNECT_TIMEOUT = 3000;
        // timeout read/write in millisecond
		private const int IO_TIMEOUT = 10000;
		public const int BUFF_SIZE = 1024;
		public bool Handshaked { get; set; }

		public TCPConnection(IPAddress _ip,ushort _port) {
            ip = _ip;
            this.port = _port;
			_encoding = HttpHeader.ENCODING_IDENTITY;
			Handshaked = false;
			//sock = new TcpClient(_ip.ToString(),port);
        }

		public bool Connect() {
			Thread t = new Thread (new ThreadStart (ConnectTimeOut));
			t.IsBackground = true;
			t.Start();
			t.Join (CONNECT_TIMEOUT);
			if (sock == null || !sock.Connected) {
				t.Abort ();
				if (exception != null)
					G2Log.Write( exception.ToString());
				return false;
			}

			sock.ReceiveTimeout = 5000;


			stream = new NetworkStream (sock, true);
            stream.ReadTimeout = IO_TIMEOUT;
            stream.WriteTimeout = IO_TIMEOUT;
			if (!stream.CanRead) {
				Console.Error.WriteLine ("NetworkStream cannot read");
				return false;
			}
			if (!stream.CanWrite) {
				Console.Error.WriteLine ("NetworkStream cannot write");
				return false;
			}
            return true;
        
        }
		private void ConnectTimeOut() {
			try {
				sock = new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp);
				sock.Connect(ip.ToString(),port);
			} catch (Exception e) {
				exception = e;
			}
		}
		public ByteBuffer Read() {
			if(_encoding == HttpHeader.ENCODING_DEFLATE) 
				return readDeflate();
            else
				return readIdentity();
        }
		public ByteBuffer readIdentity() {
			int byteRead = 0;
			byte[] bytes = new byte[BUFF_SIZE];
			ByteBuffer b = new ByteBuffer (bytes);
            try{
				byteRead = stream.Read(bytes,0,bytes.Length);
				b.DataOffset = byteRead;
            }catch (IOException e) {
                G2Log.Write("ERROR TCPConnection : readIdentity " + e.ToString());
				return null;
            } catch (Exception e) {
                G2Log.Write("ERROR TCPConnection : readIdentity Unknown Exception " + e.ToString());
				return null;
            }
			return b;
        } 
		public ByteBuffer readDeflate() {

			ByteBuffer deflateB = readIdentity ();
			if (deflateB == null)
				return null;

			int bRead;
			if (deflateB.DataOffset == 0)
				return deflateB;
			ByteBuffer b = new ByteBuffer ();
			using (MemoryStream memStream = new MemoryStream (deflateB.Bytes)) {
				using(DeflateStream deflate = new DeflateStream(memStream,CompressionMode.Decompress)) {
					bRead = deflate.Read (b.Bytes, 0, b.Length);
				}
			}
			b.DataOffset = bRead;
			return b;

		}


//		public bool CheckConnection() {
//			try
//			{
//				if (sock != null && sock.Client != null && sock.Client.Connected)
//				{
//					/*					 pear to the documentation on Poll:
//                * When passing SelectMode.SelectRead as a parameter to the Poll method it will return 
//                * -either- true if Socket.Listen(Int32) has been called and a connection is pending;
//                * -or- true if data is available for reading; 
//                * -or- true if the connection has been closed, reset, or terminated; 
//                * otherwise, returns false
//                */
//
//					// Detect if client disconnected
//					if (sock.Client.Poll(0, SelectMode.SelectRead))
//					{
//						byte[] buff = new byte[1];
//						if (sock.Client.Receive(buff, SocketFlags.Peek) == 0)
//						{
//							// Client disconnected
//							return false;
//						}
//						else
//						{
//							return true;
//						}
//					}
//
//					return true;
//				}
//				else
//				{
//					return false;
//				}
//			}
//			catch
//			{
//				return false;
//			}
//		}

		public bool Send(ByteBuffer b) {
			if(_encoding == HttpHeader.ENCODING_DEFLATE)
				return sendDeflate(b);
             else
				return sendIdentity(b);

        }

		private bool sendIdentity(ByteBuffer b) {
            
            bool ret = true;
            try{
				stream.Write(b.Bytes,0,b.DataOffset);

            } catch (IOException e) {
                G2Log.Write("ERROR TCPConnection : sendIdentity " + e.ToString()); 
                ret = false;
            } catch (Exception e) {
                G2Log.Write("ERROR TCPConnection : unknow error " + e.ToString());
                ret = false;
            }
            return ret;
        }

		private bool sendDeflate(ByteBuffer b) {
            bool ret = true;
			using (DeflateStream deflate = new DeflateStream(stream, CompressionMode.Compress,true)) {
                 try {
					deflate.Write(b.Bytes,0,b.DataOffset);

                 } catch (IOException e) {
                    G2Log.Write("ERROR TCPConnection : can not write deflate, " + e.ToString());
                    ret = false;
                } catch (Exception e) {
                     G2Log.Write("ERROR TCPConnection : unknown error writing deflate " + e.ToString());
                     ret = false;
                }
             }
            return ret;
        }

		public void Close() {
			if(sock != null && sock.Connected) {
                stream.Close();
                stream.Dispose();
                sock.Close();
               
            }

        }
        

    }
}

