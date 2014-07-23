using System;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Threading;
using ActionInnocence.P2PScan.Plugins.Gnutella2.G2Packets;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Struct;
namespace ActionInnocence.P2PScan.Plugins.Gnutella2.Network
{
	public class HubSocket 
	{
		private Socket sock;
		private NetworkStream stream;
		private NodePeer peer;
		public const int BUFF_SIZE = 4096;
		private G2PacketReader Reader;
		public Thread Receiver;
		public Thread Sender;
		private volatile bool shouldStop_;
		private const int JOIN_WAIT_TIME = 50; // ms

		public HubSocket (NodePeer p,Socket c)
		{
			this.peer = p;
			this.sock = c;
			this.stream = new NetworkStream (c, true);
			SetupSocketOptions ();
			this.Reader = new G2PacketReader (p);
			this.shouldStop_ = false;
			Receiver = new Thread (new ThreadStart (ReceiveThread));
			Sender = new Thread (new ThreadStart (SendThread));
            Receiver.Name = "HubSocket Receiver " + p.Address.ToString();
            Sender.Name = "HubSocket Sender " + p.Address.ToString();

		}
        public HubSocket(NodePeer p, Socket c, G2PacketReader packetReader) : this(p,c)
        {
            this.Reader = packetReader;
        }
        public void Start()
        {
            Receiver.Start();
            Sender.Start();
        }

		private void SetupSocketOptions() {
			sock.SetSocketOption (SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, 3000);
			//sock.SetSocketOption (SocketOptionLevel.Socket, SocketOptionName.ReceiveLowWater, 3);
			sock.ReceiveTimeout = 3000;
			//sock.SetSocketOption (SocketOptionLevel.Socket, SocketOptionName.SendLowWater, 3);
			// PUT OPTIONS HERE
		}

        public void FlushBuffer()
        {
            this.Reader.Flush();
        }

		public bool Send(MemoryStream stream) {
			byte[] bytes = stream.ToArray ();
			try {
				int bread  = sock.Send(bytes);
				if(bread == 0) return false;
				return true;
			} catch (Exception e) {
				Console.Error.WriteLine ("TCPConnection: Error sending " + e.ToString());
				return false;
			}

		}
		/**
		 * Wait for packet to send to peer from its buffer and send it
		 * */
		public void SendThread() {
			while (!shouldStop_) {
				G2Packet pack = peer.Buffer.PollPacketToSend ();

				MemoryStream str = new MemoryStream ((int)pack.getTotalPacketLength ());
				pack.Write (str);
				bool succ = Send (str);

			}
		}

		/**
		 * Check incoming data from socket every time and push it
		 * into buffer if data present
		 * */
		public void ReceiveThread() {
			byte[] buffer = new byte[BUFF_SIZE];
				// ShutdownEvent is a ManualResetEvent signaled by
				// Client when its time to close the socket.
			var count = 0;
			while (!shouldStop_)
				{
					try
				{ count++;
						// We could use the ReadTimeout property and let Read()
						// block.  However, if no data is received prior to the
						// timeout period expiring, an IOException occurs.
						// While this can be handled, it leads to problems when
						// debugging if we are wanting to break when exceptions
						// are thrown (unless we explicitly ignore IOException,
						// which I always forget to do).
						if (!stream.DataAvailable)
						{
							// Give up the remaining time slice.
							Thread.Sleep(10);
						}
						else {
						int bRead = stream.Read(buffer, 0, buffer.Length); // see if something is there
							if (bRead > 0)
							{
								//G2Log.Write("HubSocket: Received " + bRead + " bytes !");
								Reader.Read(buffer,bRead);
								buffer = new byte[BUFF_SIZE];
							}
						else {
							G2Log.Write("HubSocket: Connection killed ? " + this.peer.ToString()); // connection closed
						}
					}

					}
					catch (IOException ex)
					{
						G2Log.Write("ReceiveThread exception : " + ex.ToString());
					}
				}

		}
			



		public bool Connect() {
			try {
				sock.Connect (new IPEndPoint (peer.Address, (int)peer.Port));
			} catch (Exception e) {
				G2Log.Write ("TCP " + peer.ToString () + " => " + e.ToString ());
				return false;
			}
			return true;
		}

		public void Close() {
			G2Log.Write("HubSocket : " + this.peer.ToString() + " Closing ... ");
			shouldStop_ = true;
            if (Receiver.ThreadState == ThreadState.Running)
            {
                bool succ = Receiver.Join(JOIN_WAIT_TIME);
                if (!succ) Receiver.Abort();
            }
            G2Log.Write("\tHubSocket : =======> closed Receiver Thread (" + this.peer.ToString() + ") ...");
            // no check for sender because it can be in waitsleep join , or running, or waking ...
            bool success = Sender.Join(JOIN_WAIT_TIME);
            if (!success) Sender.Abort();
            
            G2Log.Write("\tHubSocket : =======> closed Sender Thread (" + this.peer.ToString() + ") ...");
			if (sock != null && sock.Connected) {
				stream.Close ();
                stream.Dispose();
				//sock.Shutdown (SocketShutdown.Both);
			}
		}
	}
}

