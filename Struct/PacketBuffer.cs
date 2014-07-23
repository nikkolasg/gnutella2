using System;
using System.Collections;
using System.Collections.Generic;
using System.Threading;
using ActionInnocence.P2PScan.Plugins.Gnutella2.G2Packets;

namespace ActionInnocence.P2PScan.Plugins.Gnutella2.Struct
{
	/**
	 * Class handling the storage of packet to send and packet received
	 * wakes up thread that are waiting to send / receive packet
	 * */
	public class PacketBuffer
	{
		// packet we have received
		private Queue ReceiveBuffer;
		// packet we have to send
		private Queue SendBuffer;
		private G2Network network;

        public int ReceiveBufferCount
        {
            get { return ReceiveBuffer.Count; }
        }
        public int SendBufferCount
        {
            get { return SendBuffer.Count; }
        }

		public PacketBuffer ()
		{
			
			ReceiveBuffer = new Queue ();
			SendBuffer = new Queue ();
			network = G2Network.Instance;
		}
        public void Clear()
        {
            lock(ReceiveBuffer)
            {
                ReceiveBuffer.Clear();
            }
            lock(SendBuffer)
            {
                SendBuffer.Clear();
            }

        }
		/**
		 * Retrieve a packet 
		 * */
		public G2Packet PollPacketToSend()
		{
			G2Packet pack = null;
			lock (SendBuffer) {
				while (SendBuffer.Count == 0)
					Monitor.Wait (SendBuffer);

				pack = (G2Packet)SendBuffer.Dequeue ();
			}
			return pack;
		}
		/**
		 * Push a packet to the buffer to be sent by the connection of the peer
		 * */
		public void PushPacketToSend(G2Packet pack) {
			lock (SendBuffer) {
				SendBuffer.Enqueue(pack);
				var type = pack.packetHeader.type;
				type += pack.type == G2PacketType.DEFAULT ? " (unknown) " : "";
				G2Log.Write("PacketBuffer : Enqueued packet " + type + " to send to " + pack.RemotePeer.ToString());
				Monitor.Pulse (SendBuffer);
			}
		}
		/**
		 * Pick a packet to analyse by the processing thread
		 * */
		public G2Packet PollPacketToReceive() {
			G2Packet pack = null;
			lock (ReceiveBuffer) {

					if(ReceiveBuffer.Count > 0) {
						pack = (G2Packet)ReceiveBuffer.Dequeue ();
					}
			}
			return pack;
		}

		/**
		 * Push a packet just received, to be analyzed further
		 * */
		public void PushPacketToReceive(G2Packet pack) {
			lock (ReceiveBuffer) {
				ReceiveBuffer.Enqueue(pack);
				var type = pack.packetHeader.type;
				type += pack.type == G2PacketType.DEFAULT ? " (unknown) " : "";
				G2Log.Write("PacketBuffer : Enqueued incoming packet " + type + " to receive  from " +pack.RemotePeer.ToString());
			}
		}
	}
}

