using System;
using System.IO;
using System.Diagnostics;
using Microsoft.Win32;
using Microsoft.CSharp;
using System.Runtime.InteropServices;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Struct;
using ActionInnocence.P2PScan.Plugins.Gnutella2.G2Packets;
namespace ActionInnocence.P2PScan.Plugins.Gnutella2
{
    public class G2PacketReader
    {
        private NodePeer peer; // Peer to which packets arrives 
        private ByteBuffer Buffer;
        public G2PacketReader(NodePeer p)
        {
            peer = p;
            Buffer = new ByteBuffer();
        }

        private bool ReadFromBuffer()
        {
            if (Buffer.Empty)
                return true;

            MemoryStream stream = Buffer.ToStream();
            try
            {
                G2Packet pack;
                int bRead = ReadPacket(stream, out pack);
                pack.RemotePeer = peer;
                peer.GotPacket(pack);
                int totalRead = (int)pack.getTotalPacketLength();

                //Debug.Assert(bRead == totalRead, "ReadFromBuffer : bRead = " + bRead + " vs totalRead = " + totalRead);

                if (totalRead == Buffer.DataOffset)
                { // buffer completely and uniquely stored the packet
                    Buffer.Flush();
                }
                else if (totalRead < Buffer.DataOffset)
                { // buffer contains some other data
                    Buffer.Dequeue(totalRead); // remove data already read
                    return ReadFromBuffer(); // read others packets contained
                }
                return true;
            }
            catch (NotEnoughDataException e)
            {
                return false;
            }
			catch (PacketException e)
            { // big endian for example
                Buffer.Flush();
                return true;
            }
        }

        /**
         * Read a packet from an array of bytes
         * return true if there is enough data to read all packets inside buffer
         * return false if you need more data to complete the construction of pack
         * NOTE : out G2Packet pack may not be null while function return false,
         * you can have several packets lined up, and enough data to read one
         * */
        public bool Read(byte[] bytes, int bRead)
        {
            Buffer.Append(bytes, bRead);
            return ReadFromBuffer();
        }

        
        public bool Read(ByteBuffer b)
        {
            Buffer.Append(b);
            return ReadFromBuffer();
        }

        public void Flush()
        {
            Buffer.Flush();
        }
        private int ReadPacket(MemoryStream stream, out G2Packet pack)
        {


            Header h = null;
            try
            {
                h = Header.ReadHeader(stream);
            }
			catch (Exception e) {
				throw e;
			}
            int packLength = (int)(h.PayloadLength + h.HeaderLength);
            // if stream is not enough big to contain all the packet we need to read more
            if (packLength > stream.Length)
                throw new NotEnoughDataException("Not enough data in buffer");

            pack = G2PacketType.getPacketByHeader(h);
            // Set the remote host into packet for further analysis
            pack.RemotePeer = this.peer;

            // we have a unknown packet so we just read till the end of the packet
            if (pack.type == G2PacketType.DEFAULT)
            {
                // anyway, read & store the bytes
                return (int)(h.HeaderLength + pack.ReadPayload(stream, h.PayloadLength));
            }

            // we have read header, now we calculate how much byte we need to read more (children + payload)
            int byteToRead = h.PayloadLength;
            int byteRead = 0;
            bool endOfChildStream = false;

            if (h.compound)
            {

                while (true)
                {

                    G2Packet childPacket;
                    try
                    {
                        int bRead = ReadPacket(stream, out childPacket);
                        //Debug.Assert(bRead == childPacket.getTotalPacketLength(),
                            //"ReadPacket:ChildPacket " + childPacket.type + "  bRead = " + bRead + " vs " + childPacket.getTotalPacketLength());
                    }
                    catch (BigEndianPacketException e)
                    {
                        throw e;
                    }
                    catch (EndOfStreamException e)
                    {
                        byteRead += 1;
                        break;
                    }

                    pack.AddChild(childPacket);
                    byteRead += childPacket.getTotalPacketLength();
                    // root packet does NOT have a payload 
                    if (byteRead == byteToRead)
                    {
                        endOfChildStream = true;
                        break;
                    }

                }
            }
            // have to count the remaining bytes, because length in header includes child packets.
            if (!endOfChildStream && (byteRead < byteToRead))
                byteRead += pack.ReadPayload(stream, byteToRead - byteRead);


            // return total read byte number
            return (int)(byteRead + h.HeaderLength);
        }


    }
}

