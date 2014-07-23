using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Sockets;
using System.Timers;
using System.Net;
using System.Text.RegularExpressions;
using ActionInnocence.P2PScan.Plugins.Gnutella2.G2Packets;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Struct;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Network;

namespace ActionInnocence.P2PScan.Plugins.Gnutella2.Search
{
    /** The ip from which we are testing to browse
     * */
    public delegate void BrowseSearchEnd(Peer p, SearchResult results,List<G2PacketQH2> packetResults);
    /**
     * Class that will make a http request to the peer given 
     * and collect all resultings QH2 packets coming
     * WARNING Since we will launch new connection we must make sure this address is not 
     * one of the already connected hub !!
     * */
    public class G2BrowseSearch
    {
        
        private Timer SearchTimer;

        public event BrowseSearchEnd EndSearch;
        private List<G2PacketQH2> packetResults;
        private NodePeer Peer;
        private G2PacketReader reader;

        private ActionInnocence.P2PScan.Peer referenceToPeer; // to bring back to 
        private SearchResult referenceToSearchResults; // g2 search results
        public G2BrowseSearch(Peer peerToBrowse,SearchResult results)
        {
            referenceToPeer = peerToBrowse;
            referenceToSearchResults = results;
            
            IPAddress add = null;
            bool succ = IPAddress.TryParse(peerToBrowse.Ip, out add);

            Peer = new NodePeer(new NodeAddress(add, (ushort)peerToBrowse.Port),false);
            Peer.isHub = false;

            packetResults = new List<G2PacketQH2>();
            

            reader = null;
        }

        public void StartBrowsing()
        {
            
            TCPConnection con = TCPConnection.getPeerConnection(Peer);
            if (!con.Connect())
            {
                G2Log.Write("G2BrowseSearch could not connect to Peer " + this.Peer.ToString());
                if (EndSearch != null) EndSearch(referenceToPeer,referenceToSearchResults, packetResults);
                return;
            }
            if (!SendHttpRequest(con))
            {
                if (EndSearch != null) EndSearch(referenceToPeer, referenceToSearchResults, packetResults);
                Peer.Close();
                return;
            }

            bool streaming = ReadResponseHeader(con);
            if (!streaming)
            {
                if (EndSearch != null) EndSearch(referenceToPeer, referenceToSearchResults, packetResults);
                Peer.Close();
                return;
            }

            // start to  read the flow of packets
            this.Peer.connection = new HubSocket(this.Peer, con.sock, reader);
            this.Peer.connection.Start();
            

            G2Log.Write("G2BrowseSearch : browsing peer " + Peer.ToString() + " ...");
            SearchTimer = new Timer(Settings.WAIT_TIME_BROWSING_MS);
            SearchTimer.Elapsed += new ElapsedEventHandler(SearchTimeOut);
            SearchTimer.AutoReset = false;
            
            SearchTimer.Start();
           
        }
        private bool SendHttpRequest(TCPConnection con)
        {
            HttpHeader header = new HttpHeader();
             
            string request = @"GET / HTTP/1.1" + HttpHeader.nl;
            request += HttpHeader.ACCEPT_KEY + ": " + @"text/html, " + HttpHeader.G2ACCEPT_DEFAULT_VALUE + HttpHeader.nl;
            request += HttpHeader.USER_AGENT_KEY + ": " + Settings.USER_AGENT + HttpHeader.nl;
            request += HttpHeader.ACCEPT_ENCODING_KEY + @": identity" + HttpHeader.nl;
            request += @"Connection: close" + HttpHeader.nl ;
            request += @"Host: " + Peer.Address.ToString() + ":" + Peer.Port;
            request += HttpHeader.nl + HttpHeader.nl;

            bool succ = con.Send(new ByteBuffer(BinaryUtils.getSimpleBytesFromString(request)));
            return succ;
        }
        /**
         * Read the response header to see if there are packets 
         * sometimes , browsable packet is present but servent has disactivated for G2 network
         * (shaeraza)
         * return true if servent will stream g2packets 
         * return false if not (html code listing neighbours / or nothing)
         * */
        public bool ReadResponseHeader(TCPConnection con)
        {
            ByteBuffer resp = con.Read();
            if (resp == null) return false;
            string text = BinaryUtils.getStringFromBytes(resp.Bytes,(int)resp.DataOffset);
            
            string sequence = HttpHeader.nl + HttpHeader.nl;
            string[] splitter = {sequence};
            string[] header = text.Split(splitter,StringSplitOptions.RemoveEmptyEntries);
            if (header.Length < 2) return false;
            // check if the http header is OK i.e. will the servent stream g2 packets ?
            if (!ParseBrowsingResponse(header[0]))
            {
                return false;
            }

            // remove the http header part from the buffer
            int dataOffset = text.IndexOf(sequence) + sequence.Length;
            resp.Dequeue(dataOffset);
            // put available data into the reader
            reader = new G2PacketReader(this.Peer);
            reader.Read(resp);
            return true;
        }
        /**
         * Stop the connection to the peer,
         * and sends the results back
         * */
        private void SearchTimeOut(Object sender, EventArgs args)
        {
            
            G2Packet pack = null;
            while ((pack = Peer.Buffer.PollPacketToReceive()) != null)
            {
                G2PacketQH2 qh2 = pack as G2PacketQH2;
                if (qh2 == null)
                    continue;
                packetResults.Add(qh2);
            }

            Peer.Close();

            if (EndSearch != null) EndSearch(referenceToPeer,referenceToSearchResults, packetResults);
        }

        /**
        * str contains the text until \r\n\r\n is reached
        * */
        public  bool ParseBrowsingResponse(string str)
        {
            HttpHeader header = new HttpHeader();
            string[] lines = str.Split(new string[] { HttpHeader.nl }, StringSplitOptions.RemoveEmptyEntries);
            if (lines.Length < 2) return false;
            // analyse http response code
            Match regex = Regex.Match(lines[0], @"HTTP/1.[01] (\d{3}) .*");
            if (!regex.Success)
                return false;
            string code = (regex.Groups[1].Value);
            if (code != "200") return false;

            // analyse further header, such as content-type 
            // if it is application/x-gnutella2 it is good !
            foreach (string line in lines.Skip(1))
            {
                string[] parts = line.Split(':');
                if (parts.Length < 2) continue;

                if (String.Equals(parts[0], HttpHeader.CONTENT_TYPE_KEY))
                {
                    if (String.Equals(parts[1].Trim(), HttpHeader.CONTENT_TYPE_G2_VALUE))
                    {
                        return true;
                    }
                }
            }
            return false;

        }

    }
}
