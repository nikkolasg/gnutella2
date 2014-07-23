using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Text;
using System.Text.RegularExpressions;
using System.IO;
using System.Collections.Generic;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Struct;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Network;
namespace ActionInnocence.P2PScan.Plugins.Gnutella2
{

	public class GHandshake
	{
		private NodePeer remote_host;
		public  string Encoding { get; set; }
		public TCPConnection tcp;
		// tells if we have found a hub ready to connect or not

		public GHandshake (NodePeer remoteHost)
		{
			this.remote_host = remoteHost;
            tcp = TCPConnection.getPeerConnection(remoteHost);
			Encoding = HttpHeader.ENCODING_IDENTITY;

		}

		private void setEncoding(HttpHeader header) {
			if (Encoding == HttpHeader.ENCODING_DEFLATE) {
				header [HttpHeader.ACCEPT_ENCODING_KEY] = HttpHeader.ENCODING_DEFLATE;
				header [HttpHeader.CONTENT_ENCODING_KEY] = HttpHeader.ENCODING_DEFLATE;
			}
		}
		// True if connected to a hub
		// false if attempted to connect to a leaf ( but has certainly retrieved many hubs )
		public bool TryConnect() {
			try {
				bool success = false;
			G2Log.Write ("GHandshake : Try to connect to " + remote_host.ToString ());
			var isConnected = tcp.Connect();
            if(!isConnected) {
                return false;
            }
			OnConnected ();
			success = OnResponse ();
			if(success) {
					//bool connected = tcp.CheckConnection();
					//Log.Write("GHandshake : Connected ? " + connected);
				OnReply();	
			}
			else
				tcp.Close();

	    	return success;
			} catch (Exception e) {
				tcp.Close ();
				return false;
			}

		}
		/**
		 * When the response of the hub is successful, we terminate the handshake
		 * */
		private void OnReply() {
			try {
				HttpHeader h = new HttpHeader();
				h[HttpHeader.PROTOCOL_KEY] = "GNUTELLA/0.6 200 OK";
				h[HttpHeader.CONTENT_TYPE_KEY] = HttpHeader.CONTENT_TYPE_G2_VALUE;
				h[HttpHeader.IS_HUB_KEY] = "False";
				//h[HttpHeader.IS_ULTRA_PEER_KEY] = "False";
//				/** TODO check if encoding is present **/
				setEncoding(h);
				byte[] msg = System.Text.Encoding.ASCII.GetBytes(h.ToString());
				bool byte_sent = tcp.Send(new ByteBuffer(msg));
			} catch (ArgumentNullException ane) {
                throw new ArgumentNullException("GHandshakeOnReply() : {0}", ane.ToString());
			} catch (SocketException se) {
                throw new NetException("GHandshakeOnReply() : " + se.ToString());
			} catch (Exception e) {
				G2Log.Write("GHandshake ERROR OnReply() : " + e.ToString());
			}
		}
        /**
         * Send first message handshake
         * */
		public void OnConnected() {
            HttpHeader header = new HttpHeader();
            header.headers[HttpHeader.PROTOCOL_KEY] = HttpHeader.PROTOCOL_INIT_VALUE;
			header.headers[HttpHeader.REMOTE_IP_KEY] = remote_host.Address.ToString();
			//header.headers [HttpHeader.REMOTE_IP_KEY] = "128.179.143.241";
			setListenIP (header);
			header.headers[HttpHeader.USER_AGENT_KEY] = HttpHeader.USER_AGENT_DEFAULT_VALUE;
			header.headers[HttpHeader.ACCEPT_KEY] = HttpHeader.G2ACCEPT_DEFAULT_VALUE;
			header.headers[HttpHeader.IS_HUB_KEY] = "False";
			//header.headers [HttpHeader.IS_ULTRA_PEER_KEY] = "False";
			header [HttpHeader.HUB_NEEDED_KEY] = "True";
			setEncoding (header);
            string strMsg = header.ToString();
			byte[] msg = System.Text.Encoding.ASCII.GetBytes(strMsg);
			bool byte_sent = tcp.Send(new ByteBuffer(msg));

		}
		private void setListenIP(HttpHeader h) {
			var ip = G2Network.Instance.SelfAddress;
			if (ip != null)
				h [HttpHeader.LISTEN_IP_KEY] = ip.ToString () + ":"+G2Network.Instance.SelfPort;
		}
        /**
         * Handles the response of the remote host,
         * comes after OnConnected
         * */
		public Boolean OnResponse() {
			ByteBuffer readBuffer = tcp.Read();
			if (readBuffer == null)
				return false;
			int byte_received = readBuffer.DataOffset;

            if (byte_received <= 0) throw new NetException("GHandshake OnResponse : no responses ");

			string msg = System.Text.Encoding.ASCII.GetString(readBuffer.Bytes,0,readBuffer.DataOffset);

			return handleReply(msg);
		}

        
		/**
		 * Return true IF it it a hub
		 * FALSE it is a peer OR a hub with max connection reached
		 * */
		private Boolean handleReply(string msg) {
			HttpHeader h;
			try {
				h = HttpHeader.ParseHandshake(msg);

			} catch (HeaderException e) {
				Console.Error.WriteLine (e);
				return false;
			}

			if (h[HttpHeader.PROTOCOL_CODE_KEY] == "200" && h[HttpHeader.IS_HUB_KEY] == "True") {
				HandleHub(h);
				return true;
			} else {
				HandleErrorHeader (h);
				return false;
			}
		}

		private void HandleErrorHeader(HttpHeader h) {
			List<NodePeer> hubs = h.getHubList ();
			hubs.ForEach(x => GHubCache.Instance.AddHub(x));
			G2Log.Write ("ParseErrorHeader() : Retrieved " + hubs.Count + " hubs" );

		}


		private void HandleHub(HttpHeader header) {

			IPAddress _listen_ip = IPAddress.Parse (header[HttpHeader.LISTEN_IP_KEY]);
			ushort _listen_port = Convert.ToUInt16 (header[HttpHeader.LISTEN_PORT_KEY]);

			string encoding = header[HttpHeader.ACCEPT_ENCODING_KEY]; 

			string _remote_ip = header[HttpHeader.REMOTE_IP_KEY];
			
			GHubCache cache = GHubCache.Instance;

			IPAddress self = IPAddress.Parse(_remote_ip);
			G2Network.Instance.SelfAddress = self;

			if (_listen_ip != null && _listen_port > 0 && _listen_port < 65000) {
				remote_host = new NodePeer (_listen_ip, _listen_port, DateTime.Now.ToString (), true);
			}

		}
	}
}

