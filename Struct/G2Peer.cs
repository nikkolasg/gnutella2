using System;
using ActionInnocence.P2PScan.Plugins.Gnutella2.G2Packets;

namespace ActionInnocence.P2PScan.Plugins.Gnutella2.Struct
{
	public class G2Peer : ActionInnocence.P2PScan.Peer, IEquatable<G2Peer>
	{
		public override string ToString ()
		{
			return "Peer " + base.Id + ", pseudo: " + base.Nickname + " Vendor:" + VendorCode
			+ (Browsable ? "Browsable" : "") + ", DNS:" + DNSName;
		}

		public bool Firewalled { get; set; }
		public bool Browsable { get; set; }
		public string VendorCode  { get; set; }
		public string DNSName { get; set; }
		public ActionInnocence.P2PScan.PeerCollection AlternatePeers;
		private G2Peer (String ip,String id, int port, String nickname) : base(ip,id,port,nickname) {
			AlternatePeers = null;
		}

		/** G2Peer will parse the packet itself to get the relevant info
		 * **/
		public static G2Peer ParseG2Peer(G2PacketQH2 resultPacket) {
			NodeAddress node = getAddressFromQueryHit (resultPacket);
			if (node == null)
				return null;
			string nickname = getNickFromQueryHit (resultPacket);
            GUID g = ((G2PacketGU)(resultPacket.getFirstChildPacket(G2PacketType.GU))).nodeGuid;
			G2Peer peer = new G2Peer (node.ipv4.ToString (), BitConverter.ToString(g.bytes), node.port, nickname);
			peer.Browsable = resultPacket.getFirstChildPacket (G2PacketType.BH) == null ? false : true;
			peer.Firewalled = resultPacket.getFirstChildPacket (G2PacketType.FW) == null ? false : true;
			peer.VendorCode = resultPacket.getStringFromChildType (G2PacketType.V);
			peer.DNSName = resultPacket.getStringFromChildType (G2PacketType.DNS);
			peer.AlternatePeers = getAlternateLocationsFromQueryHit (resultPacket);

			return peer;
		}
		private static ActionInnocence.P2PScan.PeerCollection getAlternateLocationsFromQueryHit(G2PacketQH2 qh2) {
			G2Packet pack = qh2.getFirstChildPacket (G2PacketType.ALT);
			if (pack == null)
				return null;
			G2PacketALT altPack = pack as G2PacketALT;
			ActionInnocence.P2PScan.PeerCollection coll = new ActionInnocence.P2PScan.PeerCollection ();
			foreach (NodeAddress add in altPack.Addresses) {
				coll.Add (new ActionInnocence.P2PScan.Peer(add.ipv4.ToString(),add.ToString(),add.port,""));
			}
			return coll;
		}
		private string getDNSNameFromQueryHit(G2PacketQH2 qh2) {
			G2Packet dns = qh2.getFirstChildPacket (G2PacketType.DNS);
			if (dns == null)
				return "";
			return ((G2PacketDNS)dns).Str;
		}
		private string getVendorCodeFromQueryHit(G2PacketQH2 qh2) {
			G2Packet vendorPacket = qh2.getFirstChildPacket (G2PacketType.V);
			if (vendorPacket == null) {
				return "";
			}
			return ((G2PacketV)vendorPacket).Str;
		}
		/** Search address of the servent
		 *  may be null
		**/
		private static NodeAddress getAddressFromQueryHit(G2PacketQH2 qh2) {
			G2Packet p = qh2.getFirstChildPacket (G2PacketType.NA);
			if (p == null)
				return null;
			G2PacketNA na = p as G2PacketNA;
			return na.node;
		}
		/*		*
		 * Return the nickname if there is one 
		 * otherwise return empty string
		 * */
		private static String getNickFromQueryHit(G2PacketQH2 qh2) {
			G2Packet upro = qh2.getFirstChildPacket (G2PacketType.UPRO);
			if (upro == null)
				return "";
			G2Packet nick = upro.getFirstChildPacket (G2PacketType.NICK);
			if (nick == null)
				return "";

			return ((G2PacketNICK)nick).Str;
		}



		public bool Equals(G2Peer p) {
			if (!this.Ip.Equals (p.Ip))
				return false;
			if (!this.Port.Equals (p.Port))
				return false;
			return true;
		}
		public override bool Equals (object obj) {
			if (!obj.GetType ().Equals (this.GetType ()))
				return false;
			G2Peer p = (G2Peer)obj;
			return this.Equals (p);
		}

		public override int GetHashCode (){
			return Ip.GetHashCode () + Port.GetHashCode ();
		}
	}
}

