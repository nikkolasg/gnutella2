using System;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Struct;
namespace  ActionInnocence.P2PScan.Plugins.Gnutella2.G2Packets {

    class G2PacketType  {
        public const string UPROC = "UPROC";
        public const string UPROD = "UPROD";
        public const string XML = "XML";
		public  const string QKR = "QKR";
		public 	const  string QKA = "QKA";
		public  const string Q2 = "Q2";
        public const string D = "D";
		public  const string DN = "DN";
		public  const string QA = "QA";
		public  const string RA = "RA";
		public  const string QH2 = "QH2";
		public  const string GU = "GU";
		public  const string NA = "NA";
		public  const string BH = "BH";
		public  const string NICK = "NICK";
		public  const string UPRO = "UPRO";
		public  const string URL = "URL";
		public  const string URN = "URN";
		public  const string HIT = "H";
		public const string LNI = "LNI";
		public const string PI = "PI";
		public const string PO = "PO";
		public const string UDP = "UDP";
		public const string QNA = "QNA";
		public const string QK = "QK";
		public const string SNA = "SNA";
		public const string V = "V";
		public const string LS = "LS";
		public const string HS = "HS";
		public const string TLS = "TLS";
		public const string H = "H";
		public const string BUP = "BUP";
		public const string FW = "FW";
		public const string NH = "NH";
		public const string HG = "HG";
		public const string SS = "SS";
        public const string S = "S";
		public const string KHL = "KHL";
		public const string TS = "TS";
		public const string MD = "MD";
		public const string SZ = "SZ";
		public const string COM = "COM";
		public const string PVU = "PVU";
		public const string ALT = "ALT";
		public const string CT = "CT";
        public const string PART = "PART";
		public const string DNS = "HN"; // CAREFUL if moving to a reflection method, these are not equal
		public const string DEFAULT = "DEFAULT";

		public static G2Packet getPacketByHeader(Header h) {
			G2Packet packet = null;
			switch(h.type) {
			case G2PacketType.PVU:
				packet = new G2PacketPVU (h);
				break;
			case G2PacketType.COM: 
				packet = new G2PacketCOM (h);
				break;
            case G2PacketType.PART:
                packet = new G2PacketPART(h);
                break;
			case G2PacketType.SZ:
				packet = new G2PacketSZ (h);
				break;
			case G2PacketType.Q2:
				packet = new G2PacketQ2 (h);
				break;
			case G2PacketType.DN:
				packet = new G2PacketDN (h);
				break;
			case G2PacketType.KHL:
				packet = new G2PacketKHL (h);
				break;
			case G2PacketType.QA:
				packet = new G2PacketQA (h);
				break;
			case G2PacketType.SS:
				packet = new G2PacketSS (h);
				break;
			case G2PacketType.QH2:
				packet = new G2PacketQH2 (h);
				break;
			case G2PacketType.HG:
				packet = new G2PacketHG (h);
				break;
			case G2PacketType.PI:
				packet = new G2PacketPI (h);
				break;
			case G2PacketType.UDP:
				packet = new G2PacketUDP (h);
				break;
			case G2PacketType.PO:
				packet = new G2PacketPO (h);
				break;
            case G2PacketType.S:
                packet = new G2PacketS(h);
                break;
            case G2PacketType.D:
                packet = new G2PacketD(h);
                break;
			case G2PacketType.LNI:
				packet = new G2PacketLNI (h);
				break;
			case G2PacketType.GU:
				packet = new G2PacketGU (h);
				break;
			case G2PacketType.NA:
				packet = new G2PacketNA (h);
				break;
			case G2PacketType.QKR:
				packet = new G2PacketQKR (h);
				break;
			case G2PacketType.QKA:
				packet = new G2PacketQKA (h);
				break;
			case G2PacketType.SNA:
				packet = new G2PacketSNA (h);
				break;
			case G2PacketType.QNA:
				packet = new G2PacketQNA (h);
				break;
			case G2PacketType.V:
				packet = new G2PacketV (h);
				break;
			case G2PacketType.LS:
				packet = new G2PacketLS (h);
				break;
			case G2PacketType.HS:
				packet = new G2PacketHS (h);
				break;
			case G2PacketType.TLS:
				packet = new G2PacketTLS (h);
				break;
			case G2PacketType.TS:
				packet = new G2PacketTS (h);
				break;
			case G2PacketType.NH:
				packet = new G2PacketNH (h);
				break;
			case G2PacketType.RA:
				packet = new G2PacketRA (h);
				break;
			case G2PacketType.BUP:
				packet = new G2PacketBUP (h);
				break;
			case G2PacketType.H:
				packet = new G2PacketH (h);
				break;
			case G2PacketType.URL:
				packet = new G2PacketURL (h);
				break;
			case G2PacketType.URN:
				packet = new G2PacketURN (h);
				break;
			case G2PacketType.UPRO:
				packet = new G2PacketUPRO (h);
				break;
			case G2PacketType.NICK:
				packet = new G2PacketNICK (h);
				break;
			case G2PacketType.BH:
				packet = new G2PacketBH (h);
				break;
			case G2PacketType.FW:
				packet = new G2PacketFW (h);
				break;
			case G2PacketType.MD:
				packet = new G2PacketMD (h);
				break;
            case G2PacketType.UPROC:
               packet = new G2PacketUPROC(h);
               break;
            case G2PacketType.UPROD :
               packet = new G2PacketUPROD(h);
               break;
           case G2PacketType.XML:
               packet = new G2PacketXML(h);
               break;
			default :
				packet = new G2PacketDefault (h);
				break;

			}
			return packet;
		}

    }
}
