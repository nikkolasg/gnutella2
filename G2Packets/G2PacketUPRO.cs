using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using System.Xml;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Struct;
namespace  ActionInnocence.P2PScan.Plugins.Gnutella2.G2Packets
{
    class G2PacketUPROC : G2Packet
    {
        public G2PacketUPROC(Header h) : base (h)
        {
            this.type = G2PacketType.UPROC;
        }
        public override int getPayloadLength()
        {
            return 0;
        }
        protected override string PayloadToString()
        {
            return "Profile Challenge";
        }
        public override int ReadPayload(System.IO.MemoryStream stream, int length)
        {
            return 0;
        }
        public override int WritePayload(System.IO.MemoryStream stream)
        {
            throw new NotImplementedException();
        }
    }
    public class G2PacketUPROD : G2Packet
    {
        public G2PacketUPROD(Header h) : base(h)
        {
            this.type = G2PacketType.UPROD;
        }
        public G2PacketUPROD() : base()
        {
            this.type = G2PacketType.UPROD;
        }
        public override int getPayloadLength()
        {
            return 0;
        }
        protected override string PayloadToString()
        {
            return "User Profile Delivery";
        }
        public override int WritePayload(System.IO.MemoryStream stream)
        {
            return 0;
        }
        public override int ReadPayload(System.IO.MemoryStream stream, int length)
        {
            return 0;
        }
    }
    public class G2PacketXML : G2PacketString
    {
        public G2UserProfile profile;
        public G2PacketXML(Header h ) : base(h)
        {
            this.type = G2PacketType.XML;
            this.profile = null;
        }
        public G2PacketXML(G2UserProfile prof) : base()
        {
            this.type = G2PacketType.XML;
            this.profile = prof;
            this.Str = this.profile.generateXML();
            this.bytes = BinaryUtils.getNullTerminatedBytesFromString(this.Str);
        }

        protected override string PayloadToString()
        {
            return "User Profile : " + this.Str;
        }

        public override int ReadPayload(System.IO.MemoryStream stream, int length)
        {
            int bread =  base.ReadPayload(stream, length);
            this.profile = new G2UserProfile();
            try
            {
               
                XElement xml = XElement.Parse(base.Str);
                XElement child = null;
                XAttribute attr = null;

                child = xml.Element("gnutella"); // get GUID
                if (child != null)
                    profile.Guid = new GUID(child.Value);
                child = null;

                child = xml.Element("identity");
                if(child != null)
                attr = child.Element("handle").Attribute("primary"); // get nickname
                if (attr != null) 
                    profile.Nickname = attr.Value;
                attr = null;

                child = xml.Element("identity");
                if(child != null)
                {
                    child = child.Element("name");
                    if (child != null)
                    {
                        attr = child.Attribute("first"); // get first name
                        if (attr != null)
                            profile.FirstName = attr.Value;
                        attr = null;
                        attr = child.Attribute("last"); // get last name
                        if (attr != null)
                            profile.LastName = attr.Value;
                        attr = null;
                        child = null;
                    }
                }
                child = xml.Element("location");
                if(child != null)
                {
                    child = child.Element("political");
                    if (child != null)
                    {
                        attr = child.Attribute("city"); // get city
                        if (attr != null)
                            profile.City = attr.Value;

                        attr = child.Attribute("country"); // getcountry
                        if (attr != null)
                            profile.Country = attr.Value;

                    }
                }


            } catch (Exception e) {
                G2Log.Write("UPROD parsing " + base.Str + " : " + e.ToString());
            }
            return bread;
        }
    }
}
