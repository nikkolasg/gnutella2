using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ActionInnocence.P2PScan.Plugins.Gnutella2.Struct
{
    public class G2UserProfile
    {
        public GUID Guid;
        public string Nickname;
        public string FirstName;
        public string LastName;
        public string Gender;
        public string Country;
        public string City;

        /**
        * generate a simple xml profile , with just guid and a nickname
        * */
        public  string generateXML()
        {
            StringBuilder b = new StringBuilder();
            b.Append("<?xml version=\"1.0\"?>\r\n");
            b.Append("<gProfile xmlns=\"http://www.shareaza.com/schemas/GProfile.xsd\">\r\n");
            b.Append("<gnutella guid=\"" + Guid.ToString() + "\"/>\r\n");
            b.Append("<identity> <handle primary=\"" + Nickname + "\"/></identity>\r\n");
            b.Append("</gProfile>");
            return b.ToString();
        }
    }
}
