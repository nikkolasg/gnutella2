using System;
using System.Text;
using System.Net;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Linq;
namespace ActionInnocence.P2PScan.Plugins.Gnutella2.Struct
{
	public class HeaderException : Exception
    {
        private string error;
        public HeaderException(string msg) : base(msg) 
        {
            error = "HeaderException: " + msg;
        }
        public override String ToString(){
            return error;
        }
    }

	public class HttpHeader
	{
		// protocol key really needed ?
      	public const string PROTOCOL_KEY = "Protocol";
        public const string PROTOCOL_INIT_VALUE = "GNUTELLA CONNECT/0.6";
        public const string PROTOCOL_VERSION_KEY = "Version";
        public const string PROTOCOL_CODE_KEY = "Code";
		public const string nl = "\r\n";
		public const string REMOTE_IP_KEY = "Remote-IP";
        public const string LISTEN_IP_KEY = "Listen-IP";
		public const string LISTEN_PORT_KEY = "Listen-Port";
		public const string USER_AGENT_KEY = "User-Agent";
        public const string USER_AGENT_DEFAULT_VALUE = "Sharelin 0.2.6";
        public const string ACCEPT_ENCODING_KEY = "Accept-Encoding";
		public const string CONTENT_ENCODING_KEY = "Content-Encoding";
		public const string ACCEPT_KEY = "Accept";
        public const string G2ACCEPT_DEFAULT_VALUE = "application/x-gnutella2";
		public const string CONTENT_TYPE_KEY = "Content-Type";
        public const string CONTENT_TYPE_G2_VALUE = "application/x-gnutella2";
		public const string IS_HUB_KEY = "X-Hub";
		public const string IS_ULTRA_PEER_KEY = "X-Ultrapeer";
		public const string HUB_NEEDED_KEY = "X-Hub-Needed";
        public const string TRY_HUBS_KEY = "X-Try-Hubs";
        public const string ENCODING_IDENTITY = "identity";
        public const string ENCODING_DEFLATE = "deflate";  
        public Dictionary<string,string> headers {get;set;}

        public HttpHeader() {
            headers = new Dictionary<string,string>();
        }
        public HttpHeader(Dictionary<string,string> dico) {

            headers = dico;
        }
        
		public string this[string key] {
			get
			{
				string v = null;
				bool suc = headers.TryGetValue(key,out v);
				if (suc)
					return v;
				return "";
			}
			set {
				headers [key] = value;
			}
		}

        public override String ToString() {
            StringBuilder builder = new StringBuilder();
            string str = "";
            if(headers.TryGetValue(PROTOCOL_KEY,out str))
                builder.Append(str + nl);
            else
                throw new HeaderException("No Protocol specified");

			foreach(KeyValuePair<string,string> kvp in headers) {
				if (kvp.Key == PROTOCOL_KEY)
					continue;
                builder.Append(kvp.Key + ": " + kvp.Value + nl);
            }
            builder.Append(nl);
            return builder.ToString();

        } 
        public static HttpHeader ParseHandshake(string msg) 
        {
			HttpHeader headers = new HttpHeader ();
           Match regex;
           regex = Regex.Match(msg,@"^(GNUTELLA)/(\d\.\d) (\d{3})",RegexOptions.Multiline | RegexOptions.IgnoreCase);
           if (!regex.Success)
				throw new HeaderException ("No match for client/version/code");
			
           headers[PROTOCOL_KEY]= regex.Groups [1].Value;
		   headers[PROTOCOL_VERSION_KEY] = regex.Groups [2].Value;
		   headers[PROTOCOL_CODE_KEY] = regex.Groups [3].Value;

			if (regex.Groups [3].Value.Equals ("503")) {
				G2Log.Write ("ParseHandshake HttpHeader : 503 Code found !");
				ParseTryHub (msg,headers);
				return (headers);
			}

			// is hub check
			regex = Regex.Match (msg, @"(X-Hub|X-Ultrapeer): (True|False)", RegexOptions.IgnoreCase|RegexOptions.Multiline);
			if (!regex.Success)
				throw new HeaderException ("No match for hub detection");


			bool _isHub = regex.Groups [2].Value.Equals("True") ? true : false;
			headers[IS_HUB_KEY] = regex.Groups [2].Value;
			// it is a leaf
			if(!_isHub) {
				ParseTryHub (msg,headers);
			}
			// it is a hub
			else {
				// retrieve hub's ip + port
				regex = Regex.Match (msg, @"^Listen-IP: (.*:.*)$",RegexOptions.IgnoreCase | RegexOptions.Multiline);
				if (regex.Success) {
					var info = regex.Groups [1].Value;
					headers[LISTEN_IP_KEY] = info.Split (':') [0];
					headers[LISTEN_PORT_KEY] = info.Split (':') [1];
				} else
					throw new HeaderException ("HttpHeader : hub ip / port not found.");

				ParseEncoding (msg, headers);

				// retrieve our self ip
				regex = Regex.Match (msg, @"Remote-IP: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", RegexOptions.IgnoreCase | RegexOptions.Multiline);
				if (!regex.Success) {
					throw new HeaderException ("HttpHeader : Parsing remote ip failed");
				}
				headers[REMOTE_IP_KEY]  = regex.Groups [1].Value;

			} 

            // content-type check
			regex = Regex.Match(msg, @"Content-Type: (.*)", RegexOptions.IgnoreCase | RegexOptions.Multiline);
           if(!regex.Success)
              G2Log.Write("ERROR HttpHeader : No Content Type Found");
			var contentType = regex.Groups [1].Value.TrimEnd ('\r', '\n');
			if (!contentType.Equals (CONTENT_TYPE_G2_VALUE))
				throw new HeaderException ("HttpHeader : Content Type error comparing :\n" + regex.Groups [1].Value + " vs " + CONTENT_TYPE_G2_VALUE);
			else
				headers [CONTENT_TYPE_KEY] = contentType;

            return headers;
        }

		private static void  ParseEncoding(string msg, HttpHeader headers) {
			Match regex = Regex.Match (msg, @"Accept-Encoding: (\w*)", RegexOptions.IgnoreCase | RegexOptions.Multiline);
			if (regex.Success)
				headers [ACCEPT_ENCODING_KEY] = regex.Groups [1].Value.TrimEnd ('\r', '\n');
			regex = Regex.Match (msg, @"Content-Encoding: (\w*)", RegexOptions.Multiline | RegexOptions.IgnoreCase);
			if (regex.Success)
				headers [CONTENT_ENCODING_KEY] = regex.Groups [1].Value.TrimEnd ('\r', '\n');
		}

		private static void ParseTryHub(string msg,HttpHeader headers) {
			Match regex = Regex.Match (msg, @"^X-Try-Hubs: (.*)$",RegexOptions.IgnoreCase | RegexOptions.Multiline );
			if (!regex.Success)
				throw new HeaderException ("HttpHeader : no hubs list given by the leaf");
			headers[TRY_HUBS_KEY] = regex.Groups[1].Value;
		}
        
		public List<NodePeer> getHubList() {
             string str = "";
             bool ret = headers.TryGetValue(TRY_HUBS_KEY,out str);
             if(!ret)
                 return null;

             string[] infos = str.Split(',');
			List<NodePeer> hubs = new List<NodePeer>();
             Match regex;
             foreach(string hub in infos) {
				regex = Regex.Match (hub, @"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{2,4}) (.*)", RegexOptions.Multiline | RegexOptions.IgnoreCase);
			    if (!regex.Success)
				    continue;
			    IPAddress _ip = IPAddress.Parse(regex.Groups [1].Value);
			    ushort _port = Convert.ToUInt16 (regex.Groups [2].Value);
				string time = regex.Groups [3].Value;
				hubs.Add(new NodePeer(_ip,_port,time,true));
			 }
			 if (hubs.Count == 0)
			    throw new HeaderException ("HttpHeader : ParseHandshake Try Hub : no hubs list retrieved");
			return hubs;   
			 
        }

	}


}
