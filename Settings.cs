using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Threading.Tasks;
using ActionInnocence.P2PScan.Plugins.Gnutella2.G2Packets;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Struct;
using System.Deployment;

namespace ActionInnocence.P2PScan.Plugins.Gnutella2
{
    public class Settings
    {
        /*****************
         * config file related members
         * File name & default separator value , ex:
         * attribut:value
         * */
        private const string CONFIG_FILE_NAME = @"gnutella2.conf";
        private const char DEFAULT_SPLIT_VALUE = ':';

        public static int LOG_OUTPUT = G2Log.CONSOLE;

        public static string LOG_OUTPUT_FILE = G2Log.FILE_NAME;


        public static string PROTOCOL_NAME = @"Gnutella 2";
        /*
         * to how many hubs shall we send a query
         * */
        public static  int PEER_DISPATCH_QUERY = 4;

        public static  string USER_AGENT = @"Shareaza 2.7.2.0";
        /**
         * Do we consider servent hosting partial files ? 
         * */
        public static bool ACCEPT_PARTIAL_FILE = false;
        /*
         * How much time do we wait for browsing a servent (in msec) 
         * */
        public static int WAIT_TIME_BROWSING_MS = 8 * 1000;
        /** 
         * How much time do we wait for results before sending it to application
         * */
        public static int SEARCH_TIME_OUT_MS = 35 * 1000;
        private static string[] SmartNickNames_ = new string[] {"John","Obama","mary","batmanou"};

        public static short Port = 6346;
        private static  string SmartNickName() 
        {
            Random r = new Random();
            int ind = r.Next(SmartNickNames_.Length);
            return SmartNickNames_[ind];
        }
        
       
        public static G2UserProfile SmartUserProfile()
        {
            G2UserProfile profile = new G2UserProfile();
            profile.Nickname = SmartNickName();
            profile.Guid = GUID.generateGuid();
            return profile;
        }
        public static G2PacketLNI SmartLNIPacket()
        {
            G2PacketLNI root = new G2PacketLNI();
            G2PacketGU guid = new G2PacketGU(GUID.generateGuid());
            root.AddChild(guid);

            NodeAddress self = new NodeAddress(G2Network.Instance.SelfAddress, G2Network.Instance.SelfPort);
            G2PacketNA na = new G2PacketNA(self);
            root.AddChild(na);

            G2PacketV v = new G2PacketV ("RAZA");
            root.AddChild (v);

            root.FinalizePacket();
            return root;
        }

        public static void ReadSettings()
        {

            try
            {
                string path = Directory.GetCurrentDirectory() + "\\" + CONFIG_FILE_NAME;
                FileInfo info = new FileInfo(path);
                if (!info.Exists)
                {
                    G2Log.Write("Settings : Config File Not Found . Default values ...");
                    return;
                }
                using (StreamReader reader = new StreamReader(info.FullName))
                {
                    string line = null;
                    while ((line = reader.ReadLine()) != null)
                    {
                        ParseLine(line);
                    }
                }

                
            }
            catch (Exception e)
            {
                G2Log.Write("Settings : Error while parsing config file ... " + e.ToString());
            }

        }
        private static void ParseLine(string line)
        {
            if (line.StartsWith("#")) return;
            string[] info = line.Split(DEFAULT_SPLIT_VALUE);
            if (info.Length < 2) return;
            string attr = info[0].ToLower().Trim();
            string value = info[1].Trim();
            bool succ = false;
            switch (attr)
            {
                case "protocol_name":
                    PROTOCOL_NAME = value;
                    break;
                case "user_agent" :
                    USER_AGENT = value;
                    break;
                case "peer_dispatch_query":
                    int n = 0;
                    succ = Int32.TryParse(value,out n);
                    if (succ)
                        PEER_DISPATCH_QUERY = n;
                    break;
                case "accept_partial_file":
                    bool acc = false;
                    succ = Boolean.TryParse(value, out acc);
                    if (succ)
                        ACCEPT_PARTIAL_FILE = acc;
                    break;
                case "nicknames":
                    string[] names = value.Split(',');
                    if (names.Length < 2)
                        return;
                    SmartNickNames_ = new string[names.Length];
                    for (int i = 0; i < names.Length; i++)
                        SmartNickNames_[i] = names[i];
                    break;
                case "wait_time_browsing_ms":
                    int wait = 0;
                    succ = Int32.TryParse(value, out wait);
                    if (succ)
                        WAIT_TIME_BROWSING_MS = wait;
                    break;
                case "search_timeout_ms":
                    int search = 0;
                    succ = Int32.TryParse(value, out search);
                    if (succ)
                        SEARCH_TIME_OUT_MS = search;
                    break;
                case "log_output":
                    int log = 0;
                    succ = Int32.TryParse(value, out log);
                    if (succ)
                    {
                        if (log == G2Log.FILE)
                            LOG_OUTPUT = G2Log.FILE;
                        else if (log == G2Log.CONSOLE)
                            LOG_OUTPUT = G2Log.CONSOLE;
                    }
                    break;
                case "log_output_file":
                    LOG_OUTPUT_FILE = value;
                    break;
                    
                    
                        
            }
        }
    }
}
