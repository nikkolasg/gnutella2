using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Struct;
using ActionInnocence.P2PScan.Plugins.Gnutella2;
namespace ActionInnocence.P2PScan
{
    // delegate for the whole gnutella2 plugin
    public delegate void ApplicationMessageLog(string message);
    public class ProtocolPlugin : IProtocol
    {

        

        public static string ipMachine_;

        private G2Manager manager_;

        public static string pluginFolder_;
        // application logger
        public event MessageLogHandler NewLogMessage;

        public event SearchResultHandler NewResult;

        public static bool LogActive = true;




        #region IProtocol Members

        public ProtocolPlugin(string pluginFolder, string ipMachine)
        {
            ipMachine_ = ipMachine; // store this here, but IP will be caught in handshake packets anyway

            manager_ = new G2Manager(this);
            manager_.NewResult += new SearchResultHandler(manager__NewResult);

            // all classes uses G2Log, which write to file or console 
            // AND also to the application log due to this event
            G2Log.MessageLog += new ApplicationMessageLog(ApplicationLog);
            pluginFolder_ = pluginFolder;
        }


        public void ApplicationLog(string msg)
        {
            
            if (NewLogMessage != null) NewLogMessage(msg, GetProtocolName());
        }

        void manager__NewResult(SearchResult searchResult)
        {
            if (NewResult != null) NewResult(searchResult);
            if (NewLogMessage != null) NewLogMessage(searchResult.PeerCollection.Count + " Results for transaction " + searchResult.SearchTransaction.IdTransaction, GetProtocolName());

        }

        public void Connect()
        {
            manager_.StartService();
        }

        public void Disconnect()
        {
            if (NewLogMessage != null) NewLogMessage("Demande de déconnexion pour "+ GetProtocolName(), GetProtocolName());

            manager_.StopService();
        }

        public string GetProtocolName()
        {
            return Settings.PROTOCOL_NAME;
        }

        public ProtocolServersCollection GetServerList()
        {
            ProtocolServersCollection pservercoll_ = new ProtocolServersCollection();
            foreach (NodePeer p in GHubCache.Instance.ConnectedHubs)
                pservercoll_.Add(p);
            return pservercoll_;
        }



        public int SearchKeyword(SearchTransaction searchTransaction)
        {
            manager_.SearchKeyword(searchTransaction);
            return 1;
        }

        #endregion


    }
}
