using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Search;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Struct;
namespace ActionInnocence.P2PScan.Plugins.Gnutella2
{
    class G2Manager
    {
        public event SearchResultHandler NewResult;

        private ProtocolPlugin protocol_;

        

        private SearchResultRegroupingCollection searchResultRegroupingKeyword_;
        private System.Collections.Queue queueKeywords;
        private G2Network network;
        private G2SearchManager searchManager;
        public G2Manager(ProtocolPlugin proto)
        {
            protocol_ = proto;
            network = G2Network.Instance;
            searchManager = G2SearchManager.Instance;
            searchManager.ResultFind += new SearchResultHandler(SearchKeywordResult);

            searchResultRegroupingKeyword_ = new SearchResultRegroupingCollection();
        }

        public void StartService()
        {
            network.StartNetwork();
        }

        public void StopService()
        {
            network.StopNetwork();
        }

 

        public void SearchKeyword(SearchTransaction searchTransaction)
        {

            queueKeywords = new System.Collections.Queue();

            try
            {

                //pour chaque keyword on lance le search dans un thread séparé
                foreach (Keyword k in searchTransaction.Keywords)
                {
                    KeywordCollection keyword = null;
                    SearchTransaction searchTrans = null;
                    keyword = new KeywordCollection();
                    keyword.Add(k);
                    searchTrans = new SearchTransaction(searchTransaction.IdTransaction, keyword, searchTransaction.MinFileFromPeerFilter, searchTransaction.IpAcceptRangeCollection);
                    queueKeywords.Enqueue(searchTrans);
                }

                // regrouping of results for this transaction 
                // will raise the CompletResultHandler event when we received one results for each keyword
                G2SearchResultRegrouping searchRegrouping = new G2SearchResultRegrouping(searchTransaction, searchTransaction.Keywords.Count, false);
                searchRegrouping.CompletResult += new CompletResultHandler(searchRegrouping_CompletResult);
                searchResultRegroupingKeyword_.Add(searchRegrouping);



                while (queueKeywords.Count > 0)
                {
                    

                    SearchTransaction srchTrans = (SearchTransaction)queueKeywords.Dequeue();

                    G2Log.Write("Starting Transaction - Keyword :" + srchTrans.Keywords[0].KeywordName.ToString());
                    searchManager.NewSearch(srchTrans);
                    
                    // on attends 30sec ?????????????????????????
                    //System.Threading.Thread.Sleep(30000);
                }
            }
            catch
            {
               G2Log.Write("Erreur niveau manager.....");
            }
        }

        /**
         * When results arrive, they are stacked  and regrouped
         * */
        public void SearchKeywordResult(SearchResult searchResult)
        {
            G2SearchResultRegrouping search = null;
            try
            {
                string id = searchResult.SearchTransaction.IdTransaction;
                search =(G2SearchResultRegrouping) searchResultRegroupingKeyword_.Find(searchResult.SearchTransaction.IdTransaction);
                search.AddGlobalResult(searchResult); // Rajoute ces résultats aux résultats globaux
                string word = searchResult.SearchTransaction.Keywords[0].KeywordName;
                G2Log.Write("G2MANAGER : Received results for " + word + " => " + searchResult.PeerCollection.Count 
                    + " Peers & " + searchResult.FileCollection.Count + " Files ...");
                
            }
            catch (Exception ex)
            {
                G2Log.Write("Error AddGlobalResult" + ex.Message,G2Log.ERROR_FILE);
                G2Log.Write("Erreur server_NewResult = " + ex.Message 
                        + "\n" + "Erreur server_NewResult, source= " + ex.Source
                        + "\n" + "Erreur server_NewResult, stack= " + ex.StackTrace,G2Log.ERROR_FILE);
            }
        }

        /**
         * When enough results are present and regrouped, pass them to the multi protocol application
         * */
        public void searchRegrouping_CompletResult(SearchResult result)
        {

            if (NewResult != null) NewResult(result);
        }

        
    }
}
