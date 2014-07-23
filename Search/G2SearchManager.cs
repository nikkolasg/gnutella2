using System;
using System.IO;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Text;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Struct;
using ActionInnocence.P2PScan.Plugins.Gnutella2.G2Packets;

namespace ActionInnocence.P2PScan.Plugins.Gnutella2.Search {
    /**
     * Class used to search, store all results etc
     * */
    public class G2SearchManager {


		public static G2SearchManager _instance;
		public static G2SearchManager Instance {
			get { if(_instance == null)
					_instance = new G2SearchManager();
				return _instance;
			}
		}

        public event SearchResultHandler ResultFind;


		public const int HUB_DISPATCH_REQUEST = 2;
		public const int MAX_RESULTS = 3;
		private Queue PacketResultBuffer;
		private ConcurrentDictionary<GUID,G2SearchResults> SearchResults;
		private ConcurrentDictionary<GUID,SearchTransaction> SearchDB; //  all launched queries

        public G2SearchManager() {
			PacketResultBuffer = new Queue ();
			SearchResults = new ConcurrentDictionary<GUID,G2SearchResults> ();
			SearchDB = new ConcurrentDictionary<GUID,SearchTransaction> ();
           
		}
		/**
		 * Take a search related packets i.e. QA (ack) or QH2 (hit)
		 * and stores it into SearchResults class
		 * */
		public void EnqueueResultPacket(NodePeer p, G2Packet pack) {
			// a hub packet ACK a query
            if (pack.type == G2PacketType.QA)
            {
                G2PacketQA qa = pack as G2PacketQA;
                G2SearchResults res = null;
                bool exists = SearchResults.TryGetValue(qa.guid, out res);
                if (!exists)  // no entry => not a search we initiated
                    G2Log.Write("G2SearchManager : Received ACK of non asked Query");
                else
                {
                    res.SetAcknowledgement(qa);
                    G2Log.Write("G2SearchManager Received ACK of search " + SearchDB[qa.guid].Keywords[0]);
                }
            }
                // Hit packet !
            else if (pack.type == G2PacketType.QH2)
            {
                G2PacketQH2 qh2 = pack as G2PacketQH2;
                G2SearchResults res = null;
                bool exists = SearchResults.TryGetValue(qh2.searchGuid, out res);
                if (exists)
                { // a new result packet coming for a requested query
                    res.PushResultPacket(qh2);
                    //if (res.TotalFiles > MAX_RESULTS)
                    //    G2Network.Instance.StopNetwork();
                }
                else // got a response for a query we did not ask ?
                    G2Log.Write("G2SearchManager : Received a Hit on a NON ASKED Query");
            }
		}

        /**
         * Remove the search from the entries and
         * and delete objects
         * */
        public void FinishSearch(G2SearchResults results)
        {
            G2SearchResults r ;
            SearchTransaction t;
            bool generalSuccess = false;
            generalSuccess |= SearchResults.TryRemove(results.SearchGUID,out r);
            generalSuccess &= SearchDB.TryRemove(results.SearchGUID, out t);       
            results.Clean(); 
        }

		/**
		 * Launch a new search on multiple hubs (starting)
         * SearchTransaction contains only one keyword
		 * */
		public void NewSearch(SearchTransaction transaction) {
			// register query
			GUID searchGUID = GUID.generateGuid ();
			SearchDB [searchGUID] = transaction;
            // creating a new search results object for this transaction, register the event that tell it has fins events and stores it
            G2SearchResults results = new G2SearchResults(transaction, searchGUID);
            
            SearchResults[searchGUID] = results;

			G2PacketQ2 q2 = CreateRequestPacket (searchGUID, transaction.Keywords[0].KeywordName);

			DispatchRequest (q2);
            results.StartSearchResult(); // start the threads only after all queries have been sent 
            // because find new hub can take some time and the search may not last long after
		
		}


		/**
		 * Create a single request packet for the specified term
		 * this request has id searchGUID
		 * */
		private G2PacketQ2 CreateRequestPacket(GUID searchGUID,string singleTerm) {
			G2PacketQ2 q2 = new G2PacketQ2 (searchGUID); // id of the query
			G2PacketDN dn = new G2PacketDN (singleTerm); // terms of the query
			q2.AddChild (dn);
			q2.FinalizePacket ();
			return q2;
		}
		/**
		 * Send the request to connected hubs .
		 * */
		private void DispatchRequest(G2PacketQ2 pack) {
			int count = 0;
			NodePeer hub = null;
			while (count < Settings.PEER_DISPATCH_QUERY) {
				hub = G2Network.Instance.getQueryableHub();
                hub.DontQueryBefore(Settings.SEARCH_TIME_OUT_MS);
				hub.SendPacket (pack);
				G2Log.Write ("G2SearchManager : Sent Query " + getTermsByGUID(pack.guid) + " on " + hub.ToString ());
				count++;
			}


		}

		public string getTermsByGUID(GUID g) {
			SearchTransaction transaction = null;
            if (SearchDB.TryGetValue(g, out transaction))
            {
                return transaction.Keywords[0].KeywordName;
            }
			return "";
		}

		public override string ToString ()
		{
			StringBuilder b = new StringBuilder ();
			foreach (KeyValuePair<GUID,G2SearchResults> kvp in SearchResults) {
				b.Append(kvp.Value.ToString());
			}
			return b.ToString ();
		}

        /**
         * Simply a proxy between manager and G2SearchResults
         * it passes along the results
         * */
        public void getResultsFromSearchResults(SearchResult results)
        {
            if (ResultFind != null) ResultFind(results);
        }

    }

}
