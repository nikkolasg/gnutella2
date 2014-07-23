using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.IO;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Search;
namespace ActionInnocence.P2PScan.Plugins.Gnutella2.Test
{
    class ProtocolPluginTest
    {
        public static object FileLocker = new Object();
        public static void Main (string[] args)
		{
            Thread.CurrentThread.Name = "MAIN G2 thread";
            ProtocolPlugin protocol = new ProtocolPlugin(Directory.GetCurrentDirectory(), "88.88.88.88");
            protocol.NewResult += new SearchResultHandler(NewResult);
            protocol.Connect();
            Thread.Sleep(10 * 1000);
            KeywordCollection coll = new KeywordCollection();
            //coll.Add(new Keyword(protocol.GetProtocolName(), "phtc"));
            coll.Add(new Keyword(protocol.GetProtocolName(), "madonna"));
            protocol.SearchKeyword(new SearchTransaction("1", coll, 1, null));
            
            Console.WriteLine("Sleeping ................................");
            Console.Read();
        }

        public static void NewResult(SearchResult searchResult)
        {
            lock (FileLocker)
            {

                using (System.IO.StreamWriter w = System.IO.File.AppendText("outputTest"))
                {
                    w.WriteLine("PEER NUMBER : " + searchResult.PeerCollection.Count.ToString());
                    w.WriteLine("FILE NUMBER : " + searchResult.FileCollection.Count.ToString());

                    foreach (Peer p in searchResult.PeerCollection)
                    {
                        w.WriteLine(p.Ip + "\t" + p.Files.Count.ToString() + "files, " + p.SharedLocalfilesList.Count + " shared files ...");
                        if (p.Files.Count >= 1)
                        {
                            
                            w.WriteLine("------------------------------------------");
							w.WriteLine ("Searched files: ");

                            foreach (File f in p.Files)
                            {
                                w.WriteLine(f.Name + " hash : " + f.Hash);
                            }
                        }
						if (p.SharedLocalfilesList.Count >= 1) {
							w.WriteLine ("-------------------------------------------");
							w.WriteLine ("Shared files: ");
							foreach (File f in p.SharedLocalfilesList) {
								w.WriteLine (f.Name + " from ip " + p.Ip + " or first peerdiffusedfiles : " + f.PeerDiffusedFiles [0].Ip);
							}
						}
						w.WriteLine("###################################################################################");
						w.WriteLine("###################################################################################");


                    }

                }
            }
            
        }
    }
}
