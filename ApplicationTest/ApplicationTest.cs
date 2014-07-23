using System;
using System.Reflection;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using ActionInnocence.P2PScan;
using System.Threading;
using ActionInnocence.P2PScan.Plugins.Gnutella2;
using System.Diagnostics;
namespace ApplicationTest
{
    [TestClass]
    public class ApplicationTest
    {
        [TestMethod]
        public void SettingsTest()
        {

            Settings.ReadSettings();
            Assert.AreEqual(Settings.PROTOCOL_NAME, "boby","Settings protocol name is " + Settings.PROTOCOL_NAME);
          
        }
        [TestMethod]
        public void DllTest()
        {
            Assembly a = Assembly.LoadFrom(@"F:\Prog\gnutella2\bin\Debug\gnutella2.dll");
            Type type = a.GetType("ActionInnocence.P2PScan.ProtocolPlugin");
            IProtocol protocol = (IProtocol)Activator.CreateInstance(type, new string[] { @"F:\Prog\gnutella2\bin\Debug\", "192.168.1.38" });
            protocol.NewResult += new SearchResultHandler(protocol_NewResult);
            protocol.Connect();
            Thread.Sleep(1000 * 2);
            Keyword w = new Keyword("gnutella2","madonna");
            KeywordCollection coll = new KeywordCollection();
            coll.Add(w);
            protocol.SearchKeyword(new SearchTransaction("1", coll, 1, null));
            System.Threading.Thread.Sleep(1000 * 30);
            protocol.Disconnect();
            
        }

         void protocol_NewResult(SearchResult searchResult)
        {

            using (System.IO.StreamWriter w = System.IO.File.AppendText("outputTest"))
            {
               w.WriteLine(searchResult.PeerCollection.Count.ToString());

                foreach (Peer p in searchResult.PeerCollection)
                {
                    if (p.Files.Count > 1)
                    {
                       w.WriteLine(p.Ip + "\t" + p.Files.Count.ToString());
                        w.WriteLine("------------------------------------------");
                        foreach (File f in p.Files)
                        {
                            w.WriteLine(f.Name);
                        }
                    }
                }
            }
        }
    }
}
