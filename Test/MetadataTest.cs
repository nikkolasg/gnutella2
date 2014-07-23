using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ActionInnocence.P2PScan.Plugins.Gnutella2.Struct;
namespace ActionInnocence.P2PScan.Plugins.Gnutella2.Test
{
    class MetadataTest
    {
        
        private static string xml = " <audio title=\"blou\" minutes=\"78.067\" />";
        
        public static void Main (string[] args)
        {
            Test();
        }
        public static void  Test() {
            Metadata.ParseMetadata(xml);

        }
    }
}
