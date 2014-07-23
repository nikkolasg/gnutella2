using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ActionInnocence.P2PScan.Plugins.Gnutella2.Test
{
    class BinaryUtilsTest
    {
        public static void Main (string[] args)
        {
            int[] numbers = { 1, 2, 4, 9, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096 };
            foreach (int n in numbers)
            {
                int size = BinaryUtils.getSizeForInt(n);
                Console.WriteLine("Number : " + n + " => size : " + size + " bytes");
            }
            Console.Read();
        }

    }
}
