using System;
using System.IO;

namespace ActionInnocence.P2PScan.Plugins.Gnutella2
{
	public static class G2Log
	{
        public static event ApplicationMessageLog MessageLog;
        // TODO put that in a enum
		public static int CONSOLE = 1;
		public static int FILE = 2;
        public static int ERROR_FILE = 3;
        public static string ERROR_FILE_NAME = @"g2error.log";
        public static string FILE_NAME = @"G2.log";
		

		private static object locker = new object ();
		public static void Write(string message) {
            if (!ProtocolPlugin.LogActive) return;

			if (Settings.LOG_OUTPUT == CONSOLE)
				WriteConsole (message);
			else if (Settings.LOG_OUTPUT == FILE)
				WriteFile (message);
            // send to application log
            if (MessageLog != null) MessageLog(message);
		}
        public static void Write(string message, int output)
        {
            if (output == CONSOLE)
                WriteConsole(message);
            else
                WriteFile(message);
            if (MessageLog != null) MessageLog(message);
        }
		private static void WriteConsole(string message) {
			Console.WriteLine (message);
		}
		private static void WriteFile(string message) {
			lock (locker) {
				try {
                    using (StreamWriter wr = System.IO.File.AppendText(Settings.LOG_OUTPUT_FILE))
                    {
                        wr.WriteLine(message);
                    }
				} catch (Exception e) {
					G2Log.WriteConsole ("LOG : " + e.ToString ());
				}
			}
		}
	}
}

