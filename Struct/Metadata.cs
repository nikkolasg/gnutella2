using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;

namespace ActionInnocence.P2PScan.Plugins.Gnutella2.Struct
{
    /**
     * Reprensent metadata given in Hit packets in xml format
     * with various information
     * example : 
//     * <audio title="" 
//        soundtype="Joint Stereo" 
//        samplerate="44100" 
//        channels="2" 
//        artist="Madonna" 
//        seconds="297" 
//        album="" 
//        genre=""
//        year=""
//        description=""
//        bitrate="128" 
//        track="6" composer=""
//        />
		
//<video framerate="25"
//        codec="MPEG"
//        height="576"
//        width="480"
//        />
     * */
    public class Metadata
    {
        private const string TITLE_ATTR = "title";
        private const string SECONDS_ATTR = "seconds";
        private const string MINUTE_ATTR = "minutes";
        private const string ARTIST_ATTR = "artist";
        private const string YEAR_ATTR = "year";
        private const string CODEC_ATTR = "codec";
        private const string DESCR_ATTR = "description";
        public string Type { get; set; }
        public string Title { get; set; }
        public int Length { get; set; }  // in seconds
        public string Artist { get; set; }
        public string Year { get; set; }
        public string Codec { get; set; }
        public string Description { get; set; }
        private Metadata()
        {

        }

        public static Metadata ParseMetadata(string xmlString) 
        {
            Metadata data = new Metadata();
            if (xmlString.Length == 0) return data;
            try
            {
                XElement xml = XElement.Parse(xmlString);

                data.Type = xml.Name.ToString();

                XAttribute attr = null;
                attr = xml.Attribute(TITLE_ATTR); // getting the title
                if (attr != null)
                    data.Title = attr.Value;

                if ((attr = xml.Attribute(SECONDS_ATTR)) != null) // getting length in seconds or minute
                {
                    data.Length = Int32.Parse(attr.Value);
                }
                else if ((attr = xml.Attribute(MINUTE_ATTR)) != null)
                {
                    string str = attr.Value.Replace('.', ',');
                    double minutes = Double.Parse(str); // can be in xx.yy format ...
                    data.Length = ((int)minutes) * 60;
                }

                if ((attr = xml.Attribute(ARTIST_ATTR)) != null) // getting artist name
                {
                    data.Artist = attr.Value;
                }
                
                if((attr = xml.Attribute(YEAR_ATTR)) != null) // getting year
                {
                    data.Year = attr.Value;
                }

                if((attr = xml.Attribute(CODEC_ATTR)) != null) // if video getting codec
                {
                    data.Codec = attr.Value;
                }
                if ((attr = xml.Attribute(DESCR_ATTR)) != null)
                {
                    data.Description = attr.Value;
                }
            }
            catch (Exception e)
            {
                G2Log.Write("ERROR Parsing metadata " + xmlString + "\n" +  e.ToString());
            }
            return data;
        }
    }
}
