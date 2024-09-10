using System.Xml;

namespace GlobalUnProtect.Utilities
{
    public class ParseXML
    {
        public static string GetXMLContentFromPath(byte[] xmlconfig, string xmlPath)
        {
            XmlDocument xmlDoc = new XmlDocument();
            using (var stream = new System.IO.MemoryStream(xmlconfig))
            {
                xmlDoc.Load(stream);
            }

            XmlNode node = xmlDoc.SelectSingleNode(xmlPath);
            if (node != null)
            {
                return node.InnerText;
            }
            else
            {
                return "empty";
            }
        }
    }
}
