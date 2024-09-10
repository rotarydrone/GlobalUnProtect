using System.IO.Compression;
using System.IO;

namespace GlobalUnProtect.Utilities
{
    public class InMemoryZip
    {
        private MemoryStream _zipStream;
        private ZipArchive _zipArchive;

        public InMemoryZip()
        {
            _zipStream = new MemoryStream();
            _zipArchive = new ZipArchive(_zipStream, ZipArchiveMode.Update, true);
        }

        public void AddFile(byte[] fileBytes, string fileName)
        {
            var zipEntry = _zipArchive.CreateEntry(fileName, CompressionLevel.Fastest);
            using (var entryStream = zipEntry.Open())
            {
                entryStream.Write(fileBytes, 0, fileBytes.Length);
            }
        }

        public void WriteZip(string outPath)
        {
            _zipArchive.Dispose();
            File.WriteAllBytes(outPath, _zipStream.ToArray());
        }

        public byte[] GetZipBytes()
        {
            _zipArchive.Dispose();
            return _zipStream.ToArray();
        }
    }
}
