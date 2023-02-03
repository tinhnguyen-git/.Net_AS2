
namespace Net.AS2.Data.Entity
{
    public class Certificate
    {
        public string Subject { get; set; }

        public string Issuer { get; set; }

        public string FingerPrint { get; set; }

        public string SerialNumber { get; set; }

        public int Version { get; set; }

        public DateTime ValidFrom { get; set; }

        public DateTime ValidTo { get; set; }

        public byte[] CertificateContent { get; set; }

        public byte[] Key { get; set; }

        public string KeyPassword { get; set; }

        public int Status { get; set; }
    }
    
}
