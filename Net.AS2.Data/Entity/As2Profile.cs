namespace Net.AS2.Data.Entity
{
    public class As2Profile : BaseEntity
    {
        public string As2Id { get; set; }

        public string Url { get; set; }
        public string MdnUrl { get; set; }
        public byte[] CertFileStream { get; set; }
        public string CertFileName { get; set; }
        public byte[] TestCertFileStream { get; set; }
        public string TestCertFileName { get; set; }
        public string EdiConfigurationId { get; set; }
        public Certificate ProCertificate { get; set; }
        public Certificate TestCertificate { get; set; }
    }
}
