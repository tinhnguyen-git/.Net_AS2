namespace Net.AS2.Data.Entity
{
    public class EdiConnectivity : BaseEntity
    {
        //ConnectivityTestStatus
        public int Status { get; set; }
        public string CertificateSerialNumber { get; set; }
        public int CertificateVersion { get; set; }
        public DateTime Time { get; set; }
        public int ConnectionType { get; set; }
        public string MdnMessage { get; set; }
        public int Direction { get; set; }
        public string EdiConfigurationId { get; set; }
        public bool IsTestMode { get; set; }
    }

}
