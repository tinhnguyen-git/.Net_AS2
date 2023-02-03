
namespace Net.AS2.Data.Entity
{
    public class DataResponseQueue : BaseEntity
    {
        public string From { get; set; }//AS2 from || FTP from || VAN from

        public string To { get; set; }//AS2 to || FTP to || VAN to

        public string EdiForm { get; set; }//850 || 940 || MDN

        public string FileName { get; set; }
        public string FilePath { get; set; }
        public int TransferMethod { get; set; }
        public int ProcessStatus { get; set; }
        public string ProcessMessage { get; set; }
        public string InterchangeId { get; set; }
        public DateTime CreatedOnUtc { get; set; }
        public DateTime? UpdatedOnUtc { get; set; }
    }
}