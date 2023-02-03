namespace Net.AS2.Data.Entity
{
    public class FtpProfile : BaseEntity
    {
        public string Url { get; set; }
        public string Folder { get; set; }
        public string UID { get; set; }
        public string Password { get; set; }
    }
}
