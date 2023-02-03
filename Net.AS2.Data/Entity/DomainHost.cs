namespace Net.AS2.Data.Entity
{
    public class DomainHost : BaseEntity
    {
        public string HostName { get; set; }
        public string Url { get; set; }
        public bool Primary { get; set; }

    }
}
