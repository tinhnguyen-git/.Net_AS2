namespace Net.AS2.Data.Entity
{
    public partial class Tenant : BaseEntity
    {
        public string Name { get; set; }
        public string Address { get; set; }
        public string PhoneNumber { get; set; }
        public string Email { get; set; }
        public string FolderName { get; set; }
        public string Url { get; set; }
        public IList<DomainHost> StoreDomains { get; set; }
        
        public string MongoConnectionString { get; set; }
        public string Collation { get; set; }
        public bool IsActive { get; set; }
        public bool IsInTrialMode { get; set; }
        public string AdminEmail { get; set; }
        public string AdminPassword { get; set; }
        public string AdminFirstName { get; set; }
        public string AdminLastName { get; set; }
        public string AdminCountry { get; set; }
        public string AdminState { get; set; }
        public string AdminCity { get; set; }
        public string AdminAddress1 { get; set; }
        public string AdminAddress2 { get; set; }
        public string AdminZipCode { get; set; }
        public string AdminPhoneNumber { get; set; }
        public DateTime? ValidToUtc { get; set; }
        public bool InstallSampleData { get; set; }
        public string ThemeName { get; set; }
        public bool IsInitialized { get; set; }
        public DateTime CreatedOnUtc { get; set; }
        public DateTime? InitializedOnUtc { get; set; }
        public bool IsUseEdi { get; set; }
        public InterchangeIdentifier InterchangeIdentifier { get; set; }
        public As2Profile AS2Profile { get; set; }
    }
}
