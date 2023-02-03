namespace Net.AS2.Data.Entity
{
    public class EdiConfiguration : BaseEntity
    {
        public string Code { get; set; }
        public int Status { get; set; }
        public InterchangeIdentifier FromIdentifier { get; set; }
        public InterchangeIdentifier ToIdentifier { get; set; }
        public string RecordSeparator { get; set; }
        public string SegmentSeparator { get; set; }
        public string EdiVersion { get; set; }
        public bool IsRequire997 { get; set; }
        public bool IsTestMode { get; set; }
        public int Direction { get; set; }
        public string EdiFormId { get; set; }
        public int ConnectionType { get; set; }
        /// <summary>
        /// Gets or sets the identifier of the default waregouse for this store
        /// </summary>
        public string DefaultWarehouseId { get; set; }
        public string TenantId { get; set; }
        public As2Profile ToAs2 { get; set; }
        public FtpProfile Ftp { get; set; }

        public bool IsDeleted { get; set; }
        public DateTime CreatedOnUtc { get; set; }
        public string CreatedBy { get; set; }
        public DateTime? UpdatedOnUtc { get; set; }
        public string UpdatedBy { get; set; }
        public DateTime? DeletedOnUtc { get; set; }
        public string DeletedBy { get; set; }
    }
}
