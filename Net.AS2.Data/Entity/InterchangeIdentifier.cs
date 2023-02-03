namespace Net.AS2.Data.Entity
{
    public class InterchangeIdentifier : BaseEntity
    {
        public string ProductionQualifier { get; set; }
        public string ProductionId { get; set; }
        public string TestQualifier { get; set; }
        public string TestId { get; set; }
    }
}
