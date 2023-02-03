namespace Net.AS2.Core.Settings
{
    public class FileLocation
    {
        public string EdiStored { get; set; }
        public string MdnStored { get; set; }
        public string LogStored { get; set; }
        public long LogFileSizeLimit { get; set; }
    }
    public class FileNameDefault
    {
        public const string Receive_EdiLogFile = "{0}-{1}_ReceiveEdi_LogFile.log";
        public const string Receive_MdnLogFile = "{0}-{1}_ReceiveAsyncMdn_LogFile.log";
        public const string Send_EdiLogFile = "{0}-{1}_SendEdi_LogFile.log";
    }
}
