using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Net.AS2.Data.Constants
{
    public static class InterchangeFailureCode
    {
        public const string Success = "Success";
        public const string IsaNotFound = "IsaNotFound";
        public const string IsaNotMatchReceiver = "IsaNotMatchReceiver";
        public const string EdiParserFailed = "CanNotParseEdi";
        public const string EdiWriterFailed = "CannotWriteEdi";
        public const string EdiSendToAs2Failed = "EdiSendToAs2Failed";
        public const string EdiNotMatchIdentifier = "EdiNotMatchIdentifier";
        public const string DuplicatedTransactionNo = "DuplicatedTransactionNo";
        public const string EdiNotSupport = "EdiNotSupport";
    }

    public static class EdiForm
    {
        public const string EDI_810 = "810";
        public const string EDI_850 = "850";
        public const string EDI_855 = "855";
        public const string EDI_856 = "856";
        public const string EDI_865 = "865";
        public const string EDI_860 = "860";
        public const string EDI_997 = "997";
        public const string EDI_753 = "753";
        public const string EDI_940 = "940";
    }
    public enum TransferMethod
    {
        EMAIL = 1,
        FTP = 2,
        AS2 = 3
    }
    public enum ProcessStatus
    {
        NOTPROCESS = 0,
        PROCESSING = 1,
        SUCCESS = 2,
        FAIL = 3
    }
}
