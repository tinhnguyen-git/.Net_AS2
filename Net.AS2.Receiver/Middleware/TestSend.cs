using Net.AS2.Data.Services;
using Net.AS2.Core.Helper;
using Net.AS2.Sender;

namespace Net.AS2.Receiver.Middleware
{
    public class TestSend
    {
        private readonly RequestDelegate _next;
        private ILogFileWriter _logFile;

        public TestSend(RequestDelegate next)
        {
            _next = next;
        }
        public void AS2SendWarehouseToTenant()
        {
            var uriToReceive = new Uri("http://localhost:5021/HttpReceiver"); 
            string filePath = "data";
            string fileName = "sample.850";
            var proxySetting = new ProxySettings();
            var _senderCertPathFile = $"{filePath}/014EBC5E8CC2F993.pfx";
            var _receiverCertPathFile = $"{filePath}/00CA6D4F16EE68578D.cer";
            string logPath = "log/";
            long logSiteLimit = 4096000;
            string activityId = "connectivityTestId";
            string asyncMDNUrl = "http://localhost:5021/HttpMdn";
            string mdn;
            AS2Send.SendFile(uriToReceive, filePath, fileName, "Key_AS2_Sender", "Key_As2_Receiver",
                proxySetting, 110000, _senderCertPathFile, "", _receiverCertPathFile, Net.AS2.Core.EncryptionAlgorithm.AES256_CBC, activityId, asyncMDNUrl, logPath, logSiteLimit, out mdn);

        }
        public async Task Invoke(HttpContext context, IConfiguration configuration, IAS2ConnectionService as2ConnectionService, ILogFileWriter logFile)
        {
            AS2SendWarehouseToTenant();
            await _next.Invoke(context);
        }
    }

    public static class TestSendExtensions
    {
        public static IApplicationBuilder UseTestSendMiddleware(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<TestSend>();
        }
    }
}
