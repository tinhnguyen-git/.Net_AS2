using Net.AS2.Data.Constants;
using Net.AS2.Data.Entity;
using Net.AS2.Data.Entity.Context;
using Net.AS2.Data.Services;
using Net.AS2.Core.Helper;
using Net.AS2.Core.Settings;

namespace Net.AS2.Receiver.Middleware
{
    public class DataReceiver
    {
        private readonly RequestDelegate _next;

        private ILogFileWriter _logFile;
        public DataReceiver(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext context,
            IConfiguration configuration,
            IAS2ConnectionService as2ConnectionService,
            ILogFileWriter logFile)
        {
            _logFile = logFile;

            string sTo = context.Request.Headers["AS2-To"];
            string sFrom = context.Request.Headers["AS2-From"];

            _logFile.FileName(string.Format(FileNameDefault.Receive_EdiLogFile, sFrom, sTo));

            object[] userHostAddress = { context.Request.Headers["X-Forwarded-For"] };
            await _logFile.WriteLog($"Receiving Edi from {userHostAddress}.");
            
            string sMessageId = context.Request.Headers["Message-Id"];
            await _logFile.WriteLog($"AS2From: '{sFrom}', AS2To: '{sTo}', MessageId: '{sMessageId}'.");
            Console.WriteLine($"to {sTo} - from {sFrom} - messageId {sMessageId}");
            Console.WriteLine($"Query.Count {context.Request.Query.Count}");
            if (context.Request.Method == "POST" || context.Request.Method == "PUT" ||
               (context.Request.Method == "GET" && context.Request.Query.Count > 0))
            {
                Console.WriteLine($"to {sTo}-from {sFrom}");
                if (sFrom == null || sTo == null)
                {
                    var querys = context.Request.Query.ToList();
                    AS2Process.BadRequest(context.Response, "Invalid or unauthorized AS2 request received.");
                }
                else
                {
                    Console.WriteLine("Process EDI");
                    var fileLoc = new FileLocation();
                    configuration.GetSection(nameof(FileLocation)).Bind(fileLoc);
                    var ediStored = string.Format(fileLoc.EdiStored, $"{sFrom}-{sTo}", DateTime.UtcNow.ToString("yyyy-MM-dd"));
                    string fileName = (context.Request.Headers.Keys.Contains("Subject") 
                        && !string.IsNullOrEmpty(context.Request.Headers["Subject"])) ? 
                        ($"{DateTime.UtcNow.Ticks}-{DateTime.UtcNow.ToString("yyyy-MM-dd-HH-mm-ss-ffff")}-{context.Request.Headers["Subject"].ToString().Replace(" ", "")}.edi")
                            : $"{DateTime.UtcNow.Ticks}-{DateTime.UtcNow.ToString("yyyy-MM-dd-HH-mm-ss-ffff")}.edi";
                    byte[] body;
                    using (var ms = new MemoryStream(2048))
                    {
                        await context.Request.Body.CopyToAsync(ms);
                        body = ms.ToArray();
                        //body = ASCIIEncoding.ASCII.GetString(rawData);
                    }
                    //var reader = new StreamReader(context.Request.Body);
                    //string body = await reader.ReadToEndAsync();


                    string contentType = context.Request.Headers["Content-Type"];
                    bool? isEncrypted = context.Request.ContentType?.Contains("application/pkcs7-mime");
                    bool? isSigned = context.Request.ContentType?.Contains("application/pkcs7-signature");
                    
                    var fileNameFinal = await AS2Process.ProcessAsync(fileName, sFrom, sTo,
                    body, contentType, isEncrypted, isSigned, ediStored, _logFile, as2ConnectionService);
                    //Insert EDI queue
                    var extensionFileArray = fileNameFinal.Split('.');
                    var dataResponseQueue = new DataResponseQueue {
                        CreatedOnUtc = DateTime.UtcNow,
                        EdiForm = extensionFileArray.Length > 0 ? extensionFileArray[extensionFileArray.Length - 1] : "unknown",
                        From = sFrom,
                        To = sTo,
                        FileName = fileNameFinal,
                        FilePath = ediStored,
                        TransferMethod = (int)TransferMethod.AS2,
                        ProcessStatus = (int)ProcessStatus.NOTPROCESS
                    };
                    var dataResponseQueueRepository = context.RequestServices.GetRequiredService<IAS2Repository<Net.AS2.Data.Entity.DataResponseQueue>>();
                    await dataResponseQueueRepository.InsertAsync(dataResponseQueue);
                }
            }
            else
            {
                AS2Process.GetMessage(context.Response);
            }
            await Task.CompletedTask;
            //await _next.Invoke(context);
        }
    }

    public static class DataReceiverExtensions
    {
        public static IApplicationBuilder UseDataReceiverMiddleware(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<DataReceiver>();
        }
    }
}
