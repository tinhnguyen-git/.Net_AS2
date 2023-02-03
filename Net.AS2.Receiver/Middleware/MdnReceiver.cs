using Net.AS2.Data.Constants;
using Net.AS2.Data.Entity;
using Net.AS2.Data.Entity.Context;
using Net.AS2.Data.Services;
using Net.AS2.Core.Helper;
using Net.AS2.Core.Settings;

namespace Net.AS2.Receiver.Middleware
{
    public class MdnReceiver
    {
        private readonly RequestDelegate _next;
        private ILogFileWriter _logFile;

        public MdnReceiver(RequestDelegate next)
        {
            _next = next;
        }
        public async Task Invoke(HttpContext context, IConfiguration configuration, IAS2ConnectionService as2ConnectionService, ILogFileWriter logFile)
        {
            try
            {
                _logFile = logFile;
                string sTo = context.Request.Headers["AS2-To"];
                string sFrom = context.Request.Headers["AS2-From"];

                _logFile.FileName(string.Format(FileNameDefault.Receive_MdnLogFile, sFrom, sTo));

                await _logFile.WriteLog($"Receiving MDN from {context.Request.HttpContext.Connection.RemoteIpAddress}.");
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
                        //Invalid AS2 Request.
                        //Section 6.2 The AS2-To and AS2-From header fields MUST be present
                        //    in all AS2 messages
                        var querys = context.Request.Query.ToList();
                        //if (!(context.Request.Method == "GET" && querys[0].Length == 0))
                        //{
                        AS2Process.BadRequest(context.Response, "Invalid or unauthorized AS2 request received.");
                        //}
                    }
                    else
                    {
                        Console.WriteLine("Process MDN");
                        var fileLoc = new FileLocation();
                        configuration.GetSection(nameof(FileLocation)).Bind(fileLoc);
                        var mdnStored = string.Format(fileLoc.MdnStored, $"{sFrom}-{sTo}", DateTime.UtcNow.ToString("yyyy-MM-dd"));
                        string fileName = $"{DateTime.UtcNow.Ticks}-{DateTime.UtcNow.ToString("yyyy-MM-dd-HH-mm-ss-ffff")}-{sFrom}-{sTo}.MDN";
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
                        var messageId = await AS2Process.ProcessMdnAsync(fileName, sFrom, sTo,
                        body, contentType, isEncrypted, isSigned, mdnStored, _logFile, as2ConnectionService);

                        //Insert EDI queue
                        var dataResponseQueue = new DataResponseQueue {
                            CreatedOnUtc = DateTime.UtcNow,
                            EdiForm = "MDN",
                            From = sFrom,
                            To = sTo,
                            FileName = fileName,
                            FilePath = mdnStored,
                            TransferMethod = (int)TransferMethod.AS2,
                            ProcessStatus = (int)ProcessStatus.NOTPROCESS,
                            InterchangeId = messageId
                        };
                        var dataResponseQueueRepository = context.RequestServices.GetRequiredService<IAS2Repository<Net.AS2.Data.Entity.DataResponseQueue>>();
                        await dataResponseQueueRepository.InsertAsync(dataResponseQueue);
                    }
                }
                else
                {
                    AS2Process.GetMessage(context.Response);
                }
            }
            catch (Exception ex)
            {
                await _logFile.WriteLog($"Exception: '{ex.Message}'");
            }
            await Task.CompletedTask;
            //await _next.Invoke(context);
        }
    }

    public static class MdnReceiverExtensions
    {
        public static IApplicationBuilder UseMdnReceiverMiddleware(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<MdnReceiver>();
        }
    }
}
