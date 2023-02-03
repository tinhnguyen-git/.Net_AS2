using Net.AS2.Core;
using Net.AS2.Data.Entity;
using Net.AS2.Data.Services;
using Net.AS2.Core.Helper;
using System.Text;
using System.Text.RegularExpressions;

namespace Net.AS2.Receiver
{
    public class AS2Process
    {
        public static void GetMessage(HttpResponse response)
        {
            response.StatusCode = 200;
            response.ContentType = "text/html";
            var message = @"<!DOCTYPE HTML PUBLIC ""-//W3C//DTD HTML 3.2 Final//EN"">"
                + @"<HTML><HEAD><TITLE>Generic AS2 Receiver</TITLE></HEAD>"
                + @"<BODY><H1>200 Ping Okay</H1></BODY></HTML>";
            byte[] bytes = Encoding.ASCII.GetBytes(message);
            response.Body.WriteAsync(bytes);
        }

        public static void BadRequest(HttpResponse response, string message)
        {
            // response.StatusCode = (int)HttpStatusCode.BadRequest;
            var messageBody = @"<!DOCTYPE HTML PUBLIC ""-//W3C//DTD HTML 3.2 Final//EN"">"
            + @"<HTML><HEAD><TITLE>400 Bad context.Request</TITLE></HEAD>"
            + @"<BODY><H1>400 Bad context.Request</H1><HR>There was a error processing this context.Request.  The reason given by the server was:"
            + @"<P><font size=-1>" + message + @"</Font><HR></BODY></HTML>";
            byte[] bytes = Encoding.ASCII.GetBytes(messageBody);
            response.Body.WriteAsync(bytes);
        }
        public static async Task<string> ProcessAsync(string fileName, string as2From, string as2To,
            byte[] bodyBytes, string contentType, bool? isEncrypted, bool? isSigned,
            string dropLocation, ILogFileWriter logFile, IAS2ConnectionService as2ConnectionService)
        {
            try
            {
                var body = ASCIIEncoding.ASCII.GetString(bodyBytes);
                var ediMessage = string.Empty;
                var ediMessageTemp = string.Empty;
                bool verifyResult = true;
                Tenant? tenant = as2ConnectionService.GetTenantByAs2Id(as2To);
                await logFile.WriteLog($"Edi fileName {fileName}\r\nisEncrypted {isEncrypted} - isSigned {isSigned}\r\nOriginal Edi:\r\n{body}");

                var ediConfig = as2ConnectionService.GetEdiConfigurationByAs2Id(as2From);
                if (tenant == null || ediConfig == null)
                {
                    await logFile.WriteLog($"Can't find relationship between as2From: {as2From} and as2To: {as2To}");
                    throw new Exception("Can't find relationship between as2From and as2To");
                }
                var _senderCertByte = ediConfig.ToAs2.ProCertificate.CertificateContent;
                if (isSigned.HasValue && isSigned.Value)
                {
                    (ediMessageTemp, verifyResult) = AS2MIMEUtilities.ExtractPayload(body, contentType, _senderCertByte, isSigned);
                }
                else if (isEncrypted.HasValue && isEncrypted.Value) // encrypted and signed inside
                {
                    //1.decrypt by receiver privateKey
                    //2. verify sign by sender public key
                    var _receiverCertByte = tenant.AS2Profile.ProCertificate.Key;
                    var _receiverCertPassword = tenant?.AS2Profile.ProCertificate.KeyPassword;
                    var keyAes = "this is the key to encrypt/decrypt by aes gcm";
                    //byte[] data = ASCIIEncoding.ASCII.GetBytes(body);
                    byte[] decryptedData = AS2Encryption.Decrypt(bodyBytes, _receiverCertByte, _receiverCertPassword, EncryptionAlgorithm.AES256_CBC, keyAes);

                    string messageWithContentTypeLineAndMIMEHeaders = ASCIIEncoding.ASCII.GetString(decryptedData);

                    isSigned = messageWithContentTypeLineAndMIMEHeaders.Contains("application/pkcs7-signature");
                    await logFile.WriteLog($"Decrypted - data \r\n{messageWithContentTypeLineAndMIMEHeaders}");
                    // when encrypted, the Content-Type line is actually stored in the start of the message
                    int firstBlankLineInMessage = messageWithContentTypeLineAndMIMEHeaders.IndexOf("\r\n" + "\r\n");
                    string contentTypeSign = messageWithContentTypeLineAndMIMEHeaders.Substring(0, firstBlankLineInMessage);
                    (ediMessageTemp, verifyResult) = AS2MIMEUtilities.ExtractPayload(messageWithContentTypeLineAndMIMEHeaders, contentTypeSign, _senderCertByte, isSigned);
                }
                else // not signed and not encrypted
                {
                    ediMessage = body;
                }
                if (!verifyResult)
                    await logFile.WriteLog($"Edi fileName {fileName} {AS2MIMEUtilities.VerifyFail}");
                else
                {
                    int firstBlankLineInMessage = ediMessageTemp.IndexOf("\r\n" + "\r\n");
                    string contentTypeTemp = ediMessageTemp.Substring(0, firstBlankLineInMessage);
                    ediMessage = AS2MIMEUtilities.ExtractPayloadEdi(ediMessageTemp, contentTypeTemp);
                    if (ediMessageTemp.Contains("Content-Disposition"))
                    {
                        Regex regex = new Regex("Content-Disposition:.*?filename=(.*?)(\\r\\n)");
                        var match = regex.Match(ediMessageTemp);
                        if (match.Groups.Count > 1)
                        {
                            fileName = $"{DateTime.UtcNow.Ticks}-{DateTime.UtcNow.ToString("yyyy-MM-dd-HH-mm-ss-ffff")}-{match.Groups[1].Value}";
                        }
                    }
                    Directory.CreateDirectory(dropLocation);
                    System.IO.File.WriteAllText(dropLocation + fileName, ediMessage);
                }
            }
            catch (Exception ex)
            {
                Serilog.Log.Logger.Error(ex, "AS2Process.ProcessAsync");
            }
            return fileName;
        }

        public static async Task<string> ProcessMdnAsync(string fileName, string as2From, string as2To,
            byte[] bodyBytes, string contentType, bool? isEncrypted, bool? isSigned,
            string dropLocation, ILogFileWriter logFile, IAS2ConnectionService as2ConnectionService)
        {
            try
            {
                var body = ASCIIEncoding.ASCII.GetString(bodyBytes);
                var mdnMessage = string.Empty;
                bool verifyResult = true;
                Tenant? tenant = as2ConnectionService.GetTenantByAs2Id(as2To);
                await logFile.WriteLog($"Mdn fileName {fileName}\r\nisEncrypted {isEncrypted} - isSigned {isSigned}\r\nOriginal MDN:\r\n{body}");

                var ediConfig = as2ConnectionService.GetEdiConfigurationByAs2Id(as2From);
                if (tenant == null || ediConfig == null)
                {
                    await logFile.WriteLog($"Can't find relationship between as2From: {as2From} and as2To: {as2To}");
                    throw new Exception("Can't find relationship between as2From and as2To");
                }
                var _senderCertByte = ediConfig.ToAs2.ProCertificate.CertificateContent;
                if (isSigned.HasValue && isSigned.Value)
                {
                    (mdnMessage, verifyResult) = AS2MIMEUtilities.ExtractPayload(body, contentType, _senderCertByte, isSigned);
                }
                else if (isEncrypted.HasValue && isEncrypted.Value) // encrypted and signed inside
                {
                    //ToDo get cert by find relation between as2To and as2Form -> get cert from DB ediconnection
                    var _receiverCertByte = tenant?.AS2Profile.ProCertificate.Key;
                    var _receiverCertPassword = tenant?.AS2Profile.ProCertificate.KeyPassword;
                    var keyAes = "this is the key to encrypt/decrypt by aes gcm";
                    byte[] decryptedData = AS2Encryption.Decrypt(bodyBytes, _receiverCertByte, _receiverCertPassword, EncryptionAlgorithm.AES256_CBC, keyAes);

                    string messageWithContentTypeLineAndMIMEHeaders = ASCIIEncoding.ASCII.GetString(decryptedData);
                    isSigned = messageWithContentTypeLineAndMIMEHeaders.Contains("application/pkcs7-signature");
                    await logFile.WriteLog($"Decrypted - data \r\n{messageWithContentTypeLineAndMIMEHeaders}");
                    // when encrypted, the Content-Type line is actually stored in the start of the message
                    int firstBlankLineInMessage = messageWithContentTypeLineAndMIMEHeaders.IndexOf("\r\n" + "\r\n");
                    string contentTypeSign = messageWithContentTypeLineAndMIMEHeaders.Substring(0, firstBlankLineInMessage);
                    (mdnMessage, verifyResult) = AS2MIMEUtilities.ExtractPayload(messageWithContentTypeLineAndMIMEHeaders, contentTypeSign, _senderCertByte, isSigned);
                }
                else // not signed and not encrypted
                {
                    mdnMessage = body;
                }
                if (!verifyResult)
                    await logFile.WriteLog($"Mdn fileName {fileName} {AS2MIMEUtilities.VerifyFail}");
                else
                {
                    Directory.CreateDirectory(dropLocation);
                    System.IO.File.WriteAllText(dropLocation + fileName, mdnMessage);
                    //TODO store mdnMessage to connectivitytest
                    Regex regex = new Regex(".?Original-Message-ID: <AS2_(.*?)(>\\r\\n)");
                    var match = regex.Match(mdnMessage);
                    if (match.Groups.Count > 1)
                    {
                        var messageId = match.Groups[1].Value;
                        return messageId;
                    }
                }
            }
            catch (Exception ex)
            {
                Serilog.Log.Logger.Error(ex, "AS2Process.ProcessMdnAsync");
            }
            return string.Empty;
        }
    }
}
