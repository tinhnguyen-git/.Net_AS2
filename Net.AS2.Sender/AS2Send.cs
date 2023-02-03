using Net.AS2.Core;
using Net.AS2.Core.Helper;
using Net.AS2.Core.Settings;
using System.Net;
using System.Text;

namespace Net.AS2.Sender
{
    public struct ProxySettings
    {
        public string Name;
        public string Username;
        public string Password;
        public string Domain;
    }

    public class AS2Send
    {
        public static HttpStatusCode SendFile(Uri uri, string filePath, string fileName, string from, string to, ProxySettings proxySettings,
            int timeoutMs, string signingCertFilename, string signingCertPassword, string recipientCertFilename, string receipientEncryptionAlgorithm,
            string activityId, string asyncMDNUrl, string logPath, long logSiteLimit, out string mdn)
        {
            if (String.IsNullOrEmpty(fileName)) throw new ArgumentNullException("filename");
            ILogFileWriter logFile = new LogFileWriter(new FileLocation { LogStored = logPath, LogFileSizeLimit = logSiteLimit });
            logFile.FileName(string.Format(FileNameDefault.Send_EdiLogFile, from, to));
            bool encrypt = !string.IsNullOrEmpty(recipientCertFilename);
            bool sign = !string.IsNullOrEmpty(signingCertFilename);
            byte[] content;
            HttpWebRequest http;
            string contentType;
            logFile.WriteLog($"Start send file {fileName} path {filePath}\r\nInterchangeId: {activityId}\r\nAsyncMdnUrl: '{asyncMDNUrl}'");
            DoBeforeSign(uri, filePath, fileName, from, to, proxySettings, timeoutMs, encrypt, sign, activityId, asyncMDNUrl, out content, out http, out contentType);
            if (sign)
            {
                // Wrap the file data with a mime header
                content = AS2MIMEUtilities.CreateMessage(contentType, "binary", $"attachment; filename={fileName}", content);
                var temp1 = ASCIIEncoding.ASCII.GetString(content);
                content = AS2MIMEUtilities.Sign(content, signingCertFilename, signingCertPassword, EncryptionAlgorithmSign.sha256, out contentType);
                var temp2 = ASCIIEncoding.ASCII.GetString(content);
                http.Headers.Add("EDIINT-Features", "multiple-attachments");
                //http.Headers.Add("Content-Type", contentType);
            }
            DoAfterSign(recipientCertFilename, receipientEncryptionAlgorithm, encrypt, ref content, http, ref contentType);

            SendWebRequest(http, content);

            var statusCode = HandleWebResponse(http, out mdn);
            logFile.WriteLog($"End send file {fileName} response: {statusCode.ToString()}\r\n{mdn}");
            return statusCode;
        }
        public static HttpStatusCode SendFile(Uri uri, string filePath, string fileName, string from, string to, ProxySettings proxySettings,
            int timeoutMs, byte[] signingCertBytes, string signingCertPassword, byte[] recipientCertFilename, string receipientEncryptionAlgorithm,
            string activityId, string asyncMDNUrl, string logPath, long logSiteLimit, out string mdn)
        {
            if (String.IsNullOrEmpty(fileName)) throw new ArgumentNullException("filename");
            ILogFileWriter logFile = new LogFileWriter(new FileLocation { LogStored = logPath, LogFileSizeLimit = logSiteLimit });
            logFile.FileName(string.Format(FileNameDefault.Send_EdiLogFile, from, to));
            bool encrypt = (recipientCertFilename != null && recipientCertFilename.Length > 0);
            bool sign = (signingCertBytes != null && signingCertBytes.Length > 0);
            byte[] content;
            HttpWebRequest http;
            string contentType;
            DoBeforeSign(uri, filePath, fileName, from, to, proxySettings, timeoutMs, encrypt, sign, activityId, asyncMDNUrl, out content, out http, out contentType);
            if (sign)
            {
                // Wrap the file data with a mime header
                content = AS2MIMEUtilities.CreateMessage(contentType, "binary", $"attachment; filename={fileName}", content);
                var temp1 = ASCIIEncoding.ASCII.GetString(content);
                content = AS2MIMEUtilities.Sign(content, signingCertBytes, signingCertPassword, EncryptionAlgorithmSign.sha256, out contentType);
                var temp2 = ASCIIEncoding.ASCII.GetString(content);
                http.Headers.Add("EDIINT-Features", "multiple-attachments");
                //http.Headers.Add("Content-Type", contentType);
            }
            DoAfterSign(recipientCertFilename, receipientEncryptionAlgorithm, encrypt, ref content, http, ref contentType);

            SendWebRequest(http, content);

            var statusCode = HandleWebResponse(http, out mdn);
            logFile.WriteLog($"End send file {fileName} response: {statusCode.ToString()}\r\n{mdn}");
            return statusCode;
        }
        private static void DoAfterSign(string recipientCertFilename, string receipientEncryptionAlgorithm, bool encrypt, ref byte[] content, HttpWebRequest http, ref string contentType)
        {
            if (encrypt)
            {
                if (string.IsNullOrEmpty(recipientCertFilename))
                {
                    throw new ArgumentNullException(recipientCertFilename, "if encrytionAlgorithm is specified then recipientCertFilename must be specified");
                }

                byte[] signedContentTypeHeader = ASCIIEncoding.ASCII.GetBytes("Content-Type: " + contentType + "\r\n");
                byte[] contentWithContentTypeHeaderAdded = AS2MIMEUtilities.ConcatBytes(signedContentTypeHeader, content);
                var keyAes = "this is the key to encrypt/decrypt by aes";
                var temp3 = ASCIIEncoding.ASCII.GetString(contentWithContentTypeHeaderAdded);
                content = AS2Encryption.Encrypt(contentWithContentTypeHeaderAdded, recipientCertFilename, receipientEncryptionAlgorithm, keyAes);


                contentType = "application/pkcs7-mime; smime-type=enveloped-data; name=\"smime.p7m\"";
            }

            http.ContentType = contentType;
            http.ContentLength = content.Length;
        }
        private static void DoAfterSign(byte[] recipientCertBytes, string receipientEncryptionAlgorithm, bool encrypt, ref byte[] content, HttpWebRequest http, ref string contentType)
        {
            if (encrypt)
            {
                byte[] signedContentTypeHeader = ASCIIEncoding.ASCII.GetBytes("Content-Type: " + contentType + "\r\n");
                byte[] contentWithContentTypeHeaderAdded = AS2MIMEUtilities.ConcatBytes(signedContentTypeHeader, content);
                var keyAes = "this is the key to encrypt/decrypt by aes";
                var temp3 = ASCIIEncoding.ASCII.GetString(contentWithContentTypeHeaderAdded);
                content = AS2Encryption.Encrypt(contentWithContentTypeHeaderAdded, recipientCertBytes, receipientEncryptionAlgorithm, keyAes);


                contentType = "application/pkcs7-mime; smime-type=enveloped-data; name=\"smime.p7m\"";
            }

            http.ContentType = contentType;
            http.ContentLength = content.Length;
        }
        private static void DoBeforeSign(Uri uri, string filePath, string fileName, string from, string to, ProxySettings proxySettings, int timeoutMs, bool encrypt, bool sign, string activityId, string asyncMDNUrl, out byte[] content, out HttpWebRequest http, out string contentType)
        {
            string fileData = System.IO.File.ReadAllText(filePath + fileName, ASCIIEncoding.ASCII);
            fileData = fileData.Replace("\n", "\r\n");
            if (fileData.Length == 0) throw new ArgumentException("fileData");

            content = ASCIIEncoding.ASCII.GetBytes(fileData);

            //Initialise the request
            http = (HttpWebRequest)WebRequest.Create(uri);
            if (!String.IsNullOrEmpty(proxySettings.Name))
            {
                WebProxy proxy = new WebProxy(proxySettings.Name);

                NetworkCredential proxyCredential = new NetworkCredential();
                proxyCredential.Domain = proxySettings.Domain;
                proxyCredential.UserName = proxySettings.Username;
                proxyCredential.Password = proxySettings.Password;

                proxy.Credentials = proxyCredential;

                http.Proxy = proxy;
            }

            //Define the standard request objects
            http.Method = "POST";

            http.AllowAutoRedirect = true;

            http.KeepAlive = true;

            http.PreAuthenticate = false; //Means there will be two requests sent if Authentication required.
            http.SendChunked = false;

            http.UserAgent = "sConnect/AS2Sender-1.0";

            //These Headers are common to all transactions
            http.Headers.Add("Mime-Version", "1.0");
            http.Headers.Add("AS2-Version", "1.2");

            http.Headers.Add("AS2-From", from);
            http.Headers.Add("AS2-To", to);
            http.Headers.Add("Subject", fileName + " transmission.");
            http.Headers.Add("Message-Id", "<AS2_" + activityId + ">");
            if (!string.IsNullOrEmpty(asyncMDNUrl)) // request async mdn
            {
                http.Headers.Add("Disposition-Notification-To", "truongtinhnguyen@gmail.com");
                http.Headers.Add("Disposition-Notification-Options", "signed-receipt-protocol=optional, pkcs7-signature; signed-receipt-micalg=optional, sha1");
                http.Headers.Add("as2_mdn_to", asyncMDNUrl);
                http.Headers.Add("as2_receipt_option", asyncMDNUrl);
                http.Headers.Add("receipt-delivery-option", asyncMDNUrl);
            }
            http.Timeout = timeoutMs;

            contentType = (Path.GetExtension(fileName) == ".xml") ? "application/xml" : "application/edi-x12";


            if (!sign && !encrypt)
            {
                http.Headers.Add("Content-Transfer-Encoding", "binary");
                http.Headers.Add("Content-Disposition", "inline; filename=\"" + fileName + "\"");
            }
        }

        private static HttpStatusCode HandleWebResponse(HttpWebRequest http, out string mdn)
        {
            HttpWebResponse response = (HttpWebResponse)http.GetResponse();
            var statusCode = response.StatusCode;
            var encoding = ASCIIEncoding.ASCII;
            using (var reader = new System.IO.StreamReader(response.GetResponseStream(), encoding))
            {
                mdn = reader.ReadToEnd();
            }
            response.Close();
            return statusCode;
        }

        private static void SendWebRequest(HttpWebRequest http, byte[] fileData)
        {
            Stream oRequestStream = http.GetRequestStream();
            oRequestStream.Write(fileData, 0, fileData.Length);
            oRequestStream.Flush();
            oRequestStream.Close();
        }
    }
}