using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Net.AS2.Core
{
    public class CreateMdn
    {
//        public HttpWebResponse CreateMdn()
//        {
//            HttpWebResponse response = new HttpWebResponse();
//            response.Clear();
//            response.Headers.Add("Date", DateTime.UtcNow.ToString("ddd, dd MMM yyy HH: mm:ss") + " GMT");

//            var incoming_subject = request.Headers["Subject"];
//            var response_subject = "Re:";
//            if (incoming_subject != null) response_subject = response_subject + incoming_subject;
//            response.Headers.Add("Subject", response_subject);

//            response.Headers.Add("Mime - Version", "1.0");
//            response.Headers.Add("AS2 - Version", "1.2");
//            response.Headers.Add("From", "XXXXXXXXXX");
//            response.Headers.Add("AS2 - To", request.Headers["AS2 - From"]);
//            response.Headers.Add("AS2 - From", request.Headers["AS2 - To"]);
//            response.Headers.Add("Connection", "Close");
//            response.ContentType = "multipart / report; report - type = disposition - notification;";
//            response.StatusCode = 202; // Accepted
//            response.StatusDescription = "Accepted";

//            var incoming_date = request.Headers["Date"];
//            var dateTimeSent = "Unknown date";
//            if (incoming_date != null) dateTimeSent = incoming_date;

//            var responseContent1 = "The Message from ‘" +request.Headers["AS2 - From"] + "‘ to ‘" +
//            request.Headers["AS2 - To"] + "‘ " +Environment.NewLine +
//"with MessageID ‘" +request.Headers["Message - Id"] + "‘" +Environment.NewLine + "sent " +dateTimeSent +
//" has been accepted for processing. " +Environment.NewLine +
//"This does not guarantee that the message has been read or understood." +Environment.NewLine;

//var responseContent2 = "Reporting - UA: AS2 Adapter" +Environment.NewLine +
//"Final - Recipient: rfc822;" +request.Headers["AS2 - From"] + Environment.NewLine +
//"Original - Message - ID: " +request.Headers["Message - ID"] + Environment.NewLine +
//"Disposition: automatic - action / MDN - Sent - automatically; processed";

//            var finalBodyContent = Encoding.ASCII.GetBytes(responseContent1);
//            var finalBodyContent2 = Encoding.ASCII.GetBytes(responseContent2);

//            //Wrap the file data with a mime header
//            finalBodyContent2 = Utilities.CreateMessage("message / disposition - notification", "7bit", "", finalBodyContent2);

//            var PublicAndPrivateKeyPath = "some path"
//var SigningPassword = "take it from app config";
//            string contentType;
//            finalBodyContent2 = Utilities.Sign(finalBodyContent2, PublicAndPrivateKeyPath, SigningPassword, out contentType);
//            response.Headers.Add("EDIINT - Features", "AS2 - Reliability");

//            byte[] signedContentTypeHeader = System.Text.Encoding.ASCII.GetBytes("Content - Type: " + "text / plain" +Environment.NewLine);
//            byte[] contentWithContentTypeHeaderAdded = Utilities.ConcatBytes(signedContentTypeHeader, finalBodyContent2);

//            finalBodyContent2 = Encryption.Encrypt(contentWithContentTypeHeaderAdded, clientCertificatePath,
//            EncryptionAlgorithm.DES3);

//            byte[] finalResponse = finalBodyContent.Concat(finalBodyContent2).ToArray();

//            response.BinaryWrite(finalResponse);
//        }

    }
}
