using MimeKit;
using MimeKit.Cryptography;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Net.AS2.Core
{
    /// <summary>
    /// Contains a number of useful static functions for creating MIME messages.
    /// </summary>
    public class AS2MIMEUtilities
    {
        public const string MESSAGE_SEPARATOR = "\r\n\r\n";
        public const string VerifyFail = "Can't verify signature";
        public AS2MIMEUtilities()
        {
        }
        /// <summary>
        /// Extracts the payload from a signed message, by looking for boundaries
        /// Ignores signatures and does checking - should really validate the signature
        /// </summary>
        public static string ExtractPayloadEdi(string message, string contentType)
        {
            
            int firstBoundary = message.IndexOf(MESSAGE_SEPARATOR);
            int payloadLength = message.Length - "\r\n".Length - firstBoundary - MESSAGE_SEPARATOR.Length;
            return message.Substring(firstBoundary + MESSAGE_SEPARATOR.Length, payloadLength);
        }

        public static (string, bool) ExtractPayload(string message, string contentType, byte[] senderCert, bool? isSigned)
        {
            string boundary = GetBoundaryFromContentType(contentType);
            boundary = "--" + boundary;

            int firstBoundary = message.IndexOf(boundary);
            int blankLineAfterBoundary = message.IndexOf("\r\n", firstBoundary) + ("\r\n").Length;
            int nextBoundary = message.IndexOf(MESSAGE_SEPARATOR + boundary, blankLineAfterBoundary);

            int payloadLength = nextBoundary - blankLineAfterBoundary;

            string mdnMessage = message.Substring(blankLineAfterBoundary, payloadLength) + "\r\n";

            //Get Sign in nextBoundary
            var verifyResult = true;
            if (isSigned.HasValue && isSigned.Value)
            {
                verifyResult = ExtractAndVerifySignMdn(nextBoundary, message, mdnMessage, boundary, MESSAGE_SEPARATOR, senderCert);
            }
            return (mdnMessage, verifyResult);
        }
        public static bool ExtractAndVerifySignMdn(int nextBoundary, string message, string mdnMessage, string boundary, string MESSAGE_SEPARATOR, byte[] senderCert)
        {
            int lastBoundary = message.IndexOf(boundary + "--");
            int length = message.Length - (message.Length - lastBoundary) - nextBoundary - MESSAGE_SEPARATOR.Length - "\r\n".Length;
            var partSign = message.Substring(nextBoundary + MESSAGE_SEPARATOR.Length, length);
            int breakLine = partSign.IndexOf(MESSAGE_SEPARATOR);
            var partSign1 = partSign.Substring(breakLine + MESSAGE_SEPARATOR.Length);
            byte[] fileData = ASCIIEncoding.ASCII.GetBytes(mdnMessage);
            byte[] signature = Convert.FromBase64String(partSign1);
            var result = AS2Encryption.VerifySign(fileData, signature, senderCert);
            return result;
        }
        /// <summary>
        /// Extracts the boundary from a Content-Type string
        /// </summary>
        /// <param name="contentType">e.g: multipart/signed; protocol="application/pkcs7-signature"; micalg="sha1"; boundary="_956100ef6a82431fb98f65ee70c00cb9_"</param>
        /// <returns>e.g: _956100ef6a82431fb98f65ee70c00cb9_</returns>
        public static string GetBoundaryFromContentType(string contentType)
        {
            return Trim(contentType, "boundary=\"", "\"");
        }

        /// <summary>
        /// Trims the string from the end of startString until endString
        /// </summary>
        private static string Trim(string str, string start, string end)
        {
            int startIndex = str.IndexOf(start) + start.Length;
            int endIndex = str.IndexOf(end, startIndex);
            int length = endIndex - startIndex;

            return str.Substring(startIndex, length);
        }
        /// <summary>
        /// return a unique MIME style boundary
        /// this needs to be unique enought not to occur within the data
        /// and so is a Guid without - or { } characters.
        /// </summary>
        /// <returns></returns>
        protected static string MIMEBoundary()
        {
            return "_" + Guid.NewGuid().ToString("N") + "_";
        }

        /// <summary>
        /// Creates the a Mime header out of the components listed.
        /// </summary>
        /// <param name="sContentType">Content type</param>
        /// <param name="sEncoding">Encoding method</param>
        /// <param name="sDisposition">Disposition options</param>
        /// <returns>A string containing the three headers.</returns>
        public static string MIMEHeader(string sContentType, string sEncoding, string sDisposition)
        {
            string sOut = "";

            sOut = "Content-Type: " + sContentType + "\r\n";
            if (sDisposition != "")
                sOut += "Content-Disposition: " + sDisposition + "\r\n";
            if (sEncoding != "")
                sOut += "Content-Transfer-Encoding: " + sEncoding + "\r\n";
            sOut = sOut + "\r\n";

            return sOut;
        }

        /// <summary>
        /// Return a single array of bytes out of all the supplied byte arrays.
        /// </summary>
        /// <param name="arBytes">Byte arrays to add</param>
        /// <returns>The single byte array.</returns>
        public static byte[] ConcatBytes(params byte[][] arBytes)
        {
            long lLength = 0;
            long lPosition = 0;

            //Get total size required.
            foreach (byte[] ar in arBytes)
                lLength += ar.Length;

            //Create new byte array
            byte[] toReturn = new byte[lLength];

            //Fill the new byte array
            foreach (byte[] ar in arBytes)
            {
                ar.CopyTo(toReturn, lPosition);
                lPosition += ar.Length;
            }

            return toReturn;
        }

        /// <summary>
        /// Create a Message out of byte arrays (this makes more sense than the above method)
        /// </summary>
        /// <param name="sContentType">Content type ie multipart/report</param>
        /// <param name="sEncoding">The encoding provided...</param>
        /// <param name="sDisposition">The disposition of the message...</param>
        /// <param name="abMessageParts">The byte arrays that make up the components</param>
        /// <returns>The message as a byte array.</returns>
        public static byte[] CreateMessage(string sContentType, string sEncoding, string sDisposition, params byte[][] abMessageParts)
        {
            int iHeaderLength = 0;
            return CreateMessage(sContentType, sEncoding, sDisposition, out iHeaderLength, abMessageParts);
        }
        /// <summary>
        /// Create a Message out of byte arrays (this makes more sense than the above method)
        /// </summary>
        /// <param name="sContentType">Content type ie multipart/report</param>
        /// <param name="sEncoding">The encoding provided...</param>
        /// <param name="sDisposition">The disposition of the message...</param>
        /// <param name="iHeaderLength">The length of the headers.</param>
        /// <param name="abMessageParts">The message parts.</param>
        /// <returns>The message as a byte array.</returns>
        public static byte[] CreateMessage(string sContentType, string sEncoding, string sDisposition, out int iHeaderLength, params byte[][] abMessageParts)
        {
            long lLength = 0;
            long lPosition = 0;

            //Only one part... Add headers only...
            if (abMessageParts.Length == 1)
            {
                byte[] bHeader = ASCIIEncoding.ASCII.GetBytes(MIMEHeader(sContentType, sEncoding, sDisposition));
                iHeaderLength = bHeader.Length;
                return ConcatBytes(bHeader, abMessageParts[0]);
            }
            else
            {
                // get boundary and "static" subparts.
                string sBoundary = MIMEBoundary();
                byte[] bPackageHeader = ASCIIEncoding.ASCII.GetBytes(MIMEHeader(sContentType + "; boundary=\"" + sBoundary + "\"", sEncoding, sDisposition));
                byte[] bBoundary = ASCIIEncoding.ASCII.GetBytes("\r\n" + "--" + sBoundary + "\r\n");
                byte[] bFinalFooter = ASCIIEncoding.ASCII.GetBytes("\r\n" + "--" + sBoundary + "--" + "\r\n");

                //Calculate the total size required.
                iHeaderLength = bPackageHeader.Length;

                foreach (byte[] ar in abMessageParts)
                    lLength += ar.Length;
                lLength += iHeaderLength + bBoundary.Length * abMessageParts.Length +
                    bFinalFooter.Length;

                //Create new byte array to that size.
                byte[] toReturn = new byte[lLength];

                //Copy the headers in.
                bPackageHeader.CopyTo(toReturn, lPosition);
                lPosition += bPackageHeader.Length;

                //Fill the new byte array in by coping the message parts.
                foreach (byte[] ar in abMessageParts)
                {
                    bBoundary.CopyTo(toReturn, lPosition);
                    lPosition += bBoundary.Length;

                    ar.CopyTo(toReturn, lPosition);
                    lPosition += ar.Length;
                }

                //Finally add the footer boundary.
                bFinalFooter.CopyTo(toReturn, lPosition);

                return toReturn;
            }
        }

        /// <summary>
        /// Signs a message and returns a MIME encoded array of bytes containing the signature.
        /// </summary>
        /// <param name="arMessage"></param>
        /// <param name="bPackageHeader"></param>
        /// <returns></returns>
        public static byte[] Sign(byte[] arMessage, string signerCert, string signerPassword, string encryptionAlgorithmSign, out string sContentType)
        {
            byte[] bBoundary, bSignatureHeader;
            string sBoundary;
            DoBeforeSign(out sContentType, out sBoundary, out bBoundary, out bSignatureHeader);

            byte[] bInPKCS7 = new byte[0];
            // Get the signature.
            byte[] bSignature = AS2Encryption.Sign(arMessage, signerCert, signerPassword, encryptionAlgorithmSign);
            bInPKCS7 = DoAfterSign(arMessage, bBoundary, bSignatureHeader, sBoundary, ref bSignature);

            return bInPKCS7;
        }
        public static byte[] Sign(byte[] arMessage, byte[] signerCert, string signerPassword, string encryptionAlgorithmSign, out string sContentType)
        {
            byte[] bBoundary, bSignatureHeader;
            string sBoundary;
            DoBeforeSign(out sContentType, out sBoundary, out bBoundary, out bSignatureHeader);
            byte[] bInPKCS7 = new byte[0];
            // Get the signature.
            byte[] bSignature = AS2Encryption.Sign(arMessage, signerCert, signerPassword, encryptionAlgorithmSign);
            bInPKCS7 = DoAfterSign(arMessage, bBoundary, bSignatureHeader, sBoundary, ref bSignature);

            return bInPKCS7;
        }
        private static byte[] DoAfterSign(byte[] arMessage, byte[] bBoundary, byte[] bSignatureHeader, string sBoundary, ref byte[] bSignature)
        {
            byte[] bInPKCS7;
            // convert to base64
            string sig = Convert.ToBase64String(bSignature, Base64FormattingOptions.InsertLineBreaks) + MESSAGE_SEPARATOR;
            bSignature = System.Text.ASCIIEncoding.ASCII.GetBytes(sig);

            // Calculate the final footer elements.
            byte[] bFinalFooter = ASCIIEncoding.ASCII.GetBytes("--" + sBoundary + "--" + "\r\n");

            // Concatenate all the above together to form the message.
            bInPKCS7 = ConcatBytes(bBoundary, arMessage, bBoundary,
                bSignatureHeader, bSignature, bFinalFooter);
            return bInPKCS7;
        }

        private static void DoBeforeSign(out string sContentType, out string sBoundary, out byte[] bBoundary, out byte[] bSignatureHeader)
        {
            // get a MIME boundary
            sBoundary = MIMEBoundary();

            // Get the Headers for the entire message.
            sContentType = "multipart/signed; protocol=\"application/pkcs7-signature\"; micalg=\"sha256\"; boundary=\"" + sBoundary + "\"";

            // Define the boundary byte array.
            bBoundary = ASCIIEncoding.ASCII.GetBytes("\r\n" + "--" + sBoundary + "\r\n");

            // Encode the header for the signature portion.
            bSignatureHeader = ASCIIEncoding.ASCII.GetBytes(MIMEHeader("application/pkcs7-signature; name=\"smime.p7s\"", "base64", "attachment; filename=\"smime.p7s\""));
        }
    }
}
