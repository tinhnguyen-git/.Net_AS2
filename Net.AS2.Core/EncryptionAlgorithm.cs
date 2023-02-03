using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Net.AS2.Core
{
    public class EncryptionAlgorithmSign
    {
        public const string rsa_md5 = "cast5";//See compatibility note in RFC 5751, section 3.4.3.1
        public const string rsa_sha1 = "SHA1WITHRSA";//See compatibility note in RFC 5751, section 3.4.3.1
        public const string md5 = "MD5WITHRSA";//Same for RFC 3851 and RFC 5751
        public const string sha1 = "SHA1WITHRSA";// Old version as of RFC 3851.
        public const string sha256 = "SHA256WITHRSA";//Old version as of RFC 3851.
        public const string sha384 = "SHA384WITHRSA";//Old version as of RFC 3851.
        public const string sha512 = "SHA512WITHRSA";//Old version as of RFC 3851.
        public const string sha_1 = "SHA1WITHRSA";//New version as of RFC 5751.
        public const string sha_224 = "SHA224WITHRSA";
        public const string sha_256 = "SHA256WITHRSA";//New version as of RFC 5751.
        public const string sha_384 = "SHA384WITHRSA";//New version as of RFC 5751.
        public const string sha_512 = "SHA1WITHRSA";//SHA512WITHRSA
        public const string rsassa_pkcs1_v1_5_with_sha3_256 = "RSASSAPSS";//id_rsassa_pkcs1_v1_5_with_sha3_256
    }
    public class EncryptionAlgorithm
    {
        public const string des_EDE3_CBC = "3des";
        public const string RC2_CBC = "rc2";
        public const string CAST5_CBC = "cast5";
        public const string IDEA_CBC = "idea";
        public const string AES128_CBC = "aes128-cbc";
        public const string AES192_CBC = "aes192-cbc";
        public const string AES256_CBC = "aes256-cbc";//Oid("2.16.840.1.101.3.4.1.42")
        public const string AES128_GCM = "aes128-gcm";
        public const string AES192_GCM = "aes192-gcm";
        public const string AES256_GCM = "aes256-gcm";//2.16.840.1.101.3.4.1.46
    }
    public class AS2Encryption
    {
        private RsaKeyParameters MakeKey(string modulusHexString, string exponentHexString, bool isPrivateKey)
        {
            var modulus = new Org.BouncyCastle.Math.BigInteger(modulusHexString, 16);
            var exponent = new Org.BouncyCastle.Math.BigInteger(exponentHexString, 16);

            return new RsaKeyParameters(isPrivateKey, modulus, exponent);
        }
        public static byte[] Sign(byte[] arMessage, string signerCert, string signerPassword, string encryptionAlgorithmSign = EncryptionAlgorithmSign.sha_1)
        {
            X509Certificate2 cert = new X509Certificate2(signerCert, signerPassword, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);

            Oid dstOid = new Oid("1.2.840.113549.1.7.1"); // PKCS#7   1.2.840.113549.1.7.2 is incorrect
            ContentInfo contentInfo = new ContentInfo(dstOid, arMessage);
            SignedCms signedCms = new SignedCms(contentInfo, true);

            CmsSigner signerWindowStore = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, cert, cert.GetRSAPrivateKey());
            signerWindowStore.DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1");//sha256//new Oid("1.3.14.3.2.26"); // SHA1
            //signerWindowStore.DigestAlgorithm = new Oid("1.3.14.3.2.26"); // SHA1
            signerWindowStore.IncludeOption = X509IncludeOption.EndCertOnly;
            signedCms.ComputeSignature(signerWindowStore, false);
            byte[] signature = signedCms.Encode();
            return signature;
            //--------------------
            //X509Certificate2 cert = new X509Certificate2(signerCert, signerPassword, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
            //ContentInfo contentInfo = new ContentInfo(arMessage);

            //SignedCms signedCms = new SignedCms(contentInfo, true); // <- true detaches the signature
            //CmsSigner cmsSigner = new CmsSigner(cert);

            //signedCms.ComputeSignature(cmsSigner);
            //byte[] signature = signedCms.Encode();

            //return signature;


            //-----------------------------

            //X509Certificate2 cert = new X509Certificate2(signerCert, signerPassword, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
            //byte[] wSignature1;
            //var privateParameter = DotNetUtilities.GetKeyPair(cert.GetRSAPrivateKey()).Private;
            //if (encryptionAlgorithmSign == EncryptionAlgorithmSign.sha256)
            //{
            //    // sign with BouncyCastle               

            //    /* Init alg */
            //    ISigner sig = SignerUtilities.GetSigner("SHA-256withRSA");

            //    /* Populate key */
            //    sig.Init(true, privateParameter);
            //    /* Calc the signature */
            //    sig.BlockUpdate(arMessage, 0, arMessage.Length);
            //    wSignature1 = sig.GenerateSignature();
            //    //Sha256Digest sha256Digest = new Sha256Digest();
            //    //byte[] theHash = new byte[sha256Digest.GetDigestSize()];
            //    //sha256Digest.BlockUpdate(arMessage, 0, arMessage.Length);
            //    //sha256Digest.DoFinal(theHash, 0);
            //    //PssSigner pssSigner = new PssSigner(new RsaEngine(), new Sha256Digest(), sha256Digest.GetDigestSize());
            //    ////PssSigner pssSigner = new PssSigner(new RsaEngine(), new ShakeDigest(256), new ShakeDigest(256), 32); // works also
            //    //var privateParameter = DotNetUtilities.GetKeyPair(cert.GetRSAPrivateKey()).Private;
            //    //pssSigner.Init(true, privateParameter);
            //    //pssSigner.BlockUpdate(theHash, 0, theHash.Length);
            //    //wSignature1 = pssSigner.GenerateSignature();
            //}
            //else //if (encryptionAlgorithmSign == EncryptionAlgorithmSign.sha_1)
            //{/* Init alg */
            //    ISigner sig = SignerUtilities.GetSigner("SHA-1withRSA");

            //    /* Populate key */
            //    sig.Init(true, privateParameter);
            //    /* Calc the signature */
            //    sig.BlockUpdate(arMessage, 0, arMessage.Length);
            //    wSignature1 = sig.GenerateSignature();
            //    //Sha1Digest sha1Digest = new Sha1Digest();
            //    //byte[] theHash = new byte[sha1Digest.GetDigestSize()];
            //    //sha1Digest.BlockUpdate(arMessage, 0, arMessage.Length);
            //    //sha1Digest.DoFinal(theHash, 0);
            //    //PssSigner pssSigner = new PssSigner(new RsaEngine(), new Sha1Digest(), sha1Digest.GetDigestSize());
            //    //var privateParameter = DotNetUtilities.GetKeyPair(cert.GetRSAPrivateKey()).Private;
            //    //pssSigner.Init(true, privateParameter);
            //    //pssSigner.BlockUpdate(theHash, 0, theHash.Length);
            //    //wSignature1 = pssSigner.GenerateSignature();
            //}
            //return wSignature1;
        }
        public static byte[] Sign(byte[] arMessage, byte[] signerCert, string signerPassword, string encryptionAlgorithmSign = EncryptionAlgorithmSign.sha_1)
        {
            X509Certificate2 cert = new X509Certificate2(signerCert, signerPassword, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);

            Oid dstOid = new Oid("1.2.840.113549.1.7.1"); // PKCS#7   1.2.840.113549.1.7.2 is incorrect
            ContentInfo contentInfo = new ContentInfo(dstOid, arMessage);
            SignedCms signedCms = new SignedCms(contentInfo, true);

            CmsSigner signerWindowStore = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, cert, cert.GetRSAPrivateKey());
            signerWindowStore.DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1");//sha256//new Oid("1.3.14.3.2.26"); // SHA1
            signerWindowStore.IncludeOption = X509IncludeOption.EndCertOnly;
            signedCms.ComputeSignature(signerWindowStore, false);
            byte[] signature = signedCms.Encode();
            return signature;
        }
        public static bool VerifySign(byte[] arMessage, byte[] signatureData, string signerCert, string encryptionAlgorithmSign = EncryptionAlgorithmSign.sha_1)
        {
            bool result1 = true;
            try
            {
                X509Certificate2 cert = new X509Certificate2(signerCert);
                //using (RSA rsa = cert.GetRSAPublicKey())
                //{
                //    var resultRsa= rsa.VerifyData(arMessage, signatureData, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
                //}
                ////var provider = (RSACryptoServiceProvider)cert.PublicKey.Key;
                ////var resultRsa1 = provider.VerifyData(arMessage, new SHA1CryptoServiceProvider(), signatureData);


                //var bcCert1 = DotNetUtilities.FromX509Certificate(cert);
                //ISigner signer = SignerUtilities.GetSigner("SHA1withRSA");
                //signer.Init(false, bcCert1.GetPublicKey());
                //signer.BlockUpdate(arMessage, 0, arMessage.Length);
                //var bcResult = signer.VerifySignature(signatureData);


                Oid dstOid = new Oid("1.2.840.113549.1.7.1"); // PKCS#7   1.2.840.113549.1.7.2 is incorrect
                ContentInfo contentInfo = new ContentInfo(dstOid, arMessage);
                SignedCms signedCms = new SignedCms(SubjectIdentifierType.IssuerAndSerialNumber, contentInfo, true);
                signedCms.Decode(signatureData);
                X509Certificate2Collection coll = new X509Certificate2Collection(cert);
                signedCms.CheckHash();
                signedCms.CheckSignature(coll, true);
            }
            catch(Exception ex)
            {
                Serilog.Log.Logger.Error(ex, "AS2Encryption.VerifySign");
                return false;
            }
            //try
            //{
            //    X509Certificate2 cert = new X509Certificate2(signerCert);
            //    var bcCert1 = DotNetUtilities.FromX509Certificate(cert);
            //    if (encryptionAlgorithmSign == EncryptionAlgorithmSign.sha256)
            //    {
            //        ISigner signer = SignerUtilities.GetSigner("SHA-256withRSA");
            //        signer.Init(false, bcCert1.GetPublicKey());
            //        signer.BlockUpdate(arMessage, 0, arMessage.Length);
            //        return signer.VerifySignature(signatureData);

            //        ///// Init public to verify
            //        //Sha256Digest sha256Digest1 = new Sha256Digest();
            //        //byte[] theHash1 = new byte[sha256Digest1.GetDigestSize()];
            //        //sha256Digest1.BlockUpdate(arMessage, 0, arMessage.Length);
            //        //sha256Digest1.DoFinal(theHash1, 0);
            //        //var bcCert1 = DotNetUtilities.FromX509Certificate(cert);
            //        //PssSigner pssSignerVerify = new PssSigner(new RsaEngine(), new Sha256Digest(), sha256Digest1.GetDigestSize());
            //        //pssSignerVerify.Init(false, bcCert1.GetPublicKey());
            //        //pssSignerVerify.BlockUpdate(theHash1, 0, theHash1.Length);
            //        ////bool result = pssSignerVerify.VerifySignature(wSignature);
            //        //result1 = pssSignerVerify.VerifySignature(signatureData);
            //    }
            //    else //if (encryptionAlgorithmSign == EncryptionAlgorithmSign.sha_1)
            //    {
            //        ISigner signer = SignerUtilities.GetSigner("SHA-1withRSA");
            //        signer.Init(false, bcCert1.GetPublicKey());
            //        signer.BlockUpdate(arMessage, 0, arMessage.Length);
            //        return signer.VerifySignature(signatureData);
            //        //Sha1Digest sha1Digest1 = new Sha1Digest();
            //        //byte[] theHash1 = new byte[sha1Digest1.GetDigestSize()];
            //        //sha1Digest1.BlockUpdate(arMessage, 0, arMessage.Length);
            //        //sha1Digest1.DoFinal(theHash1, 0);
            //        //var bcCert1 = DotNetUtilities.FromX509Certificate(cert);
            //        //PssSigner pssSignerVerify = new PssSigner(new RsaEngine(), new Sha1Digest(), sha1Digest1.GetDigestSize());
            //        //pssSignerVerify.Init(false, bcCert1.GetPublicKey());
            //        //pssSignerVerify.BlockUpdate(theHash1, 0, theHash1.Length);
            //        ////bool result = pssSignerVerify.VerifySignature(wSignature);
            //        //result1 = pssSignerVerify.VerifySignature(signatureData);
            //    }
            //}
            //catch (Exception exc)
            //{
            //    Console.WriteLine("Verification failed with the error: " + exc.ToString());
            //    return false;
            //}
            return result1;
        }
        public static bool VerifySign(byte[] arMessage, byte[] signatureData, byte[] signerCert, string encryptionAlgorithmSign = EncryptionAlgorithmSign.sha_1)
        {
            bool result1 = true;
            try
            {
                X509Certificate2 cert = new X509Certificate2(signerCert);
                ContentInfo contentInfo = new ContentInfo(arMessage);

                SignedCms signedCms = new SignedCms(contentInfo, true); // <- true detaches the signature
                signedCms.Decode(signatureData);

                signedCms.CheckSignature(true);
            }
            catch (Exception ex)
            {
                return false;
            }
            return result1;
        }
        public static byte[] Encrypt(byte[] message, string recipientCert, string encryptionAlgorithm, string aesKeyGcm)
        {
            //            Doing encryption using PKCS#7 the process is:

            //Generate random symmetric key(i.e.AES256)
            //encrypt data with symmetric key
            //encrypt symmetric key with public key of the recipient(if X recipients should be able to decrypt then encrypt the symmetric key X-times)
            //put it all together in PKCS#7 (encrypted symmetric key is put in a structure with some identification of the recipient. Usually it is serial number and issuer DN of the certificate which was used for encryption of symmetric key)
            //Decryption process is:
            //find recipient able to decrypt the message.PKCS#7 contains serial numbers and issuer DNs of all recipients who should be able to decrypt. Now look in crypto store for a certificate with serial number and issuer DN that has a corresponding private key. It does not matter which private key will be used if you have all recipients private keys in crypto store.
            //use private key to decrypt symmetric key used in the encryption process
            //use symmetric key to decrypt data
            X509Certificate2 cert = new X509Certificate2(recipientCert);
            X509Certificate2Collection col = new X509Certificate2Collection(cert);
            return SwitchCaseEncrypt(message, encryptionAlgorithm, cert);
        }
        public static byte[] Encrypt(byte[] message, byte[] recipientCert, string encryptionAlgorithm, string aesKeyGcm)
        {
            X509Certificate2 cert = new X509Certificate2(recipientCert);
            X509Certificate2Collection col = new X509Certificate2Collection(cert);
            return SwitchCaseEncrypt(message, encryptionAlgorithm, cert);
        }

        private static byte[] SwitchCaseEncrypt(byte[] message, string encryptionAlgorithm, X509Certificate2 cert)
        {
            switch (encryptionAlgorithm)
            {
                case EncryptionAlgorithm.CAST5_CBC:
                    var encryptEngine = new Pkcs1Encoding(new RsaEngine());
                    var bcCert1 = DotNetUtilities.FromX509Certificate(cert);
                    encryptEngine.Init(true, bcCert1.GetPublicKey());
                    var encrypted = encryptEngine.ProcessBlock(message, 0, message.Length);
                    return encrypted;
                case EncryptionAlgorithm.AES256_GCM:
                    AesCryptoServiceProvider publicKeyProviderAes = new AesCryptoServiceProvider();
                    //AesGcm gcm = new AesGcm(cert.GetPublicKey());
                    //gcm.Encrypt()
                    publicKeyProviderAes.Key = cert.GetPublicKey();
                    var result2 = publicKeyProviderAes.EncryptCbc(message, publicKeyProviderAes.Key);
                    return result2;
                case EncryptionAlgorithm.AES256_CBC:
                    string oidAES256_CBC = "2.16.840.1.101.3.4.1.42";
                    return EncryptCBC(message, cert, oidAES256_CBC);
                default:
                    string oid = EncryptionAlgorithm.des_EDE3_CBC;
                    return EncryptCBC(message, cert, oid);
            }
        }

        private static byte[] EncryptCBC(byte[] message, X509Certificate2 cert, string oid)
        {
            ContentInfo contentInfo = new ContentInfo(message);
            EnvelopedCms envelopedCms = new EnvelopedCms(contentInfo,
                new AlgorithmIdentifier(new System.Security.Cryptography.Oid(oid)));
            CmsRecipient recipient = new CmsRecipient(SubjectIdentifierType.IssuerAndSerialNumber, cert);
            envelopedCms.Encrypt(recipient);

            byte[] encoded = envelopedCms.Encode();
            return encoded;
        }

        //public static byte[] Decrypt(byte[] encodedEncryptedMessage, out string encryptionAlgorithmName)
        //{
        //EnvelopedCms envelopedCms = new EnvelopedCms();

        //// NB. the message will have been encrypted with your public key.
        //// The corresponding private key must be installed in the Personal Certificates folder of the user
        //// this process is running as.
        //envelopedCms.Decode(encodedEncryptedMessage);

        //envelopedCms.Decrypt();
        //encryptionAlgorithmName = envelopedCms.ContentEncryptionAlgorithm.Oid.FriendlyName;

        //return envelopedCms.Encode();
        //}
        public static byte[] Decrypt(byte[] encodedEncryptedMessage, string recipientCert, string recipientCertPassword, string encryptionAlgorithm, string aesKeyGcm)
        {
            X509Certificate2 cert = new X509Certificate2(recipientCert, recipientCertPassword, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
            X509Certificate2Collection col = new X509Certificate2Collection(cert);
            return SwitchCaseDecrypt(encodedEncryptedMessage, encryptionAlgorithm, cert, col);
        }
        public static byte[] Decrypt(byte[] encodedEncryptedMessage, byte[] recipientCert, string recipientCertPassword, string encryptionAlgorithm, string aesKeyGcm)
        {
            X509Certificate2 cert = new X509Certificate2(recipientCert, recipientCertPassword, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
            X509Certificate2Collection col = new X509Certificate2Collection(cert);
            return SwitchCaseDecrypt(encodedEncryptedMessage, encryptionAlgorithm, cert, col);
        }

        private static byte[] SwitchCaseDecrypt(byte[] encodedEncryptedMessage, string encryptionAlgorithm, X509Certificate2 cert, X509Certificate2Collection col)
        {
            switch (encryptionAlgorithm)
            {
                //case EncryptionAlgorithm.sha_256:
                //    var decrypt = new Encryptor<RsaEngine, Sha256Digest>(Encoding.UTF8, key, hmacKey);

                //    var resultSha256 = decrypt.DecryptBytes(encodedEncryptedMessage);
                //    return resultSha256;

                //System.Security.Cryptography.RSACng rSACng = (System.Security.Cryptography.RSACng)cert.GetRSAPrivateKey();
                //var result1 = rSACng.Decrypt(encodedEncryptedMessage, RSAEncryptionPadding.OaepSHA256);
                //return result1;
                //var privateKey = cert.PrivateKey;
                //if (privateKey is System.Security.Cryptography.RSACng)
                //{
                //    System.Security.Cryptography.RSACng rSACng = (System.Security.Cryptography.RSACng)cert.GetRSAPrivateKey();
                //    var result1 = rSACng.Decrypt(encodedEncryptedMessage, RSAEncryptionPadding.Pkcs1);
                //    return result1;
                //}
                //else if (privateKey is RSACryptoServiceProvider)
                //{
                //    RSACryptoServiceProvider privateKeyProvider = (RSACryptoServiceProvider)cert.GetRSAPrivateKey();
                //    var result = privateKeyProvider.Decrypt(encodedEncryptedMessage, false);
                //    return result;
                //}
                case EncryptionAlgorithm.AES256_GCM:
                    AesCryptoServiceProvider publicKeyProviderAes = new AesCryptoServiceProvider();
                    //AesGcm gcm = new AesGcm(cert.GetPublicKey());
                    //gcm.Encrypt()
                    publicKeyProviderAes.Key = cert.GetRSAPrivateKey().ExportRSAPrivateKey();
                    var result2 = publicKeyProviderAes.DecryptCbc(encodedEncryptedMessage, publicKeyProviderAes.Key);
                    return result2;
                case EncryptionAlgorithm.AES256_CBC:
                    string oidAES256_CBC = "2.16.840.1.101.3.4.1.42";
                    return DecryptCBC(encodedEncryptedMessage, cert, col, oidAES256_CBC);
                default:
                    string oid = EncryptionAlgorithm.des_EDE3_CBC;
                    return DecryptCBC(encodedEncryptedMessage, cert, col, oid);
            }
        }

        private static byte[] DecryptCBC(byte[] encodedEncryptedMessage, X509Certificate2 cert, X509Certificate2Collection col, string oid)
        {
            ContentInfo contentInfo = new ContentInfo(encodedEncryptedMessage);
            EnvelopedCms envelopedCms = new EnvelopedCms(contentInfo,
                new AlgorithmIdentifier(new System.Security.Cryptography.Oid(oid)));
            CmsRecipient recipient = new CmsRecipient(SubjectIdentifierType.IssuerAndSerialNumber, cert);
            envelopedCms.Decode(encodedEncryptedMessage);
            envelopedCms.Decrypt(col);



            //EnvelopedCms envelopedCms = new EnvelopedCms(new ContentInfo(encodedEncryptedMessage),
            //                        new AlgorithmIdentifier(new System.Security.Cryptography.Oid(oid)));
            //envelopedCms.Decode(encodedEncryptedMessage);
            //envelopedCms.Decrypt(col);
            return envelopedCms.Encode();
        }
    }
}