using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Net.AS2.Core
{
    public class As2CertificateVm
    {
        [JsonProperty("subject")]
        public string Subject { get; set; }

        [JsonProperty("issuer")]
        public string Issuer { get; set; }

        [JsonProperty("fingerPrint")]
        public string FingerPrint { get; set; }

        [JsonProperty("serialNumber")]
        public string SerialNumber { get; set; }

        [JsonProperty("version")]
        public int Version { get; set; }

        [JsonProperty("validFrom")]
        public DateTime ValidFrom { get; set; }

        [JsonProperty("validTo")]
        public DateTime ValidTo { get; set; }

        [JsonProperty("certificateContent")]

        public string CertificateContent { get; set; }

        [JsonProperty("key")]
        public string Key { get; set; }

        [JsonProperty("keyPassword")]
        public string KeyPassword { get; set; }

    }
}
