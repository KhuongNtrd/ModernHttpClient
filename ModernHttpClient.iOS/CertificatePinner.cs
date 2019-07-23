using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
<<<<<<< HEAD
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
=======
using System.Text.RegularExpressions;
>>>>>>> update pin check

namespace ModernHttpClient
{
    public class CertificatePinner
    {
        private readonly Dictionary<string, string[]> Pins;

        public CertificatePinner()
        {
            Pins = new Dictionary<string, string[]>();
        }

        public bool HasPins(string hostname)
        {
<<<<<<< HEAD
            foreach(var pin in Pins)
            {
                if (Utility.MatchHostnameToPattern(hostname, pin.Key))
                {
                    return true;
                }
            }

            return false;
=======
            return Pins.Keys.Any(x => MatchDomain(x, hostname));
>>>>>>> update pin check
        }

        public void AddPins(string hostname, string[] pins)
        {
            Utility.VerifyPins(pins);
            Pins[hostname] = pins;
        }

        public bool Check(string hostname, List<X509Certificate2> peerCertificates)
        {
            if (!HasPins(hostname))
            {
                Debug.WriteLine($"No certificate pin found for {hostname}");
                return false;
            }

            hostname = Pins.FirstOrDefault(p => Utility.MatchHostnameToPattern(hostname, p.Key)).Key;

            // Get pins
            string[] pins = Pins.First(x => MatchDomain(x.Key, hostname)).Value;

            // Skip pinning with empty array
            if (pins == null || pins.Length == 0)
            {
                return true;
            }

            foreach(var certificate in peerCertificates)
            {
                // Compute sha256
                var sha256Fingerprint = SpkiFingerprint.ComputeSHA256(certificate.RawData);

                // Check pins for sha256
                if (Array.IndexOf(pins, sha256Fingerprint) > -1)
                {
                    Debug.WriteLine($"Certificate pin {sha256Fingerprint} is ok for {hostname}");
                    return true;
                }

                // Compute sha1
                var sha1Fingerprint = SpkiFingerprint.ComputeSHA1(certificate.RawData);

                // Check pins for sha1
                if (Array.IndexOf(pins, sha1Fingerprint) > -1)
                {
                    Debug.WriteLine($"Certificate pin {sha1Fingerprint} is ok for {hostname}");
                    return true;
                }

                // Compute md5
                var md5Fingerprint = SpkiFingerprint.ComputeMD5(certificate.RawData);

                // Check pins for md5
                if (Array.IndexOf(pins, md5Fingerprint) > -1)
                {
                    Debug.WriteLine($"Certificate pin {md5Fingerprint} is ok for {hostname}");
                    return true;
                }
            }

            Debug.WriteLine($"Certificate pinning failure! Peer certificate chain for {hostname}: {string.Join("|", pins)}");
            return false;
        }

        private bool MatchDomain(string hostname1, string hostname2)
        {
            if (hostname1.ToLower().Equals(hostname2.ToLower()))
                return true;

            if (hostname1.StartsWith("*", StringComparison.Ordinal))
            {
                var regex = "[\\w\\d]\\." + hostname1.Substring(1);

                return Regex.IsMatch(hostname2, regex);
            }

            return false;
        }
    }
}
