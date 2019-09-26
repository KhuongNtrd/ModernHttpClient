using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text.RegularExpressions;

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
            return Pins.Keys.Any(x => MatchDomain(x, hostname));
        }

        public void AddPins(string hostname, string[] pins)
        {
            Pins[hostname] = pins;
        }

        public bool Check(string hostname, byte[] certificate)
        {
            if (!HasPins(hostname))
            {
                Debug.WriteLine($"No certificate pin found for {hostname}");
                return false;
            }

            // Get pins
            string[] pins = Pins.First(x => MatchDomain(x.Key, hostname)).Value;

            // Compute spki fingerprint
            var spkiFingerprint = SpkiFingerprint.Compute(certificate);

            // Check pin
            var match = Array.IndexOf(pins, spkiFingerprint) > -1;

            if (match)
            {
                Debug.WriteLine($"Certificate pin is ok for {hostname}");
            }
            else
            {
                Debug.WriteLine($"Certificate pinning failure! Peer certificate chain: {spkiFingerprint}, Pinned certificates for {hostname}: {string.Join("|", pins)}");
            }

            return match;
        }

        private bool MatchDomain(string hostname1, string hostname2)
        {
            if (hostname1.ToLower().Equals(hostname2.ToLower()))
                return true;

            if (hostname1.StartsWith("*", StringComparison.Ordinal))
            {
                var regex = "[\\w\\d]*?" + hostname1.Substring(1);

                return Regex.IsMatch(hostname2, regex);
            }

            return false;
        }
    }
}
