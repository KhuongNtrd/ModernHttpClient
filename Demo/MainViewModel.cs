﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Net.Http;
using System.Threading.Tasks;
using ModernHttpClient;

namespace Demo
{
    public class MainViewModel
    {
        readonly HttpClient client = new HttpClient(new NativeMessageHandler(false, new TLSConfig()
        {
            Pins = new List<Pin>()
            {
                new Pin()
                {
                    Hostname = "*.co.in",
                    PublicKeys = new []
                    {
                        "sha256/MCBrX+0kgfNc/qacknAJ5nojbFIx7kBSJSmXKjJviIg=",
                        "sha256/YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=",
                        "sha256/Vjs8r4z+80wjNcr1YKepWQboSIRi63WsWXhIMN+eWys="
                    }
                }
            },
            DangerousAcceptAnyServerCertificateValidator = false,
            DangerousAllowInsecureHTTPLoads = true
        })
        {
            DisableCaching = true,
            Timeout = new TimeSpan(0, 0, 9)
        });

        public async Task Get()
        {
            var response = await client.GetAsync(new Uri("http://gorest.co.in/public-api/users?format=json&access-token=ZsjrVYhueqIMDxIUtMVxFJpecrfqiL3kLY37")); //https://self-signed.badssl.com

            Debug.WriteLine(response.Content);
        }
    }
}