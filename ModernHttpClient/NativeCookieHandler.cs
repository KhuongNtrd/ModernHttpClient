﻿using System;
using System.Collections.Generic;
using System.Net;

namespace ModernHttpClient
{
    public class NativeCookieHandler
    {
        const string wrongVersion = "You're referencing the Portable version in your App - you need to reference the platform (iOS/Android) version";

        public void SetCookies(IEnumerable<Cookie> cookies)
        {
            throw new Exception(wrongVersion);
        }

        public List<Cookie> Cookies
        {
            get { throw new Exception(wrongVersion); }
        }
    }
}
