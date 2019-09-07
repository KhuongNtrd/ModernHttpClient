using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Android.OS;
using Java.Net;
using Java.Security;
using Java.Util.Concurrent;
using Javax.Net.Ssl;
using Square.OkHttp3;
using Debug = System.Diagnostics.Debug;
using IOException = Java.IO.IOException;
using Object = Java.Lang.Object;
using OperationCanceledException = System.OperationCanceledException;

namespace ModernHttpClient
{
    public class NativeMessageHandler : HttpClientHandler
    {
        readonly Dictionary<string, string> _headerSeparators =
            new Dictionary<string, string>
            {
                {"User-Agent", " "}
            };

        readonly CacheControl _noCacheCacheControl = new CacheControl.Builder().NoCache().Build();

        readonly Dictionary<HttpRequestMessage, WeakReference> _registeredProgressCallbacks =
            new Dictionary<HttpRequestMessage, WeakReference>();

        readonly bool _throwOnCaptiveNetwork;
        OkHttpClient _client = new OkHttpClient();

        IKeyManager[] _keyManagers;

        public NativeMessageHandler(bool throwOnCaptiveNetwork, bool sslVerification, CustomSSLVerification customSSLVerification = null, NativeCookieHandler cookieHandler = null)
        {
            _throwOnCaptiveNetwork = throwOnCaptiveNetwork;

            var clientBuilder = _client.NewBuilder();

            var specsBuilder = new ConnectionSpec.Builder(ConnectionSpec.ModernTls)
                .TlsVersions(TlsVersion.Tls12);

            var specs = specsBuilder.Build();

            if (!sslVerification)
                clientBuilder.ConnectionSpecs(new List<ConnectionSpec> { specs, ConnectionSpec.Cleartext });
            else
                clientBuilder.ConnectionSpecs(new List<ConnectionSpec> { specs });

            clientBuilder.Protocols(new[] { Protocol.Http11 }); // Required to avoid stream was reset: PROTOCOL_ERROR 
            if (customSSLVerification != null)
            {
                clientBuilder.HostnameVerifier(new HostnameVerifier(customSSLVerification.Pins));

                var certificatePinnerBuilder = new CertificatePinner.Builder();

                // Add Certificate Pins
                foreach (var pin in customSSLVerification.Pins) certificatePinnerBuilder.Add(pin.Hostname, pin.PublicKeys);

                clientBuilder.CertificatePinner(certificatePinnerBuilder.Build());

                // Set client credentials
                SetClientCertificate(customSSLVerification.ClientCertificate);
            }

            // Set SslSocketFactory
            if (Build.VERSION.SdkInt < BuildVersionCodes.Lollipop)
            {
                // Support TLS1.2 on Android versions before Lollipop
                clientBuilder.SslSocketFactory(new TlsSslSocketFactory(_keyManagers), TlsSslSocketFactory.GetSystemDefaultTrustManager());
            }
            else
            {
                var sslContext = SSLContext.GetInstance("TLS");
                sslContext.Init(_keyManagers, null, null);
                clientBuilder.SslSocketFactory(sslContext.SocketFactory, TlsSslSocketFactory.GetSystemDefaultTrustManager());
            }

            if (cookieHandler != null) clientBuilder.CookieJar(cookieHandler);

            _client = clientBuilder.Build();
        }

        public bool DisableCaching { get; set; }

        public TimeSpan? Timeout { get; set; }

        public void RegisterForProgress(HttpRequestMessage request, ProgressDelegate callback)
        {
            lock (_registeredProgressCallbacks)
            {
                if (callback == null && _registeredProgressCallbacks.ContainsKey(request))
                {
                    _registeredProgressCallbacks.Remove(request);
                    return;
                }
            }

            lock (_registeredProgressCallbacks)
            {
                _registeredProgressCallbacks[request] = new WeakReference(callback);
            }
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var clientBuilder = _client.NewBuilder();

            if (Timeout != null)
            {
                var timeout = (long)Timeout.Value.TotalMilliseconds;
                clientBuilder.ConnectTimeout(timeout, TimeUnit.Milliseconds);
                clientBuilder.WriteTimeout(timeout, TimeUnit.Milliseconds);
                clientBuilder.ReadTimeout(timeout, TimeUnit.Milliseconds);
            }

            _client = clientBuilder.Build();

            var javaUri = request.RequestUri.GetComponents(UriComponents.AbsoluteUri, UriFormat.UriEscaped);
            var url = new URL(javaUri);

            var body = default(RequestBody);
            if (request.Content != null)
            {
                var bytes = await request.Content.ReadAsByteArrayAsync().ConfigureAwait(false);

                var contentType = "text/plain";
                if (request.Content.Headers.ContentType != null) contentType = string.Join(" ", request.Content.Headers.GetValues("Content-Type"));
                body = RequestBody.Create(MediaType.Parse(contentType), bytes);
            }

            var requestBuilder = new Request.Builder()
                .Method(request.Method.Method.ToUpperInvariant(), body)
                .Url(url);

            if (DisableCaching) requestBuilder.CacheControl(_noCacheCacheControl);

            var keyValuePairs = request.Headers
                .Union(request.Content != null ? request.Content.Headers : Enumerable.Empty<KeyValuePair<string, IEnumerable<string>>>());

            // Add Cookie Header if there's any cookie for the domain in the cookie jar
            var stringBuilder = new StringBuilder();

            if (_client.CookieJar() != null)
            {
                var jar = _client.CookieJar();
                var cookies = jar.LoadForRequest(HttpUrl.Get(url));
                foreach (var cookie in cookies) stringBuilder.Append(cookie.Name() + "=" + cookie.Value() + ";");
            }

            foreach (var kvp in keyValuePairs)
                if (kvp.Key == "Cookie")
                    foreach (var val in kvp.Value)
                        stringBuilder.Append(val + ";");
                else
                    requestBuilder.AddHeader(kvp.Key, string.Join(GetHeaderSeparator(kvp.Key), kvp.Value));

            if (stringBuilder.Length > 0) requestBuilder.AddHeader("Cookie", stringBuilder.ToString().TrimEnd(';'));

            cancellationToken.ThrowIfCancellationRequested();

            var rq = requestBuilder.Build();
            var call = _client.NewCall(rq);

            // NB: Even closing a socket must be done off the UI thread. Cray!
            cancellationToken.Register(() => Task.Run(() => call.Cancel()));

            Response resp;
            try
            {
                resp = await call.EnqueueAsync().ConfigureAwait(false);
                var newReq = resp.Request();
                var newUri = newReq?.Url().Uri();
                if (newUri != null)
                {
                    request.RequestUri = new Uri(newUri.ToString());
                    if (_throwOnCaptiveNetwork)
                        if (url.Host != newUri.Host)
                            throw new CaptiveNetworkException(new Uri(javaUri), new Uri(newUri.ToString()));
                }
            }
            catch (IOException ex)
            {
                if (ex.Message.ToLowerInvariant().Contains("canceled")) throw new OperationCanceledException();

                // Calling HttpClient methods should throw .Net Exception when fail #5
                throw new HttpRequestException(ex.Message, ex);
            }

            var respBody = resp.Body();

            cancellationToken.ThrowIfCancellationRequested();

            var ret = new HttpResponseMessage((HttpStatusCode)resp.Code());
            ret.RequestMessage = request;
            ret.ReasonPhrase = resp.Message();

            // ReasonPhrase is empty under HTTPS #8
            if (string.IsNullOrEmpty(ret.ReasonPhrase))
            {
                try
                {
                    ret.ReasonPhrase = ((ReasonPhrases)resp.Code()).ToString().Replace('_', ' ');
                }
#pragma warning disable 0168
                catch (Exception ex)
                {
                    ret.ReasonPhrase = "Unassigned";
                }
#pragma warning restore 0168
            }

            if (respBody != null)
            {
                var content = new ProgressStreamContent(respBody.ByteStream(), CancellationToken.None) { Progress = GetAndRemoveCallbackFromRegister(request) };
                ret.Content = content;
            }
            else
            {
                ret.Content = new ByteArrayContent(new byte[0]);
            }

            var respHeaders = resp.Headers();
            foreach (var k in respHeaders.Names())
            {
                ret.Headers.TryAddWithoutValidation(k, respHeaders.Get(k));
                ret.Content.Headers.TryAddWithoutValidation(k, respHeaders.Get(k));
            }

            return ret;
        }

        ProgressDelegate GetAndRemoveCallbackFromRegister(HttpRequestMessage request)
        {
            ProgressDelegate emptyDelegate = delegate { };

            lock (_registeredProgressCallbacks)
            {
                if (!_registeredProgressCallbacks.ContainsKey(request)) return emptyDelegate;

                var weakRef = _registeredProgressCallbacks[request];
                if (weakRef == null) return emptyDelegate;

                var callback = weakRef.Target as ProgressDelegate;
                if (callback == null) return emptyDelegate;

                _registeredProgressCallbacks.Remove(request);
                return callback;
            }
        }

        string GetHeaderSeparator(string name)
        {
            if (_headerSeparators.ContainsKey(name)) return _headerSeparators[name];

            return ",";
        }

        void SetClientCertificate(ClientCertificate certificate)
        {
            if (certificate == null) return;

            var bytes = Convert.FromBase64String(certificate.RawData);

            var stream = new MemoryStream(bytes);
            var keyStore = KeyStore.GetInstance("PKCS12");
            keyStore.Load(stream, certificate.Passphrase.ToCharArray());

            var kmf = KeyManagerFactory.GetInstance("X509");
            kmf.Init(keyStore, certificate.Passphrase.ToCharArray());

            _keyManagers = kmf.GetKeyManagers();
        }
    }

    public static class AwaitableOkHttp
    {
        public static Task<Response> EnqueueAsync(this ICall This)
        {
            var cb = new OkTaskCallback();
            This.Enqueue(cb);

            return cb.Task;
        }

        class OkTaskCallback : Object, ICallback
        {
            readonly TaskCompletionSource<Response> _tcs = new TaskCompletionSource<Response>();

            public Task<Response> Task => _tcs.Task;

            public void OnFailure(ICall p0, IOException p1)
            {
                // Kind of a hack, but the simplest way to find out that server cert. validation failed
                if (p1.Message.StartsWith("Hostname " + p0.Request().Url().Host() + " not verified", StringComparison.Ordinal))
                {
                    // SIGABRT after UnknownHostException #229
                    //tcs.TrySetException(new WebException(p1.Message));
                    //tcs.TrySetException(new WebException(p1.LocalizedMessage, WebExceptionStatus.TrustFailure));
                    var ex = new OperationCanceledException(HostnameVerifier.PinningFailureMessage, p1);
                    HostnameVerifier.PinningFailureMessage = null;
                    _tcs.TrySetException(ex);
                }
                else if (p1.Message.StartsWith("Certificate pinning failure", StringComparison.Ordinal))
                {
                    Debug.WriteLine(p1.Message);
                    _tcs.TrySetException(new OperationCanceledException(FailureMessages.PinMismatch, p1));
                }
                else
                {
                    _tcs.TrySetException(p1);
                }
            }

            public void OnResponse(ICall p0, Response p1)
            {
                _tcs.TrySetResult(p1);
            }
        }
    }

    internal class HostnameVerifier : Object, IHostnameVerifier
    {
        public static string PinningFailureMessage;

        readonly List<Pin> _pins;

        public HostnameVerifier(List<Pin> pins)
        {
            _pins = pins;
        }

        /// <summary>
        ///     Verifies the server certificate by calling into ServicePointManager.ServerCertificateValidationCallback or,
        ///     if the is no delegate attached to it by using the default hostname verifier.
        /// </summary>
        /// <returns><c>true</c>, if server certificate was verifyed, <c>false</c> otherwise.</returns>
        /// <param name="hostname"></param>
        /// <param name="session"></param>
        public bool Verify(string hostname, ISSLSession session)
        {
            var errors = SslPolicyErrors.None;

            // Convert java certificates to .NET certificates and build cert chain from root certificate
            /*var serverCertChain = session.GetPeerCertificateChain();
            var chain = new X509Chain();
            X509Certificate2 root = null;
            var errors = SslPolicyErrors.None;

            // Build certificate chain and check for errors
            if (serverCertChain == null || serverCertChain.Length == 0)
            {//no cert at all
                errors = SslPolicyErrors.RemoteCertificateNotAvailable;
                PinningFailureMessage = FailureMessages.NoCertAtAll;
                goto sslErrorVerify;
            }

            if (serverCertChain.Length == 1)
            {//no root?
                errors = SslPolicyErrors.RemoteCertificateChainErrors;
                PinningFailureMessage = FailureMessages.NoRoot;
                goto sslErrorVerify;
            }

            var netCerts = serverCertChain.Select(x => new X509Certificate2(x.GetEncoded())).ToArray();

            for (int i = 1; i < netCerts.Length; i++)
            {
                chain.ChainPolicy.ExtraStore.Add(netCerts[i]);
            }

            root = netCerts[0];

            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.UrlRetrievalTimeout = new TimeSpan(0, 1, 0);
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;

            if (!chain.Build(root))
            {
                errors = SslPolicyErrors.RemoteCertificateChainErrors;
                PinningFailureMessage = FailureMessages.ChainError;
                goto sslErrorVerify;
            }

            var subject = root.Subject;
            var subjectCn = cnRegex.Match(subject).Groups[1].Value;

            if (string.IsNullOrWhiteSpace(subjectCn) || !Utility.MatchHostnameToPattern(hostname, subjectCn))
            {
                errors = SslPolicyErrors.RemoteCertificateNameMismatch;
                PinningFailureMessage = FailureMessages.SubjectNameMismatch;
                goto sslErrorVerify;
            }*/

            if (_pins.FirstOrDefault(pin => MatchDomain(pin.Hostname, hostname)) == null)
            {
                errors = SslPolicyErrors.RemoteCertificateNameMismatch;
                PinningFailureMessage = FailureMessages.NoPinsProvided + " " + hostname;
            }

            //sslErrorVerify:
            return errors == SslPolicyErrors.None;
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