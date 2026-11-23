// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Buffers.Text;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

public partial class ClientIdMetadataDocumentTests
{
    /// <summary>
    /// One request names the client at several steps - the per-client pushed request rule, the request object or
    /// request_uri it arrives with, the client validation, the client authentication of a pushed request - and a refused
    /// document is fetched once for all of them. Section 6.2 has the server "MUST NOT cache error responses" and "MUST
    /// NOT cache documents which are invalid", which a refusal held by the request that judged it does not do, and
    /// "MAY implement rate limiting or other measures to avoid repeatedly fetching".
    /// </summary>
    [Theory]
    [InlineData(Arrival.Query, Unavailable.NotFound)]
    [InlineData(Arrival.Query, Unavailable.AnotherClientId)]
    [InlineData(Arrival.Query, Unavailable.SharedSecret)]
    [InlineData(Arrival.RequestObject, Unavailable.NotFound)]
    [InlineData(Arrival.RequestUri, Unavailable.NotFound)]
    [InlineData(Arrival.Pushed, Unavailable.NotFound)]
    [InlineData(Arrival.Pushed, Unavailable.AnotherClientId)]
    public async Task ARefusedDocument_IsFetchedOncePerRequest(Arrival arrival, Unavailable why)
    {
        Arrange(why);
        await using var host = CreateHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        using var response = await SendAsync(client, discovery, arrival);

        Assert.False(response.IsSuccessStatusCode);
        Assert.Equal(1, _origin.RequestsTo(ClientId));
    }

    /// <summary>
    /// The refusal dies with the request that judged it: section 6.2 has the server "MUST NOT cache error responses",
    /// so the next request asks the client's server again.
    /// </summary>
    [Theory]
    [InlineData(Unavailable.NotFound)]
    [InlineData(Unavailable.AnotherClientId)]
    public async Task ARefusedDocument_IsFetchedAgainByTheNextRequest(Unavailable why)
    {
        Arrange(why);
        await using var host = CreateHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        using (await SendAsync(client, discovery, Arrival.Query))
            Assert.Equal(1, _origin.RequestsTo(ClientId));

        using (await SendAsync(client, discovery, Arrival.Query))
            Assert.Equal(2, _origin.RequestsTo(ClientId));
    }

    /// <summary>
    /// A valid document its server marks "no-store" is held by no cache, so the server asks for it at each lookup
    /// (section 6.2 has it "respect HTTP cache headers"); one request still asks once, up to the response JWT it is
    /// answered with (JARM section 2.1), and the next request asks again.
    /// </summary>
    [Fact]
    public async Task AValidDocumentNoCacheHolds_IsFetchedOncePerRequest_UpToItsResponseJwt()
    {
        _origin.Serve(ClientId, PublicClientDocument().ToJsonString(), "no-store");
        await using var host = CreateHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        for (var request = 1; request <= 2; request++)
        {
            var parameters = CodeFlowParameters(ClientId, GeneratePkcePair().Challenge);
            parameters[AuthorizationRequest.Parameters.Prompt] = Prompts.None;
            parameters[AuthorizationRequest.Parameters.ResponseMode] = ResponseModes.QueryJwt;

            using var response = await client.GetAsync(
                QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, parameters),
                TestContext.Current.CancellationToken);

            Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
            Assert.NotNull(System.Web.HttpUtility.ParseQueryString(response.Headers.Location!.Query)[ResponseParameters.Response]);
            Assert.Equal(request, _origin.RequestsTo(ClientId));
        }
    }

    /// <summary>
    /// A pushed request authenticated with a private_key_jwt assertion is offered to every assertion method, and a
    /// refused document is still fetched once: client_secret_jwt refuses an assertion no client secret signs before
    /// it looks the issuer up.
    /// </summary>
    [Fact]
    public async Task ARefusedDocument_IsFetchedOnceByAPushedRequestWithAPrivateKeyAssertion()
    {
        Arrange(Unavailable.NotFound);
        await using var host = CreateHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        var key = JsonWebKeyFactory.CreateEllipticCurve(EllipticCurveTypes.P256, SigningAlgorithms.ES256);
        var parameters = CodeFlowParameters(ClientId, GeneratePkcePair().Challenge);
        parameters[ClientRequest.Parameters.ClientAssertionType] = ClientAssertionTypes.JwtBearer;
        parameters[ClientRequest.Parameters.ClientAssertion] =
            await ClientSecretJwtAssertion.IssueWithKeyAsync(ClientId, key, discovery.Issuer.OriginalString);

        using var response = await FormPostHelpers.PostFormAsync(
            client, discovery.PushedAuthorizationRequestEndpoint!, parameters);

        Assert.False(response.IsSuccessStatusCode);
        Assert.Equal(1, _origin.RequestsTo(ClientId));
    }

    /// <summary>
    /// A pushed request is judged on the client its authentication found, so a valid document no cache holds is
    /// fetched once by the push, client authentication included.
    /// </summary>
    [Fact]
    public async Task AValidDocumentNoCacheHolds_IsFetchedOnceByAPushedRequest()
    {
        _origin.Serve(ClientId, PublicClientDocument().ToJsonString(), "no-store");
        await using var host = CreateHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        using var response = await SendAsync(client, discovery, Arrival.Pushed);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal(1, _origin.RequestsTo(ClientId));
    }

    /// <summary>
    /// The mirror of <see cref="ARefusedDocument_IsFetchedOnceByAPushedRequestWithAPrivateKeyAssertion"/>: an assertion
    /// signed with a shared secret is refused by private_key_jwt before it looks the issuer up, so client_secret_jwt
    /// alone fetches the document.
    /// </summary>
    [Fact]
    public async Task ARefusedDocument_IsFetchedOnceByAPushedRequestWithASecretAssertion()
    {
        Arrange(Unavailable.NotFound);
        await using var host = CreateHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        var key = JsonWebKeyFactory.CreateHmac(SigningAlgorithms.HS256);
        var parameters = CodeFlowParameters(ClientId, GeneratePkcePair().Challenge);
        parameters[ClientRequest.Parameters.ClientAssertionType] = ClientAssertionTypes.JwtBearer;
        parameters[ClientRequest.Parameters.ClientAssertion] =
            await ClientSecretJwtAssertion.IssueWithKeyAsync(ClientId, key, discovery.Issuer.OriginalString);

        using var response = await FormPostHelpers.PostFormAsync(
            client, discovery.PushedAuthorizationRequestEndpoint!, parameters);

        Assert.False(response.IsSuccessStatusCode);
        Assert.Equal(1, _origin.RequestsTo(ClientId));
    }

    /// <summary>
    /// A client certificate on the connection offers the push to the mutual TLS methods too, and each of them finds
    /// the client the request names: the document is still fetched once, whether its client is refused or valid.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ADocument_IsFetchedOnceByAPushedRequestOverAConnectionWithACertificate(bool valid)
    {
        if (valid)
            _origin.Serve(ClientId, PublicClientDocument().ToJsonString(), "no-store");
        else
            Arrange(Unavailable.NotFound);

        await using var host = CreateHost();
        var discovery = await FetchDiscoveryAsync(CreateClientFor(host));

        var key = JsonWebKeyFactory.CreateEllipticCurve(EllipticCurveTypes.P256, SigningAlgorithms.ES256);
        var parameters = CodeFlowParameters(ClientId, GeneratePkcePair().Challenge);
        if (!valid)
        {
            parameters[ClientRequest.Parameters.ClientAssertionType] = ClientAssertionTypes.JwtBearer;
            parameters[ClientRequest.Parameters.ClientAssertion] =
                await ClientSecretJwtAssertion.IssueWithKeyAsync(ClientId, key, discovery.Issuer.OriginalString);
        }

        var status = await PostWithCertificateAsync(host, discovery.PushedAuthorizationRequestEndpoint!, parameters);

        Assert.Equal(valid, status == StatusCodes.Status201Created);
        Assert.Equal(1, _origin.RequestsTo(ClientId));
    }

    /// <summary>
    /// Posts <paramref name="form"/> over a connection carrying a fresh self-signed TLS client certificate, which an
    /// HTTP client of the test server cannot present, and returns the status it is answered with.
    /// </summary>
    private static async Task<int> PostWithCertificateAsync(
        WebApplicationFactory<Program> host, Uri endpoint, Dictionary<string, string> form)
    {
        using var key = RSA.Create(2048);
        using var certificate = new CertificateRequest("CN=client", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(TimeProvider.System.GetUtcNow().AddDays(-1), TimeProvider.System.GetUtcNow().AddDays(1));
        using var content = new FormUrlEncodedContent(form);
        var body = await content.ReadAsByteArrayAsync(TestContext.Current.CancellationToken);

        var context = await host.Server.SendAsync(
            http =>
            {
                http.Connection.ClientCertificate = certificate;
                http.Request.Method = HttpMethods.Post;
                http.Request.Scheme = endpoint.Scheme;
                http.Request.Host = new HostString(endpoint.Authority);
                http.Request.Path = endpoint.AbsolutePath;
                http.Request.ContentType = content.Headers.ContentType!.ToString();
                http.Request.Body = new MemoryStream(body);
            },
            TestContext.Current.CancellationToken);

        return context.Response.StatusCode;
    }

    /// <summary>
    /// A document that cannot be had for now, with no valid copy held, is asked for once by the request that needed it
    /// and again by the next one: section 6.2 has the server "MUST NOT cache error responses". The request is refused
    /// without a redirect (section 6.1).
    /// </summary>
    [Fact]
    public async Task ADocumentUnavailableForNow_IsFetchedOncePerRequest()
    {
        _origin.Answer(ClientId, () => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        await using var host = CreateHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        for (var request = 1; request <= 2; request++)
        {
            using var response = await SendAsync(client, discovery, Arrival.Query);

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Null(response.Headers.Location);
            Assert.Equal(ErrorCodes.InvalidClient, await ErrorResponseReader.ErrorCodeOf(response));
            Assert.Equal(request, _origin.RequestsTo(ClientId));
        }
    }

    /// <summary>
    /// Sends one authorization request for <paramref name="clientId"/> the way <paramref name="arrival"/> names.
    /// </summary>
    private static Task<HttpResponseMessage> SendAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        Arrival arrival,
        string clientId = ClientId)
    {
        var parameters = CodeFlowParameters(clientId, GeneratePkcePair().Challenge);
        switch (arrival)
        {
            case Arrival.Query:
                return client.GetAsync(
                    QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, parameters),
                    TestContext.Current.CancellationToken);

            case Arrival.RequestObject:
                return client.GetAsync(
                    QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, new Dictionary<string, string>
                    {
                        [AuthorizationRequest.Parameters.ClientId] = clientId,
                        [AuthorizationRequest.Parameters.Request] = Unsecured(parameters),
                    }),
                    TestContext.Current.CancellationToken);

            case Arrival.RequestUri:
                return client.GetAsync(
                    QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, new Dictionary<string, string>
                    {
                        [AuthorizationRequest.Parameters.ClientId] = clientId,
                        [AuthorizationRequest.Parameters.RequestUri] = "https://client.example.com/oauth/request.jwt",
                    }),
                    TestContext.Current.CancellationToken);

            case Arrival.Pushed:
                return FormPostHelpers.PostFormAsync(client, discovery.PushedAuthorizationRequestEndpoint!, parameters);

            default:
                throw new ArgumentOutOfRangeException(nameof(arrival), arrival, null);
        }
    }

    /// <summary>
    /// An Unsecured JWS (RFC 7515 appendix A.5) carrying <paramref name="parameters"/> as its claims.
    /// </summary>
    private static string Unsecured(Dictionary<string, string> parameters)
    {
        var claims = new JsonObject();
        foreach (var (name, value) in parameters)
            claims[name] = value;

        var header = new JsonObject { [JwtClaimTypes.Algorithm] = SigningAlgorithms.None };
        return string.Join(
            '.',
            Base64Url.EncodeToString(Encoding.UTF8.GetBytes(header.ToJsonString())),
            Base64Url.EncodeToString(Encoding.UTF8.GetBytes(claims.ToJsonString())),
            string.Empty);
    }

    public enum Arrival
    {
        Query,
        RequestObject,
        RequestUri,
        Pushed,
    }
}
