// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Net.Sockets;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

public partial class ClientIdMetadataDocumentTests
{
    /// <summary>
    /// Section 6.1: "At the token endpoint or pushed authorization request endpoint, the authorization server MUST
    /// return an invalid_client error, or for a transient failure, an HTTP 503 status code". A document whose server
    /// answers 503 or cannot be reached is a transient failure, whatever credential the request presents for the
    /// client the document would describe. The revocation endpoint answers it alike, as RFC 7009 section 2.2.1 has a
    /// client "assume the token still exists and may retry", and so does the introspection endpoint.
    /// </summary>
    [Theory]
    [InlineData(Endpoint.Token, Credential.None, Outage.ServiceUnavailable)]
    [InlineData(Endpoint.Token, Credential.None, Outage.Unreachable)]
    [InlineData(Endpoint.Token, Credential.PrivateKeyAssertion, Outage.ServiceUnavailable)]
    [InlineData(Endpoint.Token, Credential.SecretAssertion, Outage.ServiceUnavailable)]
    [InlineData(Endpoint.Token, Credential.Certificate, Outage.ServiceUnavailable)]
    [InlineData(Endpoint.Pushed, Credential.None, Outage.ServiceUnavailable)]
    [InlineData(Endpoint.Pushed, Credential.None, Outage.Unreachable)]
    [InlineData(Endpoint.Pushed, Credential.PrivateKeyAssertion, Outage.ServiceUnavailable)]
    [InlineData(Endpoint.Pushed, Credential.SecretAssertion, Outage.ServiceUnavailable)]
    [InlineData(Endpoint.Pushed, Credential.Certificate, Outage.ServiceUnavailable)]
    [InlineData(Endpoint.Revocation, Credential.None, Outage.ServiceUnavailable)]
    [InlineData(Endpoint.Revocation, Credential.PrivateKeyAssertion, Outage.Unreachable)]
    [InlineData(Endpoint.Introspection, Credential.PrivateKeyAssertion, Outage.ServiceUnavailable)]
    [InlineData(Endpoint.Introspection, Credential.SecretAssertion, Outage.Unreachable)]
    public async Task ADocumentNotToBeHadForNow_IsAnswered503(Endpoint endpoint, Credential credential, Outage outage)
    {
        switch (outage)
        {
            case Outage.ServiceUnavailable:
                _origin.Answer(ClientId, () => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
                break;

            case Outage.Unreachable:
                _origin.Unreachable(ClientId);
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(outage), outage, null);
        }

        var (status, body) = await SendAuthenticatedAsync(endpoint, credential);

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, status);
        Assert.Empty(body);
    }

    /// <summary>
    /// The other half of section 6.1 at the same endpoints: a document that was had and refused is a terminal failure,
    /// answered invalid_client.
    /// </summary>
    [Theory]
    [InlineData(Endpoint.Token, Credential.None)]
    [InlineData(Endpoint.Token, Credential.PrivateKeyAssertion)]
    [InlineData(Endpoint.Pushed, Credential.None)]
    [InlineData(Endpoint.Pushed, Credential.PrivateKeyAssertion)]
    public async Task ARefusedDocument_IsAnInvalidClient_NotA503(Endpoint endpoint, Credential credential)
    {
        Arrange(Unavailable.AnotherClientId);

        var (status, body) = await SendAuthenticatedAsync(endpoint, credential);

        // OAuth 2.1 section 3.2.4: a client authenticating without HTTP Basic, and not registered for it, is owed no
        // challenge, so the endpoint answers invalid_client with its own status
        Assert.Equal(StatusCodes.Status400BadRequest, status);
        Assert.Contains(ErrorCodes.InvalidClient, body);
    }

    /// <summary>
    /// A name the resolver cannot answer for now (SocketError.TryAgain) is a network error, the transient failure of
    /// section 6.1, though the server's SSRF validation refuses the send it cannot judge: a request is answered 503
    /// without a valid copy of the document, and with one past its lifetime the copy serves it, as section 6.1 has the
    /// server "SHOULD NOT discard previously cached valid client metadata on transient failures".
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ADocumentWhoseNameCannotBeResolvedForNow_IsServedFromItsCopy_Or503(bool held)
    {
        _origin.Serve(ClientId, PublicClientDocument().ToJsonString());
        var resolverDown = !held;
        var resolutions = 0;
        await using var host = CreateHost(
            // A copy is fresh for a moment, then fetched again by the next request
            options => options.ClientIdMetadataDocuments = options.ClientIdMetadataDocuments with { MinimumCacheDuration = CopyLifetime },
            configureServices: services => services
            .PostConfigure<HttpClientFactoryOptions>(ClientIdMetadataDocumentTransport.HttpClientName, factory =>
                factory.HttpMessageHandlerBuilderActions.Add(builder =>
                {
                    // The server's own SSRF validation in front of the client's server, with a resolver the row turns off
                    var guard = new SsrfValidatingHttpMessageHandler(
                        builder.Services.GetRequiredService<IOptions<SecureHttpFetchOptions>>(),
                        builder.Services.GetRequiredService<ISecureUriValidator>(),
                        (_, _) =>
                        {
                            Interlocked.Increment(ref resolutions);
                            return resolverDown
                                ? throw new SocketException((int)SocketError.TryAgain)
                                : Task.FromResult(new[] { IPAddress.Parse("2001:4860:4860::8888") });
                        });
                    guard.InnerHandler!.Dispose();
                    guard.InnerHandler = _origin;
                    builder.PrimaryHandler = guard;
                })));
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        if (held)
        {
            using var first = await SendAsync(client, discovery, Arrival.Pushed);
            Assert.Equal(HttpStatusCode.Created, first.StatusCode);
            resolverDown = true;
            await Task.Delay(CopyLifetime * 2, TestContext.Current.CancellationToken);
        }

        using var response = await SendAsync(client, discovery, Arrival.Pushed);

        Assert.Equal(held ? HttpStatusCode.Created : HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal(held ? 2 : 1, resolutions);
    }

    private static readonly TimeSpan CopyLifetime = TimeSpan.FromMilliseconds(300);

    /// <summary>
    /// Sends a request for <see cref="ClientId"/> to <paramref name="endpoint"/>, authenticated the way
    /// <paramref name="credential"/> names, and returns the status and the body it is answered with.
    /// </summary>
    private async Task<(int Status, string Body)> SendAuthenticatedAsync(Endpoint endpoint, Credential credential)
    {
        await using var host = CreateHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        var (uri, form) = endpoint switch
        {
            Endpoint.Token => (discovery.TokenEndpoint, CodeExchange("code", GeneratePkcePair().Verifier)),
            Endpoint.Pushed => (discovery.PushedAuthorizationRequestEndpoint!,
                CodeFlowParameters(ClientId, GeneratePkcePair().Challenge)),
            Endpoint.Revocation => (discovery.RevocationEndpoint!, new Dictionary<string, string>
            {
                [RevocationRequest.Parameters.Token] = "token",
                [ClientRequest.Parameters.ClientId] = ClientId,
            }),
            Endpoint.Introspection => (discovery.IntrospectionEndpoint!, new Dictionary<string, string>
            {
                [IntrospectionRequest.Parameters.Token] = "token",
                [ClientRequest.Parameters.ClientId] = ClientId,
            }),
            _ => throw new ArgumentOutOfRangeException(nameof(endpoint), endpoint, null),
        };

        switch (credential)
        {
            case Credential.None:
            case Credential.Certificate:
                break;

            case Credential.PrivateKeyAssertion:
                await AddAssertionAsync(
                    form, discovery, JsonWebKeyFactory.CreateEllipticCurve(EllipticCurveTypes.P256, SigningAlgorithms.ES256));
                break;

            case Credential.SecretAssertion:
                await AddAssertionAsync(form, discovery, JsonWebKeyFactory.CreateHmac(SigningAlgorithms.HS256));
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(credential), credential, null);
        }

        if (credential == Credential.Certificate)
            return await PostWithCertificateAsync(host, uri, form);

        using var response = await FormPostHelpers.PostFormAsync(client, uri, form);
        return ((int)response.StatusCode, await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    private static async Task AddAssertionAsync(Dictionary<string, string> form, DiscoveryDocument discovery, JsonWebKey key)
    {
        form[ClientRequest.Parameters.ClientAssertionType] = ClientAssertionTypes.JwtBearer;
        form[ClientRequest.Parameters.ClientAssertion] =
            await ClientSecretJwtAssertion.IssueWithKeyAsync(ClientId, key, discovery.Issuer.OriginalString);
    }

    public enum Endpoint
    {
        Token,
        Pushed,
        Revocation,
        Introspection,
    }

    public enum Credential
    {
        None,
        PrivateKeyAssertion,
        SecretAssertion,
        Certificate,
    }

    public enum Outage
    {
        ServiceUnavailable,
        Unreachable,
    }
}
