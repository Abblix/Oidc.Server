// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Endpoints.Authorization.RequestFetching;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientIdMetadataDocuments;

/// <summary>
/// The request object and back-channel logout fetches of a client resolved from its metadata document hold to the
/// special-purpose address registries as written (draft-ietf-oauth-client-id-metadata-document section 10.7): a name
/// answering with NAT64 of a public address is refused for such a client and reached for any other.
/// </summary>
public class SpecialPurposeFetchSitesTests
{
    private static readonly TenantDefinition Tenant = new() { Id = "tenant", Issuer = new Uri("https://issuer.example.com/") };

    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public async Task ARequestUriBehindNat64_IsFetchedOnlyForAClientNotResolvedFromADocument(bool fromDocument, bool fetched)
    {
        var requestUri = new Uri("https://client.example.com/request.jwt");
        var client = new ClientInfo("client") { RequestUris = [requestUri], ResolvedFromMetadataDocument = fromDocument };
        var origin = new Origin("eyJhbGciOiJub25lIn0.e30.");
        using var http = new HttpClient(Behind(origin));
        var fetcher = new RequestUriFetcher(
            NullLogger<RequestUriFetcher>.Instance,
            Mock.Of<IClientInfoProvider>(store => store.TryFindClientAsync(Tenant, client.ClientId) == Task.FromResult<ClientInfo?>(client)),
            new SecureHttpFetcher(NullLogger<SecureHttpFetcher>.Instance, http, Options.Create(new SecureHttpFetchOptions())));

        var result = await fetcher.FetchAsync(Tenant, new AuthorizationRequest { ClientId = client.ClientId, RequestUri = requestUri });

        Assert.Equal(fetched, result.TryGetSuccess(out _));
        Assert.Equal(fetched, origin.Reached);
    }

    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public async Task ALogoutUriBehindNat64_IsPostedOnlyForAClientNotResolvedFromADocument(bool fromDocument, bool posted)
    {
        var client = new ClientInfo("client")
        {
            BackChannelLogout = new BackChannelLogoutOptions(new Uri("https://client.example.com/logout")),
            ResolvedFromMetadataDocument = fromDocument,
        };
        var origin = new Origin(string.Empty);
        using var http = new HttpClient(Behind(origin));
        var sender = new BackChannelLogoutTokenSender(NullLogger<BackChannelLogoutTokenSender>.Instance, http);

        var sent = await Record.ExceptionAsync(() => sender.SendBackChannelLogoutAsync(
            client, new EncodedJsonWebToken(new JsonWebToken(), "logout.token.")));

        Assert.Equal(posted, sent is null);
        Assert.Equal(posted, origin.Reached);
    }

    /// <summary>
    /// The server's SSRF validation with every name answering NAT64 of 8.8.8.8, and <paramref name="origin"/> in place of
    /// the network behind it.
    /// </summary>
    private static SsrfValidatingHttpMessageHandler Behind(Origin origin)
    {
        var options = Options.Create(new SecureHttpFetchOptions());
        var guard = new SsrfValidatingHttpMessageHandler(
            options,
            new SecureUriValidator(options, NullLogger<SecureUriValidator>.Instance),
            (_, _) => Task.FromResult(new[] { IPAddress.Parse("64:ff9b::808:808") }));
        guard.InnerHandler!.Dispose();
        guard.InnerHandler = origin;
        return guard;
    }

    private sealed class Origin(string body) : HttpMessageHandler
    {
        public bool Reached { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Reached = true;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body) });
        }
    }
}
