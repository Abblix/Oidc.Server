// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;
using RegistrationMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

public partial class ClientIdMetadataDocumentTests
{
    /// <summary>
    /// A request reading a token of a client resolved from its document finds that client once, for its authentication
    /// and for every step reading the token: the document no cache holds is fetched once per request.
    /// </summary>
    [Theory]
    [InlineData(TokenReader.Refresh)]
    [InlineData(TokenReader.Revocation)]
    [InlineData(TokenReader.Introspection)]
    public async Task AValidDocumentNoCacheHolds_IsFetchedOnceByARequestReadingItsToken(TokenReader reader)
    {
        var (host, client, discovery, tokens) = await IssueOfflineTokensAsync();
        await using var _ = host;
        var before = _origin.RequestsTo(ClientId);

        using var response = await ReadAsync(client, discovery, tokens, reader, asOwner: reader != TokenReader.Introspection);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(1, _origin.RequestsTo(ClientId) - before);
    }

    /// <summary>
    /// A token of a client whose document cannot be had for now, read for a request of another client, is not judged
    /// on a client the server could not find: the request is answered 503, as a failed authentication of such a client
    /// is.
    /// </summary>
    [Theory]
    [InlineData(TokenReader.Refresh)]
    [InlineData(TokenReader.Revocation)]
    [InlineData(TokenReader.Introspection)]
    public async Task ATokenOfAClientWhoseDocumentCannotBeHadForNow_IsAnswered503(TokenReader reader)
    {
        var (host, client, discovery, tokens) = await IssueOfflineTokensAsync();
        await using var _ = host;
        _origin.Answer(ClientId, () => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));

        using var response = await ReadAsync(client, discovery, tokens, reader, asOwner: false);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Empty(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// The tokens of an authorization code grant with offline access, issued to the public client of a document no cache
    /// holds.
    /// </summary>
    private async Task<(WebApplicationFactory<Program> Host, HttpClient Client, DiscoveryDocument Discovery, JsonObject Tokens)>
        IssueOfflineTokensAsync()
    {
        var document = PublicClientDocument();
        document[RegistrationMembers.GrantTypes] = new JsonArray(GrantTypes.AuthorizationCode, GrantTypes.RefreshToken);
        document[RegistrationMembers.OfflineAccess] = "allowed";
        _origin.Serve(ClientId, document.ToJsonString(), "no-store");

        var host = CreateHost(options =>
            options.NewClientOptions = options.NewClientOptions with { OfflineAccess = OfflineAccess.Allowed });
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        var (verifier, challenge) = GeneratePkcePair();
        var parameters = CodeFlowParameters(ClientId, challenge);
        parameters[AuthorizationRequest.Parameters.Scope] = $"{Scopes.OpenId} {Scopes.OfflineAccess}";
        var code = await AuthorizeAndExtractCodeAsync(client, discovery, parameters);
        var tokens = await ExchangeCodeForTokensAsync(client, discovery, CodeExchange(code, verifier));
        Assert.NotNull(tokens[TokenResponse.Parameters.RefreshToken]);

        return (host, client, discovery, tokens);
    }

    /// <summary>
    /// Reads a token of <paramref name="tokens"/> the way <paramref name="reader"/> names: as the client it was issued to,
    /// or as a client of the host's store.
    /// </summary>
    private static Task<HttpResponseMessage> ReadAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        JsonObject tokens,
        TokenReader reader,
        bool asOwner)
    {
        var refreshToken = tokens[TokenResponse.Parameters.RefreshToken]!.GetValue<string>();
        var accessToken = tokens[TokenResponse.Parameters.AccessToken]!.GetValue<string>();
        var caller = asOwner
            ? new Dictionary<string, string> { [ClientRequest.Parameters.ClientId] = ClientId }
            : new Dictionary<string, string>
            {
                [ClientRequest.Parameters.ClientId] = TestConstants.UnrestrictedClientId,
                [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
            };

        switch (reader)
        {
            case TokenReader.Refresh:
                caller[TokenRequest.Parameters.GrantType] = GrantTypes.RefreshToken;
                caller[TokenRequest.Parameters.RefreshToken] = refreshToken;
                return FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint, caller);

            case TokenReader.Revocation:
                caller[RevocationRequest.Parameters.Token] = refreshToken;
                return FormPostHelpers.PostFormAsync(client, discovery.RevocationEndpoint!, caller);

            case TokenReader.Introspection:
                caller[IntrospectionRequest.Parameters.Token] = accessToken;
                return FormPostHelpers.PostFormAsync(client, discovery.IntrospectionEndpoint!, caller);

            default:
                throw new ArgumentOutOfRangeException(nameof(reader), reader, null);
        }
    }

    public enum TokenReader
    {
        Refresh,
        Revocation,
        Introspection,
    }
}
