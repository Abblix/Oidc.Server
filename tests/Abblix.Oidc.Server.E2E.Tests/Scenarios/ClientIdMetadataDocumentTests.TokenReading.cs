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
using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
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
    [InlineData(TokenReader.Refresh, Caller.Owner)]
    [InlineData(TokenReader.Revocation, Caller.Owner)]
    [InlineData(TokenReader.Introspection, Caller.Introspector)]
    public async Task AValidDocumentNoCacheHolds_IsFetchedOnceByARequestReadingItsToken(TokenReader reader, Caller caller)
    {
        var (host, client, discovery, tokens) = await IssueOfflineTokensAsync();
        await using var _ = host;
        var before = _origin.RequestsTo(ClientId);

        using var response = await ReadAsync(client, discovery, tokens, reader, caller);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(1, _origin.RequestsTo(ClientId) - before);
    }

    /// <summary>
    /// A token of a client whose document cannot be had for now, introspected by a client authorized to introspect any
    /// token, is not judged on a client the server could not find: the request is answered 503, as a failed
    /// authentication of such a client is, rather than reporting the token inactive.
    /// </summary>
    [Fact]
    public async Task ATokenOfAClientWhoseDocumentCannotBeHadForNow_IsAnswered503()
    {
        var (host, client, discovery, tokens) = await IssueOfflineTokensAsync();
        await using var _ = host;
        _origin.Answer(ClientId, () => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));

        using var response = await ReadAsync(client, discovery, tokens, TokenReader.Introspection, Caller.Introspector);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Empty(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// A token that is not the caller's is answered as it is without the outage, since nothing its client's document
    /// would say changes the answer: a refresh is invalid_grant (RFC 6749 section 6), revocation revokes nothing with
    /// 200 (RFC 7009 section 2.1), and introspection by a client not authorized to introspect another's token reports it
    /// inactive. None tells the caller anything about a token that is not its own, its client's outage included.
    /// </summary>
    [Theory]
    [InlineData(TokenReader.Refresh, Caller.Introspector)]
    [InlineData(TokenReader.Revocation, Caller.Introspector)]
    [InlineData(TokenReader.Introspection, Caller.Stranger)]
    public async Task ATokenNotTheCallers_IsAnsweredAsWithoutTheOutageOfItsClientsDocument(TokenReader reader, Caller caller)
    {
        var (host, client, discovery, tokens) = await IssueOfflineTokensAsync();
        await using var _ = host;
        _origin.Answer(ClientId, () => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));

        using var response = await ReadAsync(client, discovery, tokens, reader, caller);

        switch (reader)
        {
            case TokenReader.Refresh:
                Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
                Assert.Equal(ErrorCodes.InvalidGrant, await ErrorResponseReader.ErrorCodeOf(response));
                break;

            case TokenReader.Revocation:
                Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                break;

            case TokenReader.Introspection:
                Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
                Assert.False(body[IntrospectionSuccess.Parameters.Active]!.GetValue<bool>());
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(reader), reader, null);
        }
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
    /// Reads a token of <paramref name="tokens"/> the way <paramref name="reader"/> names, as <paramref name="who"/>.
    /// </summary>
    private static Task<HttpResponseMessage> ReadAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        JsonObject tokens,
        TokenReader reader,
        Caller who)
    {
        var refreshToken = tokens[TokenResponse.Parameters.RefreshToken]!.GetValue<string>();
        var accessToken = tokens[TokenResponse.Parameters.AccessToken]!.GetValue<string>();
        var caller = who switch
        {
            Caller.Owner => new Dictionary<string, string> { [ClientRequest.Parameters.ClientId] = ClientId },
            Caller.Introspector => StoreClient(TestConstants.UnrestrictedClientId),
            Caller.Stranger => StoreClient(TestConstants.ConfidentialClientId),
            _ => throw new ArgumentOutOfRangeException(nameof(who), who, null),
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

    /// <summary>
    /// A client of the host's store, authenticating with the secret every confidential test client carries.
    /// </summary>
    private static Dictionary<string, string> StoreClient(string clientId) => new()
    {
        [ClientRequest.Parameters.ClientId] = clientId,
        [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
    };

    public enum TokenReader
    {
        Refresh,
        Revocation,
        Introspection,
    }

    /// <summary>
    /// Who reads the token: the client it was issued to, a store client authorized to introspect any token, or a store
    /// client that is not.
    /// </summary>
    public enum Caller
    {
        Owner,
        Introspector,
        Stranger,
    }
}
