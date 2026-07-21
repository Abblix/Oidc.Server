// Abblix OIDC Client Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Client.Features.Discovery;

namespace Abblix.Oidc.Client.Features.UserInfo;

/// <summary>
/// Asks the provider's UserInfo endpoint what it will say about the user an access token was issued for.
/// </summary>
/// <param name="metadataProvider">Supplies the endpoint address the provider published.</param>
/// <param name="httpClientFactory">Builds the client this service calls the endpoint with.</param>
public sealed class UserInfoService(
    IProviderMetadataProvider metadataProvider,
    IHttpClientFactory httpClientFactory) : IUserInfoService
{
    /// <summary>
    /// The name of the <see cref="HttpClient"/> this service resolves from <see cref="IHttpClientFactory"/>.
    /// </summary>
    /// <remarks>
    /// Named for the same reason the token service's is: a paid layer hangs its handler chain on this exact
    /// traffic, and the UserInfo endpoint is one a sender-constrained token has to be presented to
    /// correctly rather than merely presented.
    /// </remarks>
    public const string HttpClientName = "Abblix.Oidc.Client.UserInfo";

    /// <inheritdoc />
    public async Task<JsonObject> GetAsync(
        string accessToken,
        string expectedSubject,
        CancellationToken cancellationToken = default)
    {
        var metadata = await metadataProvider.GetMetadataAsync(cancellationToken);

        if (metadata.UserInfoEndpoint is not { } endpoint)
        {
            throw new UserInfoException(
                $"The OpenID Provider '{metadata.Issuer}' publishes no UserInfo endpoint, so there is "
                + "nowhere to ask.");
        }

        var claims = await ReadClaimsAsync(endpoint, accessToken, cancellationToken);

        RequireSameSubject(claims, expectedSubject, metadata.Issuer);

        return claims;
    }

    /// <summary>
    /// Calls the endpoint and reads the claims out of what it returned.
    /// </summary>
    /// <remarks>
    /// A GET carrying the token in the Authorization header, which section 5.3.1 permits ("Authorization
    /// Servers MUST support the use of the HTTP GET and POST methods") and RFC 6750 section 2.1 makes the
    /// form to prefer - the alternatives put the token in a query string, where it reaches logs and
    /// referrers.
    /// </remarks>
    private async Task<JsonObject> ReadClaimsAsync(
        string endpoint,
        string accessToken,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue(TokenTypes.Bearer, accessToken);

        var httpClient = httpClientFactory.CreateClient(HttpClientName);

        HttpResponseMessage response;
        try
        {
            response = await httpClient.SendAsync(request, cancellationToken);
        }
        catch (HttpRequestException exception)
        {
            throw new UserInfoException(
                $"The UserInfo endpoint '{endpoint}' could not be reached.", exception);
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                // Section 5.3.3 sends the failure back as an OAuth bearer-token error, which RFC 6750
                // section 3 puts in the WWW-Authenticate header rather than the body. The body is not read
                // here: whatever it holds is chosen by whoever answered, and the status plus the challenge
                // say enough for a caller to act.
                throw new UserInfoException(
                    $"The UserInfo endpoint '{endpoint}' refused the access token: "
                    + $"{(int)response.StatusCode} {response.ReasonPhrase}"
                    + $"{FormatChallenge(response.Headers.WwwAuthenticate)}.");
            }

            return await ParseAsync(response, endpoint, cancellationToken);
        }
    }

    /// <summary>
    /// Reads the response body as the JSON object of claims.
    /// </summary>
    /// <remarks>
    /// Section 5.3.2 makes <c>application/json</c> the ordinary content type and adds that "the UserInfo
    /// Endpoint MAY also return the Claims as a JWT", which a client asks for by registering a signing
    /// algorithm for the response. This client registers none, so a JWT response is one it did not ask for
    /// and refuses rather than reads: reading it would mean either verifying a signature against keys and
    /// an algorithm nothing here selected, or trusting an unverified body.
    /// </remarks>
    private static async Task<JsonObject> ParseAsync(
        HttpResponseMessage response,
        string endpoint,
        CancellationToken cancellationToken)
    {
        var contentType = response.Content.Headers.ContentType?.MediaType;

        if (!string.Equals(contentType, "application/json", StringComparison.OrdinalIgnoreCase))
        {
            throw new UserInfoException(
                $"The UserInfo endpoint '{endpoint}' answered with '{contentType}'. This client registered "
                + "no signed response algorithm, so it expects the claims as application/json.");
        }

        var body = await response.Content.ReadAsStringAsync(cancellationToken);

        try
        {
            return JsonNode.Parse(body) as JsonObject
                   ?? throw new UserInfoException(
                       $"The UserInfo endpoint '{endpoint}' answered with JSON that is not an object.");
        }
        catch (JsonException exception)
        {
            throw new UserInfoException(
                $"The UserInfo endpoint '{endpoint}' answered with a body that is not JSON.", exception);
        }
    }

    /// <summary>
    /// Refuses claims that describe somebody other than the user this login authenticated.
    /// </summary>
    /// <remarks>
    /// The check the endpoint exists to need. OpenID Connect Core 1.0 section 5.3.2: "the Client MUST
    /// verify that the sub Claim in the UserInfo Response is identical to the sub Claim in the ID Token;
    /// if they do not match, the UserInfo Response values MUST NOT be used."
    /// It closes a substitution: an access token is a bearer credential naming no user, so a client that
    /// took the response at face value would attach whatever claims came back to the session it was
    /// building - and a provider that mixed up two requests, or an attacker who got their own token
    /// answered here, would have their user's claims land in someone else's session.
    /// </remarks>
    private static void RequireSameSubject(JsonObject claims, string expectedSubject, string issuer)
    {
        var subject = claims[IanaClaimTypes.Sub]?.GetValue<string>();

        if (subject is null)
        {
            throw new UserInfoException(
                $"The UserInfo response from '{issuer}' names no subject, so it cannot be shown to belong "
                + "to this login.");
        }

        if (!string.Equals(subject, expectedSubject, StringComparison.Ordinal))
        {
            throw new UserInfoException(
                $"The UserInfo response from '{issuer}' describes a different subject than the ID Token "
                + "this login produced, so its claims must not be used.");
        }
    }

    private static string FormatChallenge(HttpHeaderValueCollection<AuthenticationHeaderValue> challenges)
        => challenges.Count == 0 ? string.Empty : $" ({string.Join(", ", challenges)})";
}
