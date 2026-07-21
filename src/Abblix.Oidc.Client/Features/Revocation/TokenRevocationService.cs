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

using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Abblix.Oidc.Client.Features.ClientAuthentication;
using Abblix.Oidc.Client.Features.Discovery;
using Abblix.Oidc.Client.Features.Tokens;

namespace Abblix.Oidc.Client.Features.Revocation;

/// <summary>
/// Revokes tokens at the provider's revocation endpoint (RFC 7009).
/// </summary>
/// <param name="metadataProvider">Supplies the endpoint address the provider published.</param>
/// <param name="httpClientFactory">Builds the client this service calls the endpoint with.</param>
/// <param name="credentialsPresenter">Puts this client's credentials on the request.</param>
public sealed class TokenRevocationService(
    IProviderMetadataProvider metadataProvider,
    IHttpClientFactory httpClientFactory,
    IClientCredentialsPresenter credentialsPresenter) : ITokenRevocationService
{
    /// <summary>
    /// The name of the <see cref="HttpClient"/> this service resolves from <see cref="IHttpClientFactory"/>.
    /// </summary>
    /// <remarks>
    /// Named for the same reason the token service's is, and for one of its own: RFC 7009 section 5 requires
    /// that "in order to detect counterfeit revocation endpoints, clients MUST authenticate the revocation
    /// endpoint (certificate validation, etc.)", which a host tightens by configuring the handler of this
    /// named client - pinning a certificate, for instance - without touching this code.
    /// </remarks>
    public const string HttpClientName = "Abblix.Oidc.Client.Revocation";

    /// <inheritdoc />
    public async Task RevokeAsync(
        string token, string? tokenTypeHint = null, CancellationToken cancellationToken = default)
    {
        var metadata = await metadataProvider.GetMetadataAsync(cancellationToken);

        if (metadata.RevocationEndpoint is not { } endpoint)
        {
            throw new TokenRevocationException(
                $"The OpenID Provider '{metadata.Issuer}' publishes no revocation endpoint, so this token "
                + "cannot be revoked.",
                tokenMayStillExist: true);
        }

        // RFC 7009 section 2.1: the token is REQUIRED, the hint OPTIONAL, and the client "also includes its
        // authentication credentials as described in Section 2.3. of [RFC6749]".
        var parameters = new Dictionary<string, string> { ["token"] = token };

        if (tokenTypeHint is not null)
            parameters["token_type_hint"] = tokenTypeHint;

        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint);
        credentialsPresenter.Present(request, parameters);
        request.Content = new FormUrlEncodedContent(parameters);

        HttpResponseMessage response;
        try
        {
            var httpClient = httpClientFactory.CreateClient(HttpClientName);
            response = await httpClient.SendAsync(request, cancellationToken);
        }
        catch (HttpRequestException exception)
        {
            throw new TokenRevocationException(
                $"The revocation endpoint of OpenID Provider '{metadata.Issuer}' at '{endpoint}' could not "
                + "be reached.",
                exception);
        }

        using (response)
        {
            // RFC 7009 section 2.2: the provider "responds with HTTP status code 200 if the token has been
            // revoked successfully or if the client submitted an invalid token", and "the content of the
            // response body is ignored by the client as all necessary information is conveyed in the
            // response code". So there is nothing here to read on success.
            if (response.IsSuccessStatusCode)
                return;

            await ThrowRefusalAsync(response, metadata, endpoint, cancellationToken);
        }
    }

    private static async Task ThrowRefusalAsync(
        HttpResponseMessage response,
        ProviderMetadata metadata,
        string endpoint,
        CancellationToken cancellationToken)
    {
        // RFC 7009 section 2.2.1: "If the server responds with HTTP status code 503, the client must assume
        // the token still exists and may retry after a reasonable delay." Every other refusal is final for
        // this request, and re-sending it unchanged would not change the answer.
        if (response.StatusCode == HttpStatusCode.ServiceUnavailable)
        {
            throw new TokenRevocationException(
                $"The revocation endpoint of OpenID Provider '{metadata.Issuer}' at '{endpoint}' is "
                + "unavailable, so the token must be assumed to still exist.",
                tokenMayStillExist: true,
                retryAfter: ReadRetryAfter(response));
        }

        var error = await ReadErrorAsync(response, cancellationToken);

        throw new TokenRevocationException(
            $"The revocation endpoint of OpenID Provider '{metadata.Issuer}' refused the request with status "
            + $"{(int)response.StatusCode}"
            + (error?.Error is { } code ? $" and error '{code}'." : "."),
            error?.Error);
    }

    /// <summary>
    /// Reads how long the provider asked the caller to wait, when it said.
    /// </summary>
    /// <remarks>
    /// RFC 7231 section 7.1.3 lets the header carry either a delay in seconds or an HTTP date; a date is
    /// turned into a delay here so a caller has one thing to wait on. A date already past yields no delay
    /// rather than a negative one.
    /// </remarks>
    private static TimeSpan? ReadRetryAfter(HttpResponseMessage response)
    {
        var retryAfter = response.Headers.RetryAfter;

        if (retryAfter?.Delta is { } delta)
            return delta;

        if (retryAfter?.Date is not { } date)
            return null;

        var wait = date - TimeProvider.System.GetUtcNow();
        return wait > TimeSpan.Zero ? wait : TimeSpan.Zero;
    }

    /// <summary>
    /// Reads the error code out of a refusal, when the provider sent one.
    /// </summary>
    /// <remarks>
    /// Refusals carry the shape of RFC 6749 section 5.2, which RFC 7009 section 2.2.1 extends with
    /// <c>unsupported_token_type</c> for the case where "the client tried to revoke an access token on a
    /// server not supporting this feature". The shape is shared with the token endpoint, so the model is too.
    /// </remarks>
    private static async Task<TokenErrorResponse?> ReadErrorAsync(
        HttpResponseMessage response, CancellationToken cancellationToken)
    {
        try
        {
            return await response.Content.ReadFromJsonAsync<TokenErrorResponse>(cancellationToken);
        }
        catch (JsonException)
        {
            // A provider that answers a refusal with something other than the documented shape still
            // refused. The status code is the part that matters, so an unreadable body is not allowed to
            // mask it.
            return null;
        }
    }
}
