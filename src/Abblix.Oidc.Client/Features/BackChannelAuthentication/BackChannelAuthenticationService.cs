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

using System.Globalization;
using System.Net.Http.Json;
using System.Text.Json;
using Abblix.Oidc.Client.Common;
using Abblix.Oidc.Client.Features.ClientAuthentication;
using Abblix.Oidc.Client.Features.Discovery;
using Abblix.Oidc.Client.Features.Tokens;

namespace Abblix.Oidc.Client.Features.BackChannelAuthentication;

/// <summary>
/// Runs CIBA in poll mode: opens the request, then waits for the person by polling on the provider's terms.
/// </summary>
/// <param name="metadataProvider">Supplies the endpoint the provider published.</param>
/// <param name="httpClientFactory">Supplies the transport.</param>
/// <param name="credentialsPresenter">Presents this client's credentials, which CIBA always requires.</param>
/// <param name="tokenRequestService">Redeems the request identifier, one attempt per call.</param>
/// <param name="timeProvider">Measures the waiting, so a test does not have to sit through it.</param>
public sealed class BackChannelAuthenticationService(
    IProviderMetadataProvider metadataProvider,
    IHttpClientFactory httpClientFactory,
    IClientCredentialsPresenter credentialsPresenter,
    ITokenRequestService tokenRequestService,
    TimeProvider timeProvider) : IBackChannelAuthenticationService
{
    /// <summary>
    /// The name of the <see cref="HttpClient"/> this service resolves from <see cref="IHttpClientFactory"/>.
    /// </summary>
    public const string HttpClientName = "Abblix.Oidc.Client.BackChannelAuthentication";

    private readonly GrantPoller _poller = new(timeProvider);

    /// <inheritdoc />
    public async Task<BackChannelAuthenticationResponse> RequestAsync(
        BackChannelAuthenticationRequest request, CancellationToken cancellationToken = default)
    {
        // Both refusals below are the specification's own words, caught here rather than after a round trip.
        // The hint one matters most: a request naming the person two ways is not one the provider can
        // resolve, and one naming them no way at all asks it to authenticate nobody in particular.
        var hints = new[] { request.LoginHint, request.LoginHintToken, request.IdTokenHint }
            .Count(hint => hint is not null);

        if (hints != 1)
            throw new ArgumentException(
                "A CIBA request names the person exactly one way: section 7.1 says it is REQUIRED that the "
                + "client provides one (and only one) of login_hint, login_hint_token and id_token_hint.",
                nameof(request));

        if (!request.Scopes.Contains(Scopes.OpenId, StringComparer.Ordinal))
            throw new ArgumentException(
                "A CIBA request asks for the openid scope, which section 7.1 requires of every one of them.",
                nameof(request));

        var metadata = await metadataProvider.GetMetadataAsync(cancellationToken);

        if (metadata.BackChannelAuthenticationEndpoint is not { } endpoint)
            throw new BackChannelAuthenticationException(
                $"The OpenID Provider '{metadata.Issuer}' names no backchannel authentication endpoint, so a "
                + "person cannot be asked this way.");

        var parameters = new Dictionary<string, string>
        {
            [Parameters.Scope] = string.Join(' ', request.Scopes),
        };

        if (request.LoginHint is { } loginHint)
            parameters[Parameters.LoginHint] = loginHint;

        if (request.LoginHintToken is { } loginHintToken)
            parameters[Parameters.LoginHintToken] = loginHintToken;

        if (request.IdTokenHint is { } idTokenHint)
            parameters[Parameters.IdTokenHint] = idTokenHint;

        if (request.BindingMessage is { } bindingMessage)
            parameters[Parameters.BindingMessage] = bindingMessage;

        if (request.UserCode is { } userCode)
            parameters[Parameters.UserCode] = userCode;

        if (request.AcrValues is { Count: > 0 })
            parameters[Parameters.AcrValues] = string.Join(' ', request.AcrValues);

        // Whole seconds, and invariant: the parameter is a number on the wire, and a culture that writes a
        // decimal comma would send something the provider cannot read.
        if (request.RequestedExpiry is { } requestedExpiry)
            parameters[Parameters.RequestedExpiry] =
                ((long)requestedExpiry.TotalSeconds).ToString(CultureInfo.InvariantCulture);

        using var message = new HttpRequestMessage(HttpMethod.Post, endpoint);
        credentialsPresenter.Present(message, parameters);
        message.Content = new FormUrlEncodedContent(parameters);

        HttpResponseMessage response;
        try
        {
            var httpClient = httpClientFactory.CreateClient(HttpClientName);
            response = await httpClient.SendAsync(message, cancellationToken);
        }
        catch (HttpRequestException exception)
        {
            throw new BackChannelAuthenticationException(
                "Failed to reach the backchannel authentication endpoint of OpenID Provider "
                + $"'{metadata.Issuer}' at '{endpoint}'.",
                exception);
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
                throw new BackChannelAuthenticationException(
                    $"The backchannel authentication endpoint of OpenID Provider '{metadata.Issuer}' refused "
                    + $"the request with status {(int)response.StatusCode}.");

            try
            {
                return await response.Content
                           .ReadFromJsonAsync<BackChannelAuthenticationResponse>(cancellationToken)
                       ?? throw new BackChannelAuthenticationException(
                           $"The backchannel authentication endpoint of OpenID Provider '{metadata.Issuer}' "
                           + "returned an empty response.");
            }
            catch (JsonException exception)
            {
                throw new BackChannelAuthenticationException(
                    $"Failed to read the response of the backchannel authentication endpoint at '{endpoint}'.",
                    exception);
            }
        }
    }

    /// <inheritdoc />
    public Task<TokenResponse> WaitForTokensAsync(
        BackChannelAuthenticationResponse authentication, CancellationToken cancellationToken = default)
        => _poller.PollAsync(
            authentication.PollingInterval,
            authentication.Lifetime,
            token => tokenRequestService.RedeemAuthenticationRequestAsync(
                authentication.AuthenticationRequestId, token),
            "The backchannel authentication request expired before its user answered it.",
            cancellationToken);
}
