// Abblix OIDC Server Library
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

using System.Buffers.Text;
using Abblix.Oidc.Client.Features.AuthorizationState;
using Abblix.Oidc.Client.Features.Discovery;
using Abblix.Oidc.Client.Features.Pkce;
using Abblix.Utils;
using Utils = Abblix.Utils;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Client.Features.AuthorizationRequests;

/// <summary>
/// Builds the address the user is sent to in order to sign in, and the state that must survive until they
/// come back.
/// </summary>
public sealed class AuthorizationRequestBuilder : IAuthorizationRequestBuilder
{
    /// <summary>
    /// The number of random bytes behind each opaque value the client generates.
    /// </summary>
    /// <remarks>
    /// 256 bits, which is far past what guessing could reach. These values are the client's only handle on
    /// which request a response belongs to, so their unguessability is what makes a forged callback fail.
    /// </remarks>
    private const int OpaqueValueByteCount = 32;

    private readonly IProviderMetadataProvider _metadataProvider;
    private readonly IPkceProvider _pkceProvider;
    private readonly IAuthorizationStateStore _stateStore;
    private readonly OidcClientOptions _clientOptions;
    private readonly AuthorizationRequestOptions _options;

    /// <summary>
    /// Creates the builder.
    /// </summary>
    public AuthorizationRequestBuilder(
        IProviderMetadataProvider metadataProvider,
        IPkceProvider pkceProvider,
        IAuthorizationStateStore stateStore,
        IOptions<OidcClientOptions> clientOptions,
        IOptions<AuthorizationRequestOptions> options)
    {
        _metadataProvider = metadataProvider;
        _pkceProvider = pkceProvider;
        _stateStore = stateStore;
        _clientOptions = clientOptions.Value;
        _options = options.Value;
    }

    /// <inheritdoc />
    public async Task<AuthorizationRequest> CreateAsync(
        Uri returnUri, CancellationToken cancellationToken = default)
    {
        var metadata = await _metadataProvider.GetMetadataAsync(cancellationToken);

        if (metadata.AuthorizationEndpoint is not { } authorizationEndpoint)
            throw new AuthorizationRequestException(
                $"The OpenID Provider '{metadata.Issuer}' names no authorization endpoint, so there is "
                + "nowhere to send the user.");

        var pkce = await _pkceProvider.CreateAsync(cancellationToken);

        var state = new AuthorizationState.AuthorizationState
        {
            State = NewOpaqueValue(),
            Nonce = NewOpaqueValue(),
            CodeVerifier = pkce.CodeVerifier,
            ReturnUri = returnUri.ToString(),
            Issuer = metadata.Issuer,
            RedirectUri = _options.RedirectUri.ToString(),
        };

        // Stored before the address is handed out, so the callback can never arrive for a state that was not
        // put aside yet.
        await _stateStore.StoreAsync(state, cancellationToken);

        return new AuthorizationRequest(BuildRequestUri(authorizationEndpoint, state, pkce), state);
    }

    private Uri BuildRequestUri(string authorizationEndpoint, AuthorizationState.AuthorizationState state, PkceParameters pkce)
    {
        // The builder carries over whatever the endpoint already has in its query: a provider is free to
        // publish an authorization endpoint with parameters of its own, and dropping them would break it.
        var endpoint = new Utils.UriBuilder(authorizationEndpoint);
        var parameters = endpoint.Query;

        parameters[Parameters.ResponseType] = ResponseTypes.Code;
        parameters[Parameters.ClientId] = _clientOptions.ClientId;
        parameters[Parameters.RedirectUri] = state.RedirectUri;
        parameters[Parameters.Scope] = string.Join(' ', _options.Scopes);
        parameters[Parameters.State] = state.State;
        parameters[Parameters.Nonce] = state.Nonce;
        parameters[Parameters.CodeChallenge] = pkce.CodeChallenge;
        parameters[Parameters.CodeChallengeMethod] = pkce.CodeChallengeMethod;

        // Naming the resources narrows the issued token to them, so one that leaks from a resource cannot be
        // spent at another (RFC 8707). Omitted when the host names none, leaving the audience to the provider.
        foreach (var resource in _options.Resources)
            parameters.Add(Parameters.Resource, resource.ToString());

        foreach (var (name, value) in _options.AdditionalParameters)
            parameters[name] = value;

        return endpoint.Uri;
    }

    private static string NewOpaqueValue()
        => Base64Url.EncodeToString(CryptoRandom.GetRandomBytes(OpaqueValueByteCount));
}
