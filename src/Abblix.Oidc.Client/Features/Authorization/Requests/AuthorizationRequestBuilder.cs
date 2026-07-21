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

using System.Buffers.Text;
using Abblix.Oidc.Client.Features.Authorization.Context;
using Abblix.Oidc.Client.Features.Discovery;
using Abblix.Oidc.Client.Features.Pkce;
using Abblix.Utils;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Client.Features.Authorization.Requests;

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

        var state = new AuthorizationContext
        {
            State = NewOpaqueValue(),
            Nonce = NewOpaqueValue(),
            CodeVerifier = pkce.CodeVerifier,
            ReturnUri = RequireLocal(returnUri),
            Issuer = metadata.Issuer,
            RedirectUri = RequireAbsolute(_options.RedirectUri),
        };

        // Stored before the address is handed out, so the callback can never arrive for a state that was not
        // put aside yet.
        await _stateStore.StoreAsync(state, cancellationToken);

        return new AuthorizationRequest(BuildRequestUri(authorizationEndpoint, state, pkce), state);
    }

    /// <summary>
    /// Refuses a return address that would send the user off this application.
    /// </summary>
    /// <remarks>
    /// This value is where the user is sent once the login finishes, and in practice it comes from the
    /// request that triggered the login - a "?returnUrl=" the user agent supplied. Stored unchecked, it
    /// makes the client an open redirector: an ordinary-looking link lands the victim on an attacker's
    /// page immediately after a genuine interaction with their real identity provider, which is the
    /// most trusted moment in the whole flow and the best possible place to ask them to sign in again.
    /// RFC 6749 section 10.15 names the hazard - "The authorization server, authorization endpoint, and
    /// client redirection endpoint can be improperly configured and operate as open redirectors" - and
    /// RFC 9700 section 4.11 puts the duty on the client.
    /// The check belongs here, where the value enters the store, rather than wherever it is later read.
    /// A rule applied at the point of use is a rule every future caller has to remember; applied at the
    /// point of storage, a dangerous value simply cannot be held.
    /// What this package can enforce is the host-agnostic half: the address must be relative, so it
    /// carries no scheme and no authority of its own. Whether a relative path is one this application
    /// actually serves is a question only the host can answer, and its adapter narrows it further.
    /// </remarks>
    private static string RequireLocal(Uri returnUri)
    {
        var address = returnUri.OriginalString;

        // Two leading separators make a protocol-relative address: "//evil.example" is off-site despite
        // having no scheme. Backslashes are checked alongside because browsers normalise them to slashes
        // before resolving, so "/\evil.example" reaches the same place while reading as a local path.
        var isProtocolRelative = address.Length >= 2 && IsSeparator(address[0]) && IsSeparator(address[1]);

        if (returnUri.IsAbsoluteUri || isProtocolRelative)
        {
            throw new AuthorizationRequestException(
                "The return address must be relative to this application. An absolute one would let a "
                + "caller redirect the user anywhere once the login finishes.");
        }

        return address;
    }

    private static bool IsSeparator(char character) => character is '/' or '\\';

    /// <summary>
    /// Refuses a redirection endpoint that is not absolute.
    /// </summary>
    /// <remarks>
    /// The opposite requirement to the return address, and for a reason worth stating as a
    /// consequence rather than as a rule. The provider does not resolve this address; it hands it to
    /// the browser, and the browser resolves it from where it is standing at that moment, which is the
    /// provider's own page. So a relative value points back into the provider's site: the user
    /// authenticates successfully and lands there, never reaching this application at all. RFC 6749
    /// section 3.1.2 says it plainly: "The redirection endpoint URI MUST be an absolute URI as defined
    /// by [RFC3986] Section 4.3."
    /// The two addresses are easy to confuse, both being places a login returns to. Each is checked
    /// because the browser resolves them standing in different places: the return address while it is
    /// already here, so it must not name a host, and this one while it is still at the provider, so it
    /// must.
    /// The type cannot carry this: <see cref="Uri"/> holds relative addresses just as happily.
    /// </remarks>
    private static string RequireAbsolute(Uri redirectUri)
    {
        if (!redirectUri.IsAbsoluteUri)
        {
            throw new AuthorizationRequestException(
                $"The configured redirect address '{redirectUri}' is relative. The browser "
                + "resolves it while it is still on the provider's page, so a relative one leads back "
                + "into the provider's site instead of this application. It must be absolute.");
        }

        return redirectUri.ToString();
    }

    private Uri BuildRequestUri(string authorizationEndpoint, AuthorizationContext state, PkceParameters pkce)
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
