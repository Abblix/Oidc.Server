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

        RequireFlowIsPermitted(_options.Flow);

        // Only where there is a code to protect. Creating the pair also refuses a provider advertising no
        // SHA-256 challenge method, and that refusal has no business stopping a flow which issues no code
        // and never visits the token endpoint - there would be nothing for PKCE to guard.
        var pkce = _options.Flow.IncludesAuthorizationCode()
            ? await _pkceProvider.CreateAsync(cancellationToken)
            : null;

        var state = new AuthorizationContext
        {
            State = NewOpaqueValue(),
            Nonce = NewOpaqueValue(),
            CodeVerifier = pkce?.CodeVerifier ?? string.Empty,
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
    /// Refuses a flow that returns tokens through the browser unless the host has said it accepts them,
    /// and refuses one whose response mode was left for this builder to guess.
    /// </summary>
    /// <remarks>
    /// Two separate refusals, because they answer different questions and a host can get either wrong on
    /// its own.
    /// The first is the opt-in: a front-channel token is exposed to the browser's history, to the referrer
    /// of anything the page loads, and to any script running on it, and RFC 9700 section 2.1.2 says
    /// "clients SHOULD NOT use the implicit grant (response type "token") or any other response type
    /// issuing access tokens in the authorization response". Choosing such a flow is legal and this client
    /// supports it, but not by accident.
    /// The second is the response mode, and it is refused rather than defaulted because both plausible
    /// defaults are wrong for somebody. Multiple Response Type Encoding Practices section 5 makes the
    /// fragment the default for these flows and says "the query encoding MUST NOT be used", while RFC 3986
    /// section 3.5 says a fragment "is dereferenced solely by the user agent" - so a server-side client
    /// that inherits the default receives an empty callback, and a browser-based one that is handed
    /// form_post cannot use it. Only the host knows which it is, so it must say.
    /// </remarks>
    private void RequireFlowIsPermitted(AuthorizationFlow flow)
    {
        if (!flow.ReturnsFrontChannelTokens())
            return;

        if (!_options.FrontChannelTokensAccepted)
        {
            throw new AuthorizationRequestException(
                $"The '{flow.ToResponseType()}' flow returns tokens through the browser, which this client "
                + $"does not do unless {nameof(AuthorizationRequestOptions)}."
                + $"{nameof(AuthorizationRequestOptions.FrontChannelTokensAccepted)} says so.");
        }

        if (string.IsNullOrEmpty(_options.ResponseMode))
        {
            throw new AuthorizationRequestException(
                $"The '{flow.ToResponseType()}' flow needs a response mode: its default is the fragment, "
                + "which never reaches a server. Set "
                + $"{nameof(AuthorizationRequestOptions)}.{nameof(AuthorizationRequestOptions.ResponseMode)}"
                + $" to '{ResponseModes.FormPost}' for a server-side client, or '{ResponseModes.Fragment}' "
                + "for a browser-based one that reads the fragment itself.");
        }
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

    private Uri BuildRequestUri(string authorizationEndpoint, AuthorizationContext context, PkceParameters? pkce)
    {
        // The builder carries over whatever the endpoint already has in its query: a provider is free to
        // publish an authorization endpoint with parameters of its own, and dropping them would break it.
        var endpoint = new Utils.UriBuilder(authorizationEndpoint);
        var parameters = endpoint.Query;

        var flow = _options.Flow;

        parameters[Parameters.ResponseType] = flow.ToResponseType();
        parameters[Parameters.ClientId] = _clientOptions.ClientId;
        parameters[Parameters.RedirectUri] = context.RedirectUri;
        parameters[Parameters.Scope] = string.Join(' ', _options.Scopes);
        parameters[Parameters.State] = context.State;

        // Always sent. It binds an ID Token to this request, and for the flows that return one from the
        // authorization endpoint OIDC Core 1.0 section 3.2.2.11 makes that binding mandatory.
        parameters[Parameters.Nonce] = context.Nonce;

        // Omitted for the code flow, whose default mode is already the query a server-side callback reads
        // (Multiple Response Type Encoding Practices section 5); required and validated for the rest.
        if (!string.IsNullOrEmpty(_options.ResponseMode))
            parameters[Parameters.ResponseMode] = _options.ResponseMode;

        // PKCE protects the redemption of an authorization code, so it goes only where there is a code to
        // redeem. A pure implicit flow returns its tokens from the authorization endpoint and never visits
        // the token endpoint, leaving the challenge nothing to be checked against - and so no pair was
        // built for it in the first place.
        if (pkce is not null)
        {
            parameters[Parameters.CodeChallenge] = pkce.CodeChallenge;
            parameters[Parameters.CodeChallengeMethod] = pkce.CodeChallengeMethod;
        }

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
