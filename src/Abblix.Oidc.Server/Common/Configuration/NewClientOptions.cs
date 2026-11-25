// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Defaults used by the dynamic client registration endpoint when minting credentials for a newly
/// registered client: how its client identifier and client secret are generated and how long the
/// secret stays valid.
/// </summary>
public record NewClientOptions
{
    /// <summary>
    /// Generation parameters for the client identifier issued to a newly registered client.
    /// </summary>
    public ClientIdOptions ClientId { get; init; } = new();

    /// <summary>
    /// Lets a client registering itself choose its client identifier by sending a <c>client_id</c> member. Off by
    /// default: the server assigns every identifier and a proposed one is ignored, as RFC 9700 section 4.15.1
    /// recommends.
    /// </summary>
    /// <remarks>
    /// It governs the library's registration pipeline, which the dynamic client registration endpoint runs. A token
    /// the client credentials grant issues carries <c>idp</c> set to <c>client_credentials</c>, in the token and in the
    /// introspection response, which shows it to every caller for such a token alone, and the user information
    /// endpoint refuses such a token. A proposed identifier is refused when another client holds it, or when it is an
    /// <c>https</c> URL while client ID metadata documents are enabled. Applied on registration only: an RFC 7592
    /// update keeps the identifier the client has.
    /// </remarks>
    public bool AcceptProposedClientId { get; init; }

    /// <summary>
    /// Generation parameters and lifetime policy for the client secret issued to a newly registered client.
    /// </summary>
    public ClientSecretOptions ClientSecret { get; init; } = new();

    /// <summary>
    /// The scope values a client registering without a <c>scope</c> member may request: the default set
    /// RFC 7591 section 2 lets the server register such a client with. Unset, the client may request any scope.
    /// </summary>
    /// <remarks>
    /// Applied on registration and on every RFC 7592 update that omits the member, since an update replaces the
    /// metadata whole.
    /// </remarks>
    public string[]? Scope { get; init; }

    /// <summary>
    /// The resources a dynamically registered client may get an access token for: the list a client registering
    /// without an <c>allowed_resources</c> member is given, and the set a list it sends has to stay within. Unset, a
    /// client registering without the member may get a token for any registered resource, and for none a client
    /// registered while anybody may register, that is while <see cref="OidcOptions.RequireInitialAccessToken"/> is
    /// <c>false</c> and no software statement from a trusted issuer is required, and every client resolved from its
    /// metadata document. One sending a resource is refused, since which resources a client reaches is the server's
    /// policy rather than the client's choice.
    /// </summary>
    /// <remarks>
    /// Applied on registration, on every RFC 7592 update and to every client resolved from its metadata document, since
    /// an update replaces the metadata whole. An update of a client stored as <see cref="ClientTrust.Unreviewed"/> is
    /// held to these defaults; a record that names no trust, as every record stored by 3.0, is
    /// <see cref="ClientTrust.Reviewed"/> until the host writes its trust.
    /// </remarks>
    public Uri[]? AllowedResources { get; init; }

    /// <summary>
    /// The resources a client registered while anybody may register, or resolved from its metadata document, is given
    /// when it names none: <see cref="AllowedResources"/>, or none when it is unset.
    /// </summary>
    internal Uri[] UnreviewedClientResources => AllowedResources ?? [];

    /// <summary>
    /// The token exchange audiences a dynamically registered client may name: the list a client registering without
    /// a <c>token_exchange_audiences</c> member is given, and the set a list it sends has to stay within. Unset, a
    /// client registering without the member may name no audience, and one sending an audience is refused.
    /// </summary>
    /// <remarks>
    /// Applied on registration and on every RFC 7592 update, since an update replaces the metadata whole.
    /// </remarks>
    public string[]? TokenExchangeAudiences { get; init; }

    /// <summary>
    /// The grant types a dynamically registered client may request in its <c>grant_types</c> member: a registration
    /// naming one outside the set, the <c>authorization_code</c> grant RFC 7591 section 2 takes for an omitted member
    /// included, is refused with <c>invalid_client_metadata</c>. Unset, a client may request every grant type the
    /// server supports, and a client nobody vetted only <c>authorization_code</c> and <c>refresh_token</c>: one
    /// registered while anybody may register, that is while <see cref="OidcOptions.RequireInitialAccessToken"/> is
    /// <c>false</c> and no software statement from a trusted issuer is required.
    /// </summary>
    /// <remarks>
    /// A grant outside an interactive sign-in, such as <c>client_credentials</c>, gets tokens with no user present, so
    /// a client nobody vetted gets only the grants of one unless the host names others here. Clients the host
    /// defines itself are not bound by it, and the discovery document still lists every grant type the server supports.
    /// Applied on
    /// registration and on every RFC 7592 update, since an update replaces the metadata whole, so a client registered
    /// before the limit was set keeps its grant types until its next update. An empty set, or one
    /// holding a blank value, is refused at startup.
    /// </remarks>
    public string[]? AllowedGrantTypes { get; init; }

    /// <summary>
    /// The grant types OAuth 2.1 leaves to an interactive sign-in, the authorization code and the refresh token,
    /// which a client nobody vetted gets unless the host names others: one registered while anybody may register and
    /// one resolved from its metadata document.
    /// </summary>
    internal static readonly string[] InteractiveSignInGrantTypes =
        [GrantTypes.AuthorizationCode, GrantTypes.RefreshToken];

    /// <summary>
    /// What a dynamically registered client's authentication assertions may name as their audience, and in which
    /// form: <see cref="ClientAssertionAudiences.Issuer"/> by default, the issuer identifier RFC 10070
    /// section 4 requires, as a string. A value left at zero reads as that default.
    /// </summary>
    /// <remarks>
    /// RFC 7591 metadata has no member for it, so it is the host's to grant, never the client's to ask for. Widening
    /// it departs from the MUST of RFC 10070 sections 4 and 5 for every client that registers, so a host does it only
    /// while those clients still write an older form, the token endpoint URL OpenID Connect Core 1.0 section 9
    /// recommends, the backchannel authentication endpoint URL CIBA Core 1.0 section 7.1 names and the pushed
    /// authorization request endpoint URL RFC 9126 section 2 named among them: section 6 of that RFC warns that such
    /// clients "may not interoperate with authorization servers that strictly enforce the updated requirements". A
    /// tenant held to FAPI 2.0 gives its clients the issuer alone whatever is set here. Applied on registration and on
    /// every RFC 7592 update, since an update builds the client anew. A set without the issuer, or naming a value the
    /// enumeration does not define, is refused at startup.
    /// </remarks>
    public ClientAssertionAudiences ClientAssertionAudiences
    {
        get => field.ByDefault(ClientAssertionAudiences.Issuer);
        init => field = value.ByDefault(ClientAssertionAudiences.Issuer);
    } = ClientAssertionAudiences.Issuer;

    /// <summary>
    /// Lets a dynamically registered client receive the offline access it is allowed beside an access token carried
    /// through the user agent (<see cref="ClientInfo.AllowOfflineAccessWithUserAgentAccessToken"/>). Off by default,
    /// as OpenID Connect Core 1.0 section 17.4 mandates.
    /// </summary>
    /// <remarks>
    /// RFC 7591 metadata has no member for it, so it is the host's to grant. Applied on registration and on every
    /// RFC 7592 update, since an update builds the client anew.
    /// </remarks>
    public bool AllowOfflineAccessWithUserAgentAccessToken { get; init; }

    /// <summary>
    /// The offline access a dynamically registered client receives: what a client registering without an
    /// <c>offline_access</c> member is given, and the most a value it sends may raise it to.
    /// <see cref="Features.ClientInformation.OfflineAccess.ConsentRequired"/> by default, so a client receives offline
    /// access only from an authorization request with <c>prompt=consent</c>.
    /// </summary>
    /// <remarks>
    /// <see cref="Features.ClientInformation.OfflineAccess.Allowed"/> is the host stating, for every client that
    /// registers, the "other conditions for processing the request permitting offline access" under which OpenID
    /// Connect Core 1.0 section 11 waives <c>prompt=consent</c>; it does not waive the end user's consent to offline
    /// access, which the host's consent provider still reports. A client may ask for less, never for more. It governs
    /// new registrations and any value an RFC 7592 update raises, and an update omitting the member takes it, since an
    /// update builds the client anew. A client already stored keeps what it was given, and an update restating that
    /// value keeps it, so lowering this setting takes nothing from a client registered before: the host changes such
    /// clients in its client store.
    /// A value the enumeration does not define is refused at startup.
    /// </remarks>
    public OfflineAccess OfflineAccess { get; init; } = OfflineAccess.ConsentRequired;

    /// <summary>
    /// The lifetime of the access tokens a dynamically registered client is issued
    /// (<see cref="ClientInfo.AccessTokenExpiresIn"/>), by default the one a client takes unless one is set on it.
    /// </summary>
    /// <remarks>
    /// RFC 7591 metadata has no member for it, so it is the host's to set. Applied on registration and to every client
    /// resolved from its metadata document; an RFC 7592 update keeps what the client was given, and the host changes a
    /// stored client in its client store. A lifetime of zero or less, or one longer than ten years, is refused at
    /// startup.
    /// </remarks>
    public TimeSpan AccessTokenExpiresIn { get; init; } = ClientInfo.DefaultAccessTokenExpiresIn;

    /// <summary>
    /// Whether every access token a dynamically registered client is issued names one resource
    /// (<see cref="ClientInfo.SingleResourceAccessTokens"/>). Off by default.
    /// </summary>
    /// <remarks>
    /// RFC 7591 metadata has no member for it, so it is the host's to set. Applied on registration and to every client
    /// resolved from its metadata document; an RFC 7592 update keeps what the client was given.
    /// </remarks>
    public bool SingleResourceAccessTokens { get; init; }

    /// <summary>
    /// The lifetime and reuse policy of the refresh tokens a dynamically registered client is issued
    /// (<see cref="ClientInfo.RefreshToken"/>). The defaults of <see cref="RefreshTokenOptions"/> by default.
    /// </summary>
    /// <remarks>
    /// RFC 7591 metadata has no member for it, so it is the host's to set. Applied on registration and to every client
    /// resolved from its metadata document; an RFC 7592 update keeps what the client was given. An absolute or sliding
    /// lifetime of zero or less, or one longer than ten years, and a reuse policy the enumeration does not define are
    /// refused at startup.
    /// </remarks>
    public RefreshTokenOptions RefreshToken { get; init; } = new();
}
