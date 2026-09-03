// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.AspNetCore.Routing;

namespace Abblix.Oidc.Server.MinimalApi;

/// <summary>
/// Route templates for the OpenID Connect and OAuth 2.0 endpoints mapped by
/// <see cref="EndpointRouteBuilderExtensions.MapOidcEndpoints(IEndpointRouteBuilder,string)"/>.
/// </summary>
/// <remarks>
/// The MVC integration encodes these paths as tokenized templates resolved through the MVC application model.
/// Minimal API has no application-model hook, so the same configurability is expressed as a plain options object:
/// a host overrides any path through the options pattern, and the endpoints are mapped against the resolved literals
/// at startup. Defaults mirror the MVC fallbacks (<c>/connect/*</c> and <c>/.well-known/*</c>).
/// </remarks>
public sealed class OidcRouteOptions
{
    /// <summary>The authorization endpoint (OpenID Connect Core 3.1).</summary>
    public string Authorize { get; set; } = "/connect/authorize";

    /// <summary>The pushed authorization request endpoint (RFC 9126).</summary>
    public string PushedAuthorizationRequest { get; set; } = "/connect/par";

    /// <summary>The UserInfo endpoint (OpenID Connect Core 5.3).</summary>
    public string UserInfo { get; set; } = "/connect/userinfo";

    /// <summary>The end-session (logout) endpoint (OpenID Connect Session Management 5).</summary>
    public string EndSession { get; set; } = "/connect/endsession";

    /// <summary>The check-session endpoint (OpenID Connect Session Management 4).</summary>
    public string CheckSession { get; set; } = "/connect/checksession";

    /// <summary>The token endpoint (OpenID Connect Core 3.1.3, OAuth 2.0 RFC 6749 3.2).</summary>
    public string Token { get; set; } = "/connect/token";

    /// <summary>The token revocation endpoint (RFC 7009).</summary>
    public string Revocation { get; set; } = "/connect/revoke";

    /// <summary>The token introspection endpoint (RFC 7662).</summary>
    public string Introspection { get; set; } = "/connect/introspect";

    /// <summary>The backchannel authentication endpoint (OpenID Connect CIBA).</summary>
    public string BackChannelAuthentication { get; set; } = "/connect/bc-authorize";

    /// <summary>The device authorization endpoint (RFC 8628).</summary>
    public string DeviceAuthorization { get; set; } = "/connect/deviceauthorization";

    /// <summary>The dynamic client registration endpoint (OpenID Connect Dynamic Client Registration).</summary>
    public string Register { get; set; } = "/connect/register";

    /// <summary>
    /// The client configuration endpoint (RFC 7592). Must contain the <c>{clientId}</c> route parameter.
    /// </summary>
    public string RegisterClient { get; set; } = "/connect/register/{clientId}";

    /// <summary>The OpenID Provider configuration document (OpenID Connect Discovery 4).</summary>
    public string Configuration { get; set; } = "/.well-known/openid-configuration";

    /// <summary>The JSON Web Key Set endpoint (OpenID Connect Discovery 4).</summary>
    public string Keys { get; set; } = "/.well-known/jwks";

    /// <summary>
    /// The OAuth 2.0 Authorization Server Metadata document (RFC 8414 section 3) - the same metadata served at
    /// <see cref="Configuration"/>, also exposed at the oauth-authorization-server suffix.
    /// </summary>
    public string OAuthAuthorizationServer { get; set; } = "/.well-known/oauth-authorization-server";
}
