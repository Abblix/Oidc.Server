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

namespace Abblix.Oidc.Server.Mvc;

/// <summary>
/// Contains constants for various OpenID Connect and OAuth2 endpoint paths.
/// This class centralizes the paths used throughout the application for consistency and maintainability.
/// </summary>
public static class Path
{
    /// <summary>
    /// Route prefix used in route templates for dynamic path configuration.
    /// </summary>
    public const string RoutePrefix = "route";

    /// <summary>
    /// Base route template with default value ~/connect.
    /// Used as foundation for all endpoint paths.
    /// </summary>
    private const string Base = "[" + RoutePrefix + ":base?~/connect]";

    /// <summary>
    /// Path for the authorization endpoint per OpenID Connect Core Section 3.1.
    /// </summary>
    public const string Authorize = "[" + RoutePrefix + ":authorize?" + Base + "/authorize]";

    /// <summary>
    /// Path for the pushed authorization request (PAR) endpoint per RFC 9126.
    /// </summary>
    public const string PushAuthorizationRequest = "[" + RoutePrefix + ":par?" + Base + "/par]";

    /// <summary>
    /// Path for the user information endpoint per OpenID Connect Core Section 5.3.
    /// </summary>
    public const string UserInfo = "[" + RoutePrefix + ":userinfo?" + Base + "/userinfo]";

    /// <summary>
    /// Path for the end session (logout) endpoint per OpenID Connect Session Management Section 5.
    /// </summary>
    public const string EndSession = "[" + RoutePrefix + ":endsession?" + Base + "/endsession]";

    /// <summary>
    /// Path for the session checking endpoint per OpenID Connect Session Management Section 4.
    /// </summary>
    public const string CheckSession = "[" + RoutePrefix + ":checksession?" + Base + "/checksession]";

    /// <summary>
    /// Path for the token endpoint per OpenID Connect Core Section 3.1.3 and OAuth 2.0 RFC 6749 Section 3.2.
    /// </summary>
    public const string Token = "[" + RoutePrefix + ":token?" + Base + "/token]";

    /// <summary>
    /// Path for the token revocation endpoint per RFC 7009.
    /// </summary>
    public const string Revocation = "[" + RoutePrefix + ":revoke?" + Base + "/revoke]";

    /// <summary>
    /// Path for the token introspection endpoint per RFC 7662.
    /// </summary>
    public const string Introspection = "[" + RoutePrefix + ":introspect?" + Base + "/introspect]";

    /// <summary>
    /// Path for the backchannel authentication endpoint per OpenID Connect CIBA.
    /// </summary>
    public const string BackChannelAuthentication = "[" + RoutePrefix + ":bc_authorize?" + Base + "/bc-authorize]";

    /// <summary>
    /// Path for the device authorization endpoint per RFC 8628.
    /// </summary>
    public const string DeviceAuthorization = "[" + RoutePrefix + ":deviceauthorization?" + Base + "/deviceauthorization]";

    /// <summary>
    /// Path for the client registration endpoint per OpenID Connect Dynamic Client Registration.
    /// </summary>
    public const string Register = "[" + RoutePrefix + ":register?" + Base + "/register]";

    /// <summary>
    /// Path for the client configuration endpoint per RFC 7592 Section 2.
    /// Format: /connect/register/{client_id}
    /// </summary>
    public const string RegisterClient = Register + "/{clientId}";

    /// <summary>
    /// Base route template for .well-known endpoints with default value ~/.well-known.
    /// </summary>
    private const string WellKnown = "[" + RoutePrefix + ":well_known?~/.well-known]";

    /// <summary>
    /// Path for the OpenID configuration document per OpenID Connect Discovery Section 4.
    /// </summary>
    public const string Configuration = "[" + RoutePrefix + ":configuration?" + WellKnown + "/openid-configuration]";

    /// <summary>
    /// Path for the JSON Web Key Set (JWKS) endpoint per OpenID Connect Discovery Section 4.
    /// </summary>
    public const string Keys = "[" + RoutePrefix + ":jwks?" + WellKnown + "/jwks]";
}
