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

namespace Abblix.Oidc.Client.Features.EndSession;

/// <summary>
/// The parameters of an RP-initiated logout request, named as on the wire.
/// </summary>
/// <remarks>
/// Defined by OpenID Connect RP-Initiated Logout 1.0 section 2, and carrying the same names as the server
/// side of the family reads them under.
/// </remarks>
public static class Parameters
{
    /// <summary>
    /// The ID Token this client last received for the session being ended.
    /// </summary>
    public const string IdTokenHint = "id_token_hint";

    /// <summary>
    /// A hint about which end-user is logging out, in whatever form the provider documents.
    /// </summary>
    public const string LogoutHint = "logout_hint";

    /// <summary>
    /// This client's identifier.
    /// </summary>
    public const string ClientId = "client_id";

    /// <summary>
    /// Where the provider is asked to send the user once the logout is done.
    /// </summary>
    public const string PostLogoutRedirectUri = "post_logout_redirect_uri";

    /// <summary>
    /// An opaque value the provider echoes back to the client.
    /// </summary>
    public const string State = "state";

    /// <summary>
    /// The languages the end-user prefers for the provider's own pages.
    /// </summary>
    public const string UiLocales = "ui_locales";
}
