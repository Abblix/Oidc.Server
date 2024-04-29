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

namespace Abblix.Oidc.Server.Features.LogoutNotification;

/// <summary>
/// Represents the context for a logout operation, containing details necessary for processing the logout.
/// This context includes the session identifier, the subject identifier of the user, the issuer of the
/// authentication token, and a collection of URIs for front-channel logout notifications.
/// </summary>
public record LogoutContext(string SessionId, string SubjectId, string Issuer)
{
    /// <summary>
    /// The session ID associated with the logout event.
    /// This identifier is typically used to identify and terminate the specific session that the logout request pertains to.
    /// </summary>
    public string SessionId { get; init; } = SessionId;

    /// <summary>
    /// The subject ID of the user initiating the logout.
    /// This identifier usually corresponds to the unique identifier of the user within the identity system,
    /// facilitating the identification of the user across different services or components.
    /// </summary>
    public string SubjectId { get; init; } = SubjectId;

    /// <summary>
    /// The issuer of the logout event.
    /// This is typically represented by the URL of the authentication server that issued the original authentication token,
    /// allowing the identification of the authority responsible for the user's authentication.
    /// </summary>
    public string Issuer { get; init; } = Issuer;

    /// <summary>
    /// A list of URIs for sending front-channel logout requests.
    /// These URIs are intended for notifying relevant parties of the logout event through the front-channel,
    /// enabling the propagation of logout notifications to clients or services that need to respond to the logout event.
    /// </summary>
    public IList<Uri> FrontChannelLogoutRequestUris { get; init; } = new List<Uri>();
}
