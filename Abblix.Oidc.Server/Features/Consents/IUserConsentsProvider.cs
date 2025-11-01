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

using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.UserAuthentication;

namespace Abblix.Oidc.Server.Features.Consents;

/// <summary>
/// Defines an interface for a service that provides user consents. This service is responsible for retrieving
/// and managing user consent decisions related to authorization requests. It ensures that the application adheres
/// to user preferences and legal requirements concerning data access and processing.
/// </summary>
public interface IUserConsentsProvider
{
    /// <summary>
    /// Asynchronously retrieves the user consents for a given authorization request and authentication session.
    /// This method is essential for determining which scopes and resources the user has consented to, enabling
    /// the application to respect user permissions and comply with data protection regulations.
    /// </summary>
    /// <param name="request">The validated authorization request containing the scopes and resources for which
    /// consent may be required.</param>
    /// <param name="authSession">The current authentication session that provides context about the authenticated user,
    /// potentially influencing consent retrieval based on the user's settings or previous consent decisions.</param>
    /// <returns>A task that resolves to an instance of <see cref="UserConsents"/>, containing detailed information
    /// about the consents granted or denied by the user.</returns>
    Task<UserConsents> GetUserConsentsAsync(ValidAuthorizationRequest request, AuthSession authSession);
}
