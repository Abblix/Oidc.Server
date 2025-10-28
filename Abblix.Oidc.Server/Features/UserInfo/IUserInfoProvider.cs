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

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Features.UserAuthentication;

namespace Abblix.Oidc.Server.Features.UserInfo;

/// <summary>
/// Provides functionality to retrieve user information as JWT claims, supporting both simple and structured claim
/// values.
/// This interface enables the dynamic extraction and packaging of user attributes into JWT claims, accommodating a
/// variety
/// of claim types including those that require complex, structured data beyond traditional scalar values.
/// </summary>
public interface IUserInfoProvider
{
    /// <summary>
    /// Asynchronously retrieves a set of user claims for an authenticated session, including both simple and
    /// structured claim values as requested by the client application. This method supports the OpenID Connect
    /// specification by allowing for the selective disclosure of user information, catering to the need for complex
    /// data structures within claims.
    /// </summary>
    /// <param name="authSession">
    /// The authentication session containing the user's subject identifier and additional authentication context.
    /// This provides access to authentication-specific claims such as the email used during authentication,
    /// which may differ from the user's primary email stored in the database.
    /// </param>
    /// <param name="requestedClaims">
    /// A collection of names representing the claims requested by a client application.
    /// Implementations should check against this list to return only those claims that are requested and authorized
    /// for release, including both scalar values and structured data as necessary.
    /// </param>
    /// <returns>
    /// A task that resolves to a <see cref="JsonObject" />, encapsulating the user's claims where each entry consists of
    /// a claim name and its value. The value can be a simple scalar value (e.g., a string or number) or a structured
    /// object, allowing for complex data types to be represented. Returns null if no information is available for the
    /// given subject. The use of <see cref="JsonObject" /> facilitates the representation of hierarchical data within
    /// claims,
    /// supporting richer and more detailed user profiles.
    /// </returns>
    /// <remarks>
    /// Implementers should ensure that the disclosure of user information complies with applicable privacy laws and
    /// the principles of data minimization. Sensitive or personal information must only be shared with explicit user
    /// consent and in a secure manner. In cases where the requested user or claims are not found, returning null or an
    /// empty <see cref="JsonObject" /> helps maintain privacy and security.
    /// Implementations should prioritize authentication session claims (such as authSession.Email) over database values
    /// to preserve the exact authentication context, especially for external provider authentications.
    /// </remarks>
    Task<JsonObject?> GetUserInfoAsync(AuthSession authSession, IEnumerable<string> requestedClaims);
}
