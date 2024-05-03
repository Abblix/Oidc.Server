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
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Features.UserInfo;

/// <summary>
/// Defines an interface for retrieving user-specific claims based on authentication sessions and requested claims.
/// This interface plays a crucial role in authentication flows, where it extracts and formats user data for inclusion
/// in tokens or other authorization responses, ensuring compliance with specified scopes and claim requests.
/// </summary>
public interface IUserClaimsProvider
{
    /// <summary>
    /// Asynchronously retrieves structured user claims based on the provided authentication session, requested scopes,
    /// additional claim details, and client information. This method is crucial for generating claims that are to be
    /// embedded in identity tokens or provided through user info endpoints, allowing for a personalized and secure user
    /// experience based on the authenticated session and application requirements.
    /// </summary>
    /// <param name="authSession">The authentication session which includes details about the user's authentication
    /// state and may affect the resultant claims.</param>
    /// <param name="scope">A collection of scopes indicating which categories of claims are requested.
    /// Each scope can correlate to multiple claims, influencing the granularity and type of data returned.</param>
    /// <param name="requestedClaims">Additional details about specific claims requested, often providing finer control
    /// over the claims’ properties such as essentiality or value requirements, enhancing the flexibility and
    /// adaptiveness of claim retrieval.</param>
    /// <param name="clientInfo">Information about the client application making the request, which may influence
    /// the processing and filtering of claims based on client-specific settings or requirements.</param>
    /// <returns>A task that resolves to a <see cref="JsonObject"/> encapsulating the user claims in a structured JSON
    /// format suitable for further processing, or null if the necessary claims cannot be retrieved or are not
    /// applicable based on the session details.</returns>
    Task<JsonObject?> GetUserClaimsAsync(
        AuthSession authSession,
        ICollection<string> scope,
        ICollection<KeyValuePair<string, RequestedClaimDetails>>? requestedClaims,
        ClientInfo clientInfo);
}
