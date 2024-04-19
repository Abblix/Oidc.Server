// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
//
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
//
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
//
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
//
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
//
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
//
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
