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


namespace Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;

/// <summary>
/// Provides functionality to retrieve user information as JWT claims, supporting both simple and structured claim values.
/// This interface enables the dynamic extraction and packaging of user attributes into JWT claims, accommodating a variety
/// of claim types including those that require complex, structured data beyond traditional scalar values.
/// </summary>
public interface IUserInfoProvider
{
    /// <summary>
    /// Asynchronously retrieves a set of user claims for a specified subject identifier, including both simple and
    /// structured claim values as requested by the client application. This method supports the OpenID Connect
    /// specification by allowing for the selective disclosure of user information, catering to the need for complex
    /// data structures within claims.
    /// </summary>
    /// <param name="subject">The unique subject identifier (sub claim) of the user whose information is being requested.
    /// This identifier must uniquely identify the user across all applications and services.</param>
    /// <param name="requestedClaims">A collection of names representing the claims requested by a client application.
    /// Implementations should check against this list to return only those claims that are requested and authorized
    /// for release, including both scalar values and structured data as necessary.</param>
    /// <returns>
    /// A task that resolves to a <see cref="JsonObject"/>, encapsulating the user's claims where each entry consists of
    /// a claim name and its value. The value can be a simple scalar value (e.g., a string or number) or a structured
    /// object, allowing for complex data types to be represented. Returns null if no information is available for the
    /// given subject. The use of <see cref="JsonObject"/> facilitates the representation of hierarchical data within claims,
    /// supporting richer and more detailed user profiles.
    /// </returns>
    /// <remarks>
    /// Implementers should ensure that the disclosure of user information complies with applicable privacy laws and
    /// the principles of data minimization. Sensitive or personal information must only be shared with explicit user
    /// consent and in a secure manner. In cases where the requested user or claims are not found, returning null or an
    /// empty <see cref="JsonObject"/> helps maintain privacy and security.
    /// </remarks>
    Task<JsonObject?> GetUserInfoAsync(string subject, IEnumerable<string> requestedClaims);
}
