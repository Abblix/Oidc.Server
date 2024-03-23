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

namespace Abblix.Oidc.Server.Features.RandomGenerators;

/// <summary>
/// Defines an interface for generating client IDs for OpenID Connect (OIDC) clients.
/// This interface abstracts the mechanism for creating unique client identifiers used in the registration
/// of OIDC clients. Implementations of this interface can provide different strategies for generating client IDs,
/// such as UUIDs, random strings, or based on specific patterns.
/// </summary>
public interface IClientIdGenerator
{
    /// <summary>
    /// Generates a new, unique client ID. This client ID is intended for use in identifying an OIDC client
    /// within an authorization server or OIDC provider. The format and uniqueness constraints of the client ID
    /// can vary depending on the implementation.
    /// </summary>
    /// <returns>A string representing the generated client ID, which should be unique across all clients
    /// within the authorization server's context.</returns>
    string GenerateClientId();
}
