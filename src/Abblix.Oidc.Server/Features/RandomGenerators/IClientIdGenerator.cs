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
