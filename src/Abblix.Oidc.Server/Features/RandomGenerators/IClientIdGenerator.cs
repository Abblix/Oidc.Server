// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
