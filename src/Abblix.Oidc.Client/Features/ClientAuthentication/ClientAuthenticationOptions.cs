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


namespace Abblix.Oidc.Client.Features.ClientAuthentication;

/// <summary>
/// Configuration of how this client presents itself at the provider's authenticated endpoints.
/// </summary>
/// <remarks>
/// One configuration for every such endpoint, not one per endpoint. A client has a single identity and a
/// single set of credentials: RFC 7009 section 2.1 says a revocation request authenticates "as described in
/// Section 2.3 of [RFC6749]", the same section the token endpoint points at. Splitting the settings per
/// endpoint would invite a deployment where the token endpoint is authenticated and the revocation endpoint,
/// by omission, is not.
/// </remarks>
public sealed class ClientAuthenticationOptions
{
    /// <summary>
    /// How the client authenticates itself.
    /// </summary>
    /// <remarks>
    /// Required rather than defaulted. OAuth 2.0 for Browser-Based Applications puts a server-side client
    /// like this one in the Backend-For-Frontend role, where it is a confidential client - so quietly
    /// defaulting to <see cref="ClientAuthenticationMethods.None"/> would let a deployment end up public by
    /// omission, which is the one thing a default must never decide. Say which it is.
    /// </remarks>
    public required string Method { get; set; }

    /// <summary>
    /// The secret shared with the provider. Required by every method other than
    /// <see cref="ClientAuthenticationMethods.None"/>.
    /// </summary>
    /// <remarks>
    /// This belongs in a secret store, not in a configuration file committed anywhere. A client that keeps a
    /// secret somewhere the user can read it is not a confidential client, whatever it is configured as.
    /// </remarks>
    public string? ClientSecret { get; set; }
}
