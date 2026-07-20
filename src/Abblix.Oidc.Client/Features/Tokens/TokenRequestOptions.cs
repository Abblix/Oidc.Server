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


namespace Abblix.Oidc.Client.Features.Tokens;

/// <summary>
/// Configuration of how this client presents itself at the token endpoint.
/// </summary>
public sealed class TokenRequestOptions
{
    /// <summary>
    /// How the client authenticates itself.
    /// </summary>
    /// <remarks>
    /// Defaults to <see cref="ClientAuthenticationMethods.None"/>, the public-client case, because that is
    /// the one where getting it wrong is harmless: a client with no secret cannot leak one. A confidential
    /// client says so, and supplies <see cref="ClientSecret"/>.
    /// </remarks>
    public string ClientAuthenticationMethod { get; set; } = ClientAuthenticationMethods.None;

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
