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
/// Defines an interface responsible for generating secure client secrets for OpenID Connect (OIDC) clients.
/// Client secrets are used as credentials for client authentication to the OIDC provider or authorization server.
/// </summary>
public interface IClientSecretGenerator
{
    /// <summary>
    /// Generates a new, secure client secret string of the specified length. The generated secret is intended
    /// for use by confidential clients in OAuth 2.0 and OpenID Connect authentication flows. It is crucial
    /// that the generated secret is of sufficient length and randomness to ensure the security of client
    /// authentication processes.
    /// </summary>
    /// <param name="length">The desired length of the client secret. It is recommended that secrets be of
    /// sufficient length (e.g., at least 32 characters) to ensure adequate security against brute-force
    /// or guessing attacks.</param>
    /// <returns>A securely generated client secret string of the specified length. The secret should consist
    /// of a cryptographically strong, random sequence of characters that can include a mix of letters,
    /// digits, and special characters.</returns>
    string GenerateClientSecret(int length);
}
