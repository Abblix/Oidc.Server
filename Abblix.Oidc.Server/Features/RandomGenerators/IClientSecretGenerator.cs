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
