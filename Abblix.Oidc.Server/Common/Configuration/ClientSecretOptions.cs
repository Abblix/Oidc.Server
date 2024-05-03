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

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Configuration options for generating client secrets in OAuth2/OpenID Connect authentication.
/// </summary>
public record ClientSecretOptions
{
    /// <summary>
    /// The length of the generated client secret.
    /// Specifies the number of characters in the secret. Default value is 16.
    /// </summary>
    public int Length { get; init; } = 16;

    /// <summary>
    /// The expiration duration for the client secret.
    /// Defines how long after creation the secret will remain valid.
    /// Default value is 30 days.
    /// </summary>
    public TimeSpan ExpiresAfter { get; init; } = TimeSpan.FromDays(30);
}
