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

namespace Abblix.Oidc.Server.Endpoints.Token.Interfaces;

/// <summary>
/// Identity of an issued token, recorded against an authorization grant so that the token can be
/// revoked by JTI if the grant is later invalidated (for example when an authorization code is reused).
/// </summary>
/// <param name="JwtId">The token's <c>jti</c> claim.</param>
/// <param name="ExpiresAt">When the token expires; used to expire the revocation record alongside the token itself.</param>
public record TokenInfo(string JwtId, DateTimeOffset ExpiresAt);
