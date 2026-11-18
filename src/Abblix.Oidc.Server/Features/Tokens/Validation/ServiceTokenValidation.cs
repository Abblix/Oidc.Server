// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;

namespace Abblix.Oidc.Server.Features.Tokens.Validation;

/// <summary>
/// How the server checks a token it issued and reads back.
/// </summary>
internal static class ServiceTokenValidation
{
    /// <summary>
    /// Every check of a token this server issued, except that its audience names this server, for a reader whose
    /// token may be addressed to somebody else. Each reader says at its call why its token may be.
    /// </summary>
    /// <remarks>
    /// The issuer, the signature with the tenant's keys, the lifetime and the token's recorded status are checked as
    /// for any other token, so a token passing them is still one this server issued at this tenant.
    /// </remarks>
    public const ValidationOptions AnyAudience = ValidationOptions.Default & ~ValidationOptions.RequireValidAudience;
}
