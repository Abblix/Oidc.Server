// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Features.ClientInformation;

namespace Abblix.Oidc.Server.Features.Tokens.Validation;

/// <summary>
/// Represents a successfully validated client JWT with associated client information.
/// </summary>
/// <param name="Token">The validated JSON Web Token.</param>
/// <param name="Client">The client information associated with the token's issuer.</param>
public record ValidJsonWebToken(JsonWebToken Token, ClientInfo Client);
