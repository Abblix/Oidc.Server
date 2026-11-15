// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.Tokens.Formatters;

/// <summary>
/// Subtype of <see cref="OidcError"/> refusing a JWT the server cannot issue to a client, naming why, so that where it
/// is logged the causes are told apart: the client registered a signature algorithm its security profile does not
/// admit, or an encryption algorithm it publishes no key for, which is the client's configuration, or no signing key of
/// the tenant performs the algorithm, which is the server's. The client is answered with unauthorized_client either
/// way (RFC 6749 section 5.2), in each endpoint's own protocol.
/// </summary>
/// <param name="Cause">Why the JWT cannot be signed.</param>
/// <param name="ErrorDescription">The human-readable description.</param>
public sealed record ClientJwtRefusal(ClientJwtRefusalCause Cause, string ErrorDescription)
    : OidcError(ErrorCodes.UnauthorizedClient, ErrorDescription)
{
    /// <summary>
    /// The level the refusal is logged at where the JWT is refused: a warning where the client's registration or keys
    /// are what is wrong, an error where the tenant's signing keys are.
    /// </summary>
    internal LogLevel LogLevel => Cause switch
    {
        ClientJwtRefusalCause.AlgorithmOutsideProfile => LogLevel.Warning,
        ClientJwtRefusalCause.NoTenantSigningKey => LogLevel.Error,
        ClientJwtRefusalCause.NoClientEncryptionKey => LogLevel.Warning,
        _ => throw new ArgumentOutOfRangeException(nameof(Cause), Cause, "A refusal cause without a log level."),
    };
}
