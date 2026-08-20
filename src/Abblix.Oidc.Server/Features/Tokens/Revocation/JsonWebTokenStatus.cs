// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Tokens.Revocation;

/// <summary>
/// Defines the possible states of a JSON Web Token within the system.
/// </summary>
public enum JsonWebTokenStatus
{
    /// <summary>
    /// Indicates that the status of the token is not known.
    /// This may be used as a default value when the token's status has not been explicitly set or determined.
    /// </summary>
    Unknown,

    /// <summary>
    /// Indicates that the token has been used.
    /// This status can be used to mark tokens that have been consumed in a process, such as authorization codes that have been exchanged for access tokens.
    /// </summary>
    Used,

    /// <summary>
    /// Indicates that the token has been revoked.
    /// A revoked token is no longer valid for use and should be rejected in any validation checks.
    /// This status is typically set when a user or system administrator manually invalidates a token.
    /// </summary>
    Revoked,
}
