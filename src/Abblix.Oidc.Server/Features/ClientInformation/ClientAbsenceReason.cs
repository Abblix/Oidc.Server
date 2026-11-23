// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// Why a client identifier does not name a client the server serves.
/// </summary>
public enum ClientAbsenceReason
{
    /// <summary>
    /// No client is known under the identifier.
    /// </summary>
    Unknown,

    /// <summary>
    /// The identifier is a client identifier URL whose metadata document was had and refused
    /// (draft-ietf-oauth-client-id-metadata-document section 6.1): it is invalid, or the tenant does not accept the
    /// client it describes.
    /// </summary>
    Refused,

    /// <summary>
    /// The identifier is a client identifier URL whose metadata document could not be had for a reason that may pass,
    /// such as the network or a server error, and no valid copy of it is held.
    /// </summary>
    TemporarilyUnavailable,
}
