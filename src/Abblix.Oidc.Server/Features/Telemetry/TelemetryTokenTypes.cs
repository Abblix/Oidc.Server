// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <summary>
/// The values of <see cref="TelemetryTags.TokenType"/>: the response parameter a token is handed out in.
/// </summary>
public static class TelemetryTokenTypes
{
    /// <summary>
    /// An access token.
    /// </summary>
    public const string AccessToken = "access_token";

    /// <summary>
    /// An ID token.
    /// </summary>
    public const string IdToken = "id_token";

    /// <summary>
    /// A refresh token.
    /// </summary>
    public const string RefreshToken = "refresh_token";
}
