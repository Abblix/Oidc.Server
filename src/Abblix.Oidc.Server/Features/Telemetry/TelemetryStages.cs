// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <summary>
/// The stages of handling a request that run in spans of their own under the endpoint's span, and the values of
/// <see cref="TelemetryTags.Stage"/>.
/// </summary>
public static class TelemetryStages
{
    /// <summary>
    /// Checking the request before anything acts on it.
    /// </summary>
    public const string Validation = "validation";

    /// <summary>
    /// Acting on a validated request.
    /// </summary>
    public const string Processing = "processing";

    /// <summary>
    /// Minting the tokens a validated token request is answered with.
    /// </summary>
    public const string Issuance = "issuance";

    /// <summary>
    /// Telling which client sent the request from the credentials it presents.
    /// </summary>
    public const string ClientAuthentication = "client_authentication";

    /// <summary>
    /// Finding what a token request's grant authorizes.
    /// </summary>
    public const string Grant = "grant";

    /// <summary>
    /// Finding what the end user has consented to.
    /// </summary>
    public const string Consent = "consent";

    /// <summary>
    /// Signing a token.
    /// </summary>
    public const string Signing = "signing";

    /// <summary>
    /// Reading, writing or removing an entry of the server's storage.
    /// </summary>
    public const string Storage = "storage";
}
