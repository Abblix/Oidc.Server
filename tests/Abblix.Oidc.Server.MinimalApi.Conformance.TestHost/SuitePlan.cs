// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.MinimalApi.Conformance.TestHost;

/// <summary>
/// One configuration the suite runs a FAPI or CIBA plan with: the pair of static clients it names, and how they
/// authenticate and hold their tokens, which the plan's variants have to match.
/// </summary>
/// <param name="Alias">The suite's alias for the configuration, which is also the path of the clients' redirect URI on
/// the suite and the name of the configuration file written for it.</param>
/// <param name="AuthenticatesByMutualTls">The clients authenticate by a self-signed certificate rather than a private
/// key JWT: the plan's <c>client_auth_type=mtls</c>.</param>
/// <param name="BindsTokensByMutualTls">Access tokens are bound to the client certificate rather than to a DPoP key:
/// the plan's <c>sender_constrain=mtls</c>, and every FAPI 1.0 and FAPI-CIBA plan.</param>
/// <param name="CibaDeliveryMode">The CIBA token delivery mode of the clients, or null for clients of the
/// authorization code flow.</param>
public sealed record SuitePlan(
    string Alias,
    bool AuthenticatesByMutualTls,
    bool BindsTokensByMutualTls,
    string? CibaDeliveryMode = null);
