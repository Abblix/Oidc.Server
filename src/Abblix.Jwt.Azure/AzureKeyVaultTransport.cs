// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Jwt.Azure;

/// <summary>
/// The HTTP transport the custodian's Key Vault calls travel on.
/// </summary>
public static class AzureKeyVaultTransport
{
    /// <summary>
    /// The name the transport's client is registered under, published so a host can configure it without copying
    /// the string: <c>services.AddHttpClient(AzureKeyVaultTransport.HttpClientName)</c> reaches the same client the
    /// custodian resolves.
    /// </summary>
    /// <remarks>
    /// The value is the client type's name because this is a typed client, and that is the logical name
    /// <c>AddHttpClient&lt;TClient&gt;</c> gives it. The credential authenticates over a transport of its own, so
    /// what a host chains here does not cover the token requests.
    /// </remarks>
    public const string HttpClientName = nameof(KeyVaultClient);
}
