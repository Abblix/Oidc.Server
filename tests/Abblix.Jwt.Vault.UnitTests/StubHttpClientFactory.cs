// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Jwt.Vault.UnitTests;

/// <summary>
/// Hands every caller the same client, the one wired over a stub transport. It stands in for the real factory,
/// whose only job the engines rely on is to resolve the named client.
/// </summary>
internal sealed class StubHttpClientFactory(HttpClient httpClient) : IHttpClientFactory
{
    public HttpClient CreateClient(string name) => httpClient;
}
