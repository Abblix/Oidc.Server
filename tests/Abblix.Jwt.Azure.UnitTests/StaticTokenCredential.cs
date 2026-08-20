// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Azure.Core;

namespace Abblix.Jwt.Azure.UnitTests;

/// <summary>
/// Credential that returns a fixed token without any network call, so the Azure SDK's authentication pipeline
/// never reaches Entra ID during a test.
/// </summary>
internal sealed class StaticTokenCredential : TokenCredential
{
    public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
        => new("stub-token", DateTimeOffset.MaxValue);

    public override ValueTask<AccessToken> GetTokenAsync(
        TokenRequestContext requestContext, CancellationToken cancellationToken)
        => ValueTask.FromResult(GetToken(requestContext, cancellationToken));
}
