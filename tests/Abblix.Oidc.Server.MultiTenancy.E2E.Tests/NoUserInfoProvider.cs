// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Features.UserInfo;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// The user store a host supplies, here knowing nobody: no request in these tests gets as far as a signed-in user.
/// </summary>
internal sealed class NoUserInfoProvider : IUserInfoProvider
{
    public Task<JsonObject?> GetUserInfoAsync(AuthSession authSession, IEnumerable<string> requestedClaims)
        => Task.FromResult<JsonObject?>(null);
}
