// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Features.UserInfo;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// The user store a host supplies, knowing the one user <see cref="SignedInUser"/> signs in, by its subject alone.
/// </summary>
internal sealed class SignedInUserInfo : IUserInfoProvider
{
    public Task<JsonObject?> GetUserInfoAsync(AuthSession authSession, IEnumerable<string> requestedClaims)
        => Task.FromResult<JsonObject?>(new JsonObject { [IanaClaimTypes.Sub] = authSession.Subject });
}
