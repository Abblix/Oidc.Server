// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.UserAuthentication;

namespace Abblix.Oidc.Server.Features.UserInteraction;

/// <summary>
/// The registration a host without steps of its own keeps: no end user is ever required to complete one.
/// </summary>
public sealed class NoUserInteractionRequirement : IUserInteractionRequirement
{
    /// <inheritdoc />
    public Task<bool> IsRequiredAsync(ValidAuthorizationRequest request, AuthSession authSession)
        => Task.FromResult(false);
}
