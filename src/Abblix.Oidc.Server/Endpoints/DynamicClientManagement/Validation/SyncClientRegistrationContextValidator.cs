// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Convenience base for validation steps whose checks are purely in-memory: implements the
/// async contract by wrapping the synchronous <see cref="Validate"/> result in a completed task.
/// </summary>
public abstract class SyncClientRegistrationContextValidator : IClientRegistrationContextValidator
{
    /// <inheritdoc />
    public Task<OidcError?> ValidateAsync(ClientRegistrationValidationContext context)
        => Task.FromResult(Validate(context));

    /// <summary>
    /// Validates the slice of registration metadata this implementation owns.
    /// </summary>
    /// <param name="context">The shared validation context.</param>
    /// <returns>An <see cref="OidcError"/> describing the rejection, or <c>null</c> when valid.</returns>
    protected abstract OidcError? Validate(ClientRegistrationValidationContext context);
}
