// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;

namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;

/// <summary>
/// Defines a contract for validating the context of a backchannel authentication request.
/// Implementations of this interface are responsible for ensuring that the backchannel authentication request
/// meets all necessary validation criteria based on the context, which may include client information,
/// requested scopes, and other parameters.
/// </summary>
public interface IBackChannelAuthenticationContextValidator
{
    /// <summary>
    /// Asynchronously validates the backchannel authentication request context.
    /// This method checks the context of the request, including client information and requested parameters,
    /// to ensure compliance with security and protocol requirements.
    /// </summary>
    /// <param name="context">The context of the backchannel authentication request that needs to be validated.</param>
    /// <returns>
    /// A task that represents the asynchronous validation operation. The task result contains
    /// a <see cref="OidcError"/> if validation fails, or null if the context is valid.
    /// </returns>
    Task<OidcError?> ValidateAsync(BackChannelAuthenticationValidationContext context);
}
