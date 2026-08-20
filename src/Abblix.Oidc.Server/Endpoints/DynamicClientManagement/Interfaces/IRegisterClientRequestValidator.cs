// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Utils;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;

/// <summary>
/// Validates client metadata supplied to the registration endpoint per RFC 7591 §2 and
/// OpenID Connect Dynamic Client Registration 1.0. Produces a typed
/// <see cref="ValidClientRegistrationRequest"/> on success or an <see cref="OidcError"/>
/// describing the rejected metadata field.
/// </summary>
public interface IRegisterClientRequestValidator
{
    /// <summary>
    /// Validates the request and returns either the typed valid form or the first error encountered.
    /// </summary>
    /// <param name="request">The raw registration request to validate.</param>
    Task<Result<ValidClientRegistrationRequest, OidcError>> ValidateAsync(ClientRegistrationRequest request);
}
