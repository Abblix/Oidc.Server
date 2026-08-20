// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.EndSession;

/// <summary>
/// Default <see cref="IEndSessionHandler"/> implementation. Delegates validation to
/// <see cref="IEndSessionRequestValidator"/>, then forwards a successful
/// <see cref="Interfaces.ValidEndSessionRequest"/> to <see cref="IEndSessionRequestProcessor"/>;
/// validation failures short-circuit and are returned as-is.
/// </summary>
public class EndSessionHandler(
    IEndSessionRequestValidator validator,
    IEndSessionRequestProcessor processor) : IEndSessionHandler
{
    /// <inheritdoc />
    public async Task<Result<EndSessionSuccess, OidcError>> HandleAsync(Model.EndSessionRequest endSessionRequest)
    {
        var validationResult = await validator.ValidateAsync(endSessionRequest);
        return await validationResult.BindAsync(processor.ProcessAsync);
    }
}
