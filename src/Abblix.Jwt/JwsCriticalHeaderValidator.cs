// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Jwt;

/// <summary>
/// The 'crit' link of the JWS validation chain (RFC 7515 section 4.1.11).
/// </summary>
/// <param name="serviceProvider">Resolves the registered <see cref="ICriticalHeaderHandler"/> for each listed
/// name, keyed by that name.</param>
internal sealed class JwsCriticalHeaderValidator(IServiceProvider serviceProvider)
{
    /// <summary>
    /// Validates the JWS 'crit' header parameter (RFC 7515 section 4.1.11). Runs the spec-required
    /// malformation guards (empty array, duplicates, reserved names, dangling references)
    /// independent of any registry, then routes each crit name to its registered
    /// <see cref="ICriticalHeaderHandler"/>. An unrouted name is rejected as «unknown
    /// critical header parameter» per RFC 7515 section 4.1.11 ("If any of the listed extension
    /// Header Parameters are not understood and supported by the recipient, then the JWS
    /// is invalid").
    /// </summary>
    public async Task<Result<JsonWebToken, JwtValidationError>> ValidateAsync(
        JsonWebToken token,
        ValidationParameters parameters)
    {
        var structuralError = CriticalHeaderValidation.ValidateStructure(
            token.Header, CriticalHeaderValidation.JwsReservedNames, out var crit);

        if (structuralError is not null)
            return structuralError;

        // No 'crit' at all is the ordinary case and needs no handler pass.
        if (crit is null)
            return token;

        return await DispatchCritHandlersAsync(token, parameters, crit);
    }

    /// <summary>
    /// Resolves the registered handler for each crit-listed name (keyed by name in DI) and
    /// runs them in declaration order. Every name is resolved BEFORE any handler runs: per
    /// RFC 7515 section 4.1.11 an unknown name invalidates the whole JWS, so an earlier extension's
    /// side effects must never apply only to reject on a later unknown name. An unresolved
    /// name is rejected as «unknown critical header parameter».
    /// </summary>
    private async Task<Result<JsonWebToken, JwtValidationError>> DispatchCritHandlersAsync(
        JsonWebToken token,
        ValidationParameters parameters,
        IReadOnlyList<string> crit)
    {
        var handlers = new ICriticalHeaderHandler[crit.Count];
        for (var i = 0; i < crit.Count; i++)
        {
            if (serviceProvider.GetKeyedService<ICriticalHeaderHandler>(crit[i]) is not { } handler)
            {
                return new JwtValidationError(
                    JwtError.InvalidHeader,
                    $"Unknown critical header parameter: {crit[i]}");
            }

            handlers[i] = handler;
        }

        var context = new CriticalHeaderContext
        {
            Token = token,
            Parameters = parameters,
        };

        // The JWS validation pipeline does not thread a CancellationToken (see
        // IJsonWebTokenValidator.ValidateAsync), so none is available to propagate here.
        var error = await handlers.FirstOrDefaultAsync(
            handler => handler.HandleAsync(context, CancellationToken.None));
        if (error is not null)
            return error;

        return token;
    }
}
