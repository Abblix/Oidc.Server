// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

#if !NET11_0_OR_GREATER

using System.ComponentModel.DataAnnotations;

namespace Abblix.Oidc.Server.MinimalApi.Filters;

/// <summary>
/// The asynchronous object validation of .NET 11 for .NET 10, whose base library has only the synchronous one. It
/// carries the name and the signature of the .NET 11 static method, so the caller is one code path: on .NET 11 the
/// type's own member wins and this file compiles to nothing.
/// </summary>
/// <remarks>
/// Synchronous underneath, which answers the same as the .NET 11 method for every attribute that validates
/// synchronously - and no request model this adapter binds carries any other kind.
/// </remarks>
internal static class ValidatorNet10
{
    extension(Validator)
    {
        /// <summary>
        /// Validates <paramref name="instance"/> as <see cref="Validator.TryValidateObject(object, ValidationContext,
        /// ICollection{ValidationResult}?, bool)"/> does.
        /// </summary>
        public static Task<bool> TryValidateObjectAsync(
            object instance,
            ValidationContext validationContext,
            ICollection<ValidationResult>? validationResults,
            bool validateAllProperties,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(
                Validator.TryValidateObject(instance, validationContext, validationResults, validateAllProperties));
        }
    }
}

#endif
