// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common.Exceptions;

/// <summary>
/// Represents an exception that is thrown when an unexpected data type is encountered.
/// </summary>
/// <remarks>
/// This exception is typically used to indicate an unexpected or invalid type for a parameter or variable.
/// It provides information about the parameter name and the unexpected type encountered.
/// </remarks>
public class UnexpectedTypeException : InvalidOperationException
{
    /// <summary>
    /// Creates the exception with a message naming the offending parameter and the runtime type observed.
    /// </summary>
    /// <param name="paramName">Name of the variable, parameter, or member whose type was unexpected.</param>
    /// <param name="paramType">The runtime type that the calling code did not know how to handle.</param>
    public UnexpectedTypeException(string? paramName, Type paramType)
        : base($"Something goes wrong: {paramName} has unexpected type {paramType}")
    {
    }
}
