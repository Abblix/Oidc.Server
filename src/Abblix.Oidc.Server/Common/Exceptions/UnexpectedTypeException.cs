// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
// 
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
// 
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
// 
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
// 
// For full licensing terms, please visit:
// 
// https://oidc.abblix.com/license
// 
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

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
