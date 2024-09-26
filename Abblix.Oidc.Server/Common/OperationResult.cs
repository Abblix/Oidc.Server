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

using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Common;

/// <summary>
/// Represents the result of an operation that can either be successful, returning a value of type
/// <typeparamref name="T"/>, or result in an error with an error code and description.
/// </summary>
/// <typeparam name="T">The type of the value returned in case of a successful result.</typeparam>
public abstract record OperationResult<T>
{
    private OperationResult() { }

    /// <summary>
    /// Represents a successful result containing a value of type <typeparamref name="T"/>.
    /// </summary>
    /// <param name="Value">The value returned by the successful operation.</param>
    public sealed record Success(T Value) : OperationResult<T>
    {
        /// <summary>
        /// Returns a string that represents the current object, either the successful value or an error description.
        /// </summary>
        /// <returns>
        /// A string representation of the result, displaying the value in case of success,
        /// or an error message in case of failure.
        /// </returns>
        public override string ToString() => Value?.ToString() ?? string.Empty;
    }

    /// <summary>
    /// Represents an error result containing an error code and a descriptive message.
    /// </summary>
    /// <param name="ErrorCode">The code representing the type or cause of the error.</param>
    /// <param name="ErrorDescription">A human-readable description of the error.</param>
    public sealed record Error(string ErrorCode, string ErrorDescription) : OperationResult<T>
    {
        /// <summary>
        /// Returns a string that represents the current object, either the successful value or an error description.
        /// </summary>
        /// <returns>
        /// A string representation of the result, displaying the value in case of success,
        /// or an error message in case of failure.
        /// </returns>
        public override string ToString()
            => $"{nameof(ErrorCode)}: {ErrorCode}, {nameof(ErrorDescription)}: {ErrorDescription}";
    }

    /// <summary>
    /// Implicitly converts a value of type <typeparamref name="T"/> into a successful <see cref="Success"/> result.
    /// </summary>
    /// <param name="value">The value to be wrapped as a successful result.</param>
    public static implicit operator OperationResult<T>(T value) => new Success(value);

    /// <summary>
    /// Implicitly converts an <see cref="ErrorResponse"/> into an <see cref="Error"/> result.
    /// </summary>
    /// <param name="error">The error response to be wrapped as an error result.</param>
    public static implicit operator OperationResult<T>(ErrorResponse error)
        => new Error(error.Error, error.ErrorDescription);
}
