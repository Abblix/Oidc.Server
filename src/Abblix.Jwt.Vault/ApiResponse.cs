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

using System.Net;
using System.Text.Json;

namespace Abblix.Jwt.Vault;

/// <summary>
/// What Vault answered: the status, and the parsed body when there was one.
/// </summary>
/// <remarks>
/// The status is handed over rather than judged, because only the caller knows what it means: a 404 is a failure
/// to whoever reads a key and the expected answer to whoever lists a ring nobody has minted into yet, and a 400
/// is a lost race to one caller and a rejected ciphertext to another. What every caller does share is how to read
/// Vault's error text and how to phrase the failure, which is what this carries alongside.
/// </remarks>
/// <param name="Status">The HTTP status Vault answered with.</param>
/// <param name="Document">The parsed body, or null when Vault answered with none, as it does for a delete.</param>
internal sealed record ApiResponse(HttpStatusCode Status, JsonDocument? Document) : IDisposable
{
    /// <summary>Whether Vault answered with a success status.</summary>
    internal bool IsSuccess => Status is >= HttpStatusCode.OK and < HttpStatusCode.Ambiguous;

    /// <summary>Throws <see cref="Failure"/> unless Vault answered with a success status.</summary>
    /// <param name="path">The path that was called, named in the message.</param>
    internal void EnsureSuccess(string path)
    {
        if (!IsSuccess)
            throw Failure(path);
    }

    /// <summary>The body of a call that requires one.</summary>
    /// <param name="path">The path that was called, named in the message.</param>
    /// <exception cref="InvalidOperationException">Vault answered without a body where one was required.</exception>
    internal JsonDocument Body(string path)
        => Document ?? throw new InvalidOperationException($"Vault '{path}' answered {(int)Status} with no body.");

    /// <summary>
    /// Describes a failed call. The path carries the mount, so it names the engine without the message having to.
    /// </summary>
    /// <param name="path">The path that was called.</param>
    internal InvalidOperationException Failure(string path)
        => new($"Vault '{path}' failed with {(int)Status}: {Errors}");

    /// <summary>
    /// Vault's own error text, which is how some outcomes are told apart: a lost cas race and a malformed write
    /// share status 400 and differ only here.
    /// </summary>
    internal string Errors
        => Document?.RootElement.TryGetProperty("errors", out var errors) == true ? errors.ToString() : "(none)";

    /// <summary>
    /// Releases the body. JsonDocument rents its buffer from the shared pool and only returns it on dispose, so a
    /// response left undisposed leaks that buffer for good, and a failing Vault fails every call - the leak
    /// compounds exactly when the process can least afford it.
    /// </summary>
    public void Dispose() => Document?.Dispose();
}
