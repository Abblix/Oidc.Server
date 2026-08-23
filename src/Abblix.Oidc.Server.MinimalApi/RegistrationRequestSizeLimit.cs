// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http.Metadata;

namespace Abblix.Oidc.Server.MinimalApi;

/// <summary>
/// Bounds a request body at <see cref="OidcOptions.MaxRegistrationRequestSize"/>, as endpoint metadata the
/// server reads before it reads the body.
/// </summary>
/// <remarks>
/// The registration and update endpoints parse a foreign document and keep the members they do not model,
/// which costs several times the body's own size in memory. Model binding runs ahead of every validator,
/// including the initial access token check and the registration access token check, so nothing inside the
/// pipeline is early enough to bound it - and an endpoint filter, which runs after binding, would refuse a
/// request whose cost has already been paid. Metadata is the one hook the server consults first.
/// </remarks>
/// <param name="MaxRequestBodySize">The largest body the server will read, in bytes.</param>
internal sealed record RegistrationRequestSizeLimit(long? MaxRequestBodySize) : IRequestSizeLimitMetadata;

/// <summary>
/// Attaches a body bound to an endpoint, or leaves it to whatever already bounds it.
/// </summary>
internal static class RequestSizeLimitExtensions
{
    /// <summary>
    /// Declares <paramref name="maxRequestBodySize"/> as this endpoint's body bound; a cleared value attaches
    /// nothing.
    /// </summary>
    /// <remarks>
    /// The absence matters and is the whole reason this method exists. A null carried IN the metadata is not
    /// "no bound of ours" - it is the value <c>DisableRequestSizeLimitAttribute</c> uses to switch the bound
    /// off, because the routing middleware writes whatever the metadata says onto
    /// <c>IHttpMaxRequestBodySizeFeature</c>, and a null there means unlimited. Attaching it would therefore
    /// remove the server's own default (Kestrel's is 30,000,000 bytes) on exactly the endpoint that most
    /// needs one, while reading in configuration as the safest possible setting. Measured on Kestrel: an
    /// endpoint with no metadata refuses a 40 MB body with 413, the same endpoint carrying null-valued
    /// metadata accepts it and reads all of it.
    /// </remarks>
    /// <param name="builder">The endpoint being mapped.</param>
    /// <param name="maxRequestBodySize">The bound in bytes, or <c>null</c> to attach none.</param>
    /// <returns>The same builder, for chaining.</returns>
    public static RouteHandlerBuilder BoundBy(this RouteHandlerBuilder builder, long? maxRequestBodySize)
        => maxRequestBodySize is { } bytes
            ? builder.WithMetadata(new RegistrationRequestSizeLimit(bytes))
            : builder;
}
