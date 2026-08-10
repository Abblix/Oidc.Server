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

using Microsoft.Extensions.Http;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.SecureHttpFetch;

/// <summary>
/// Reports, once per handler build, a client that was registered with SSRF validation and no longer has it.
/// </summary>
/// <remarks>
/// The validation is a client's primary handler, so a host that sets its own primary handler on such a client
/// replaces it. That call is the ordinary way to configure a proxy, a client certificate or connection pooling,
/// which is exactly why the substitution deserves to be said out loud: the build stays green and the address of a
/// client-supplied endpoint stops being checked.
/// <para>
/// This is a report, not a veto. A deployment that made the swap deliberately silences this one message by its own
/// category, leaving every other log this library writes untouched:
/// <c>"Logging": { "LogLevel": { "Abblix.Oidc.Server.Features.SecureHttpFetch.SsrfGuardWatch": "None" } }</c>.
/// </para>
/// </remarks>
/// <param name="logger">Writes under this type's own category, which is what makes the message separately
/// silenceable.</param>
/// <param name="guardedClients">The clients registered through <c>AddSsrfHttpClient</c>.</param>
internal sealed partial class SsrfGuardWatch(
    ILogger<SsrfGuardWatch> logger,
    SsrfGuardedClients guardedClients) : IHttpMessageHandlerBuilderFilter
{
    /// <inheritdoc />
    public Action<HttpMessageHandlerBuilder> Configure(Action<HttpMessageHandlerBuilder> next)
        => builder =>
        {
            // Everything the library and the host asked for runs first, so the primary handler below is final.
            next(builder);

            if (builder.Name is { } name
                && guardedClients.Contains(name)
                && builder.PrimaryHandler is not SsrfValidatingHttpMessageHandler)
            {
                LogValidationReplaced(name, builder.PrimaryHandler?.GetType().Name ?? "none");
            }
        };
}
