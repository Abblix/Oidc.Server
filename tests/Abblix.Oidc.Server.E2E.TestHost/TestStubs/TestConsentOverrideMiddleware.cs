// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using System.Text.Json.Nodes;

namespace Abblix.Oidc.Server.MinimalApi.E2E.TestHost;

/// <summary>
/// Test-only middleware that lifts a per-test consent override out of an HTTP request header
/// into <see cref="HttpContext.Items"/>, where <see cref="AutoConsentsProvider"/> reads it
/// via <see cref="IHttpContextAccessor"/>. Because the override travels with the request, no
/// static / <see cref="AsyncLocal{T}"/> propagation is needed across the WebApplicationFactory's
/// test-thread &lt;-&gt; request-thread boundary -- HttpContext is unambiguously per-request.
/// </summary>
/// <remarks>
/// Wire shape: the header value is either the JSON-serialised <c>authorization_details</c>
/// array the test wants the provider to "grant", or the literal string <c>"null"</c> to mean
/// "override is active but the granted AD is null" (i.e. provider has no AD opinion -- the
/// pipeline falls back to the request's value). Header absent means no override at all.
/// </remarks>
public sealed class TestConsentOverrideMiddleware(RequestDelegate next)
{
    /// <summary>HTTP header carrying the per-test override (JSON array or the literal string
    /// <c>"null"</c>).</summary>
    public const string HeaderName = "X-Test-Consent-Override-AuthorizationDetails";

    /// <summary><see cref="HttpContext.Items"/> key set when the override header is present.</summary>
    public const string PresenceItemKey = "test.consent-override.authorization-details.present";

    /// <summary><see cref="HttpContext.Items"/> key holding the parsed <see cref="JsonArray"/>
    /// (or <c>null</c> when the header value was <c>"null"</c>).</summary>
    public const string ValueItemKey = "test.consent-override.authorization-details.value";

    /// <summary>Sentinel header value for "override is active, granted AD is null".</summary>
    private const string NullSentinel = "null";

    public Task InvokeAsync(HttpContext context)
    {
        if (context.Request.Headers.TryGetValue(HeaderName, out var headerValue))
        {
            context.Items[PresenceItemKey] = true;
            var raw = headerValue.ToString();
            if (!string.Equals(raw, NullSentinel, StringComparison.Ordinal) && !string.IsNullOrEmpty(raw))
            {
                context.Items[ValueItemKey] = JsonNode.Parse(raw) as JsonArray;
            }
        }

        return next(context);
    }
}
