// Abblix OIDC Client Library
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

using System.Text.Json;
using Abblix.Oidc.Client.Features.Authorization.Context;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Client.AspNetCore;

/// <summary>
/// Keeps each pending login in a cookie on the browser that started it, so the login is bound to that
/// browser and to no other.
/// </summary>
/// <remarks>
/// This is the store the in-process default cannot be: it answers the user-agent binding RFC 9700
/// section 2.1.1 requires ("the PKCE challenge or OpenID Connect nonce MUST be transaction-specific and
/// securely bound to the client and the user agent in which the transaction was started"). The binding
/// is not a separate check bolted on - it is where the login lives. The whole context, including the
/// code verifier, rides in the cookie; the <c>state</c> value in the callback URL is only a name for
/// which cookie to read. An attacker who learns that value - it travels in the request URL to the
/// provider, so it is not a secret - still has nothing, because the cookie is <c>HttpOnly</c> and
/// same-origin and never left the victim's browser. There is no server-side entry to find, which also
/// makes the store correct across replicas: the context travels with the user, not with a node.
/// The cookie payload is encrypted with Data Protection because it carries the code verifier, and an
/// <c>HttpOnly</c> flag keeps script out but does nothing against a cookie read at rest.
/// </remarks>
/// <param name="httpContextAccessor">Reaches the request being handled, whose cookies this reads and writes.</param>
/// <param name="dataProtectionProvider">Encrypts the cookie payload so the verifier is not stored in the clear.</param>
/// <param name="options">Carries the lifetime that bounds how long a started login stays usable.</param>
internal sealed class CookieAuthorizationStateStore(
    IHttpContextAccessor httpContextAccessor,
    IDataProtectionProvider dataProtectionProvider,
    IOptions<AuthorizationStateOptions> options) : IAuthorizationStateStore
{
    // A distinct purpose string binds the protector to this use: a payload encrypted for the state cookie
    // cannot be unprotected by a protector created for anything else, so a value lifted from elsewhere in
    // the application does not decrypt here.
    private readonly IDataProtector _protector =
        dataProtectionProvider.CreateProtector("Abblix.Oidc.Client.AuthorizationState.v1");

    // Every pending login gets its own cookie, named for its state value, so several started at once (a
    // user with two tabs mid-login) do not overwrite each other. The state value is base64url, whose
    // alphabet is already cookie-name-safe.
    private const string CookieNamePrefix = ".Abblix.Oidc.Client.AuthorizationState.";

    public Task StoreAsync(AuthorizationContext context, CancellationToken cancellationToken = default)
    {
        var httpContext = RequireHttpContext();

        var protectedPayload = _protector.Protect(JsonSerializer.Serialize(context));

        httpContext.Response.Cookies.Append(CookieName(context.State), protectedPayload, CookieOptions());

        return Task.CompletedTask;
    }

    public Task<AuthorizationContext?> FindAsync(string state, CancellationToken cancellationToken = default)
    {
        var httpContext = RequireHttpContext();

        if (!httpContext.Request.Cookies.TryGetValue(CookieName(state), out var protectedPayload)
            || string.IsNullOrEmpty(protectedPayload))
        {
            return Task.FromResult<AuthorizationContext?>(null);
        }

        // Unprotect fails on a payload that was tampered with, encrypted for another purpose, or protected
        // by a key that has since been retired past its window. Any of those is a callback this login
        // cannot own, so it is a miss rather than an error - the same answer as no cookie at all.
        try
        {
            var context = JsonSerializer.Deserialize<AuthorizationContext>(_protector.Unprotect(protectedPayload));
            return Task.FromResult(context);
        }
        catch (Exception exception) when (exception is System.Security.Cryptography.CryptographicException or JsonException)
        {
            return Task.FromResult<AuthorizationContext?>(null);
        }
    }

    public Task<bool> RemoveAsync(string state, CancellationToken cancellationToken = default)
    {
        var httpContext = RequireHttpContext();

        var present = httpContext.Request.Cookies.ContainsKey(CookieName(state));

        // Deleting sets an already-expired cookie on the response, so the browser drops it and does not
        // present it on any later callback - the single-use spend, expressed in cookie terms. The delete
        // options must match how it was written, or the browser keeps the original alongside the deletion.
        httpContext.Response.Cookies.Delete(CookieName(state), CookieOptions());

        return Task.FromResult(present);
    }

    private HttpContext RequireHttpContext() =>
        httpContextAccessor.HttpContext
        ?? throw new InvalidOperationException(
            "The cookie-backed authorization state store needs an HTTP request in flight, and none is "
            + "current. It runs during the redirect to the provider and the callback back; a caller "
            + "outside a request should use the in-memory store instead.");

    private static string CookieName(string state) => CookieNamePrefix + state;

    private CookieOptions CookieOptions() => new()
    {
        // No script needs this cookie, and keeping script out is the point: an XSS foothold must not be
        // able to read the code verifier it carries.
        HttpOnly = true,

        // Only ever sent over TLS. The callback carries the code, and the cookie carries the verifier;
        // neither belongs on a plaintext connection (RFC 9700 section 2.6).
        Secure = true,

        // Lax, not None: the provider returns the user by a top-level GET navigation to the redirect
        // address, which Lax permits, so the cookie arrives on the callback without being sent on the
        // cross-site subrequests None would also allow. A response_mode of form_post would need None,
        // and this client does not use one.
        SameSite = SameSiteMode.Lax,

        // Bounded to the same window the login itself is, so an abandoned cookie does not outlive the
        // login it was for.
        MaxAge = options.Value.Lifetime,

        // Scoped to the application root; the callback address is served by this application.
        Path = "/",
    };
}
