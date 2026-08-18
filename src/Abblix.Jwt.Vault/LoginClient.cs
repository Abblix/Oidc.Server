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
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Jwt.Vault;

/// <summary>
/// Logs in to Vault with the configured auth method and renews the resulting token, translating each call
/// into a verdict rather than an exception: to the lifecycle loop a refusal and a network error are answers
/// that pick the next step, not faults.
/// </summary>
/// <remarks>
/// The client goes through the same named <see cref="IHttpClientFactory"/> client as everything else in this
/// package, so a host's TLS, proxy and resilience configuration covers the login too - a bare client would
/// silently bypass exactly the settings that matter most on the connection carrying credentials. Login paths
/// are unauthenticated in Vault, and the request is marked so it does not wait for the token it is about to
/// produce. Authentication options are re-read on every call: the kubelet rotates the projected
/// service-account token underneath the file, and an AppRole secret can arrive rotated through configuration
/// reload.
/// </remarks>
internal sealed partial class LoginClient(
    ILogger<LoginClient> logger,
    IHttpClientFactory httpClientFactory,
    IOptionsMonitor<VaultTransitOptions> options)
{
    /// <summary>
    /// Logs in with the configured method. Null means the attempt failed - refused by Vault or lost to the
    /// network - and the caller retries with backoff; the reason is already logged with Vault's own words.
    /// </summary>
    public async Task<TokenLease?> LoginAsync(CancellationToken cancellationToken)
    {
        var authentication = options.CurrentValue.Authentication;

        var path = "auth/login";
        try
        {
            object body;
            switch (authentication)
            {
                case { Kubernetes: { } kubernetes }:
                    path = $"auth/{kubernetes.Mount.Trim('/')}/login";
                    body = new KubernetesLoginRequest
                    {
                        Role = kubernetes.Role ?? throw MisconfiguredAuthentication(nameof(kubernetes.Role)),

                        // Read inside the try: a missing or unreadable projected file is a failure to retry,
                        // not an exception to escape. Trimmed because the file routinely ends with a newline,
                        // which would travel into the JSON string and make Vault reject a valid token.
                        Jwt = (await File.ReadAllTextAsync(kubernetes.ServiceAccountTokenPath, cancellationToken))
                            .Trim(),
                    };
                    break;

                case { AppRole: { } appRole }:
                    path = $"auth/{appRole.Mount.Trim('/')}/login";
                    body = new AppRoleLoginRequest
                    {
                        RoleId = appRole.RoleId ?? throw MisconfiguredAuthentication(nameof(appRole.RoleId)),
                        SecretId = appRole.SecretId ?? throw MisconfiguredAuthentication(nameof(appRole.SecretId)),
                    };
                    break;

                default:
                    // The lifecycle service only runs when the section is present, and startup validation
                    // requires exactly one populated method, so this is unreachable short of a torn
                    // configuration reload - and the service's own backstop turns even that into a retry.
                    throw MisconfiguredAuthentication(nameof(VaultTransitOptions.Authentication));
            }

            // A retried login that succeeded but lost its response mints an orphan token; it idles out at its
            // TTL and costs nothing, so nothing here tries to prevent or clean it up.
            using var response = await HttpClient().SendAnonymousAsync(HttpMethod.Post, path, body, cancellationToken);
            if (!response.IsSuccess)
            {
                LogLoginRefused(path, (int)response.Status, response.Errors);
                return null;
            }

            var lease = ParseLease(response, path);
            if (lease is not null)
                LogLoggedIn(path, lease.LeaseDuration, lease.Renewable);
            return lease;
        }
        catch (Exception exception) when (IsRecoverableFailure(exception, cancellationToken))
        {
            LogLoginUnreachable(path, exception);
            return null;
        }
    }

    /// <summary>
    /// Renews the current token's lease. The token itself travels on the request like on any other call, so
    /// what is renewed is always the token currently presented.
    /// </summary>
    public async Task<RenewResult> RenewSelfAsync(CancellationToken cancellationToken)
    {
        const string path = "auth/token/renew-self";
        try
        {
            using var response = await HttpClient().SendAsync(HttpMethod.Post, path, null, cancellationToken);
            switch (response)
            {
                // Vault answers permission denied both for a token that cannot renew itself and for one already
                // gone; either way asking again is pointless and the caller switches to clock-watching. The
                // status stands in for the "permission denied" message match Vault's own watcher performs: a 403
                // minted by an intermediary lands here too, and the consequence is benign - the clock-watching
                // branch still logs in again before the lease ends.
                case { Status: HttpStatusCode.Forbidden }:
                    LogRenewDenied(response.Errors);
                    return new RenewResult(RenewStatus.PermissionDenied, null);

                case { IsSuccess: false }:
                    LogRenewFailed((int)response.Status, response.Errors);
                    return new RenewResult(RenewStatus.Failed, null);

                default:
                    var lease = ParseLease(response, path);
                    if (lease is null)
                        return new RenewResult(RenewStatus.Failed, null);

                    LogRenewed(lease.LeaseDuration);
                    return new RenewResult(RenewStatus.Renewed, lease);
            }
        }
        catch (Exception exception) when (IsRecoverableFailure(exception, cancellationToken))
        {
            LogRenewUnreachable(exception);
            return new RenewResult(RenewStatus.Failed, null);
        }
    }

    private HttpClient HttpClient() => httpClientFactory.CreateClient(VaultTransport.HttpClientName);

    /// <summary>
    /// A failure that retrying can cure, as opposed to an answer from Vault: a connection error, the
    /// client's own timeout - which surfaces as cancellation without the caller's token being cancelled -
    /// or a credential file that cannot be read right now.
    /// </summary>
    private static bool IsRecoverableFailure(Exception exception, CancellationToken cancellationToken)
        => exception switch
        {
            HttpRequestException => true,
            IOException => true,
            OperationCanceledException => !cancellationToken.IsCancellationRequested,
            _ => false,
        };

    private TokenLease? ParseLease(ApiResponse response, string path)
    {
        // Shape-checked rather than read with throwing accessors: an answer of the wrong shape is a
        // verdict for the retry loop, never an exception escaping it.
        if (response.Document is not { } document ||
            !document.RootElement.TryGetProperty("auth", out var auth) ||
            auth.ValueKind is not JsonValueKind.Object ||
            !auth.TryGetProperty("client_token", out var token) ||
            token.ValueKind is not JsonValueKind.String ||
            token.GetString() is not { Length: > 0 } clientToken)
        {
            LogMalformedAuthResponse(path);
            return null;
        }

        var leaseSeconds =
            auth.TryGetProperty("lease_duration", out var lease) &&
            lease.ValueKind is JsonValueKind.Number &&
            lease.TryGetInt64(out var seconds)
                ? seconds
                : 0;
        var renewable = auth.TryGetProperty("renewable", out var flag) && flag.ValueKind is JsonValueKind.True;
        return new TokenLease(clientToken, TimeSpan.FromSeconds(leaseSeconds), renewable);
    }

    private static InvalidOperationException MisconfiguredAuthentication(string memberName)
        => new($"Vault authentication is configured without '{memberName}', which startup validation refuses - " +
               $"reaching this point means the configuration changed shape after startup.");
}
