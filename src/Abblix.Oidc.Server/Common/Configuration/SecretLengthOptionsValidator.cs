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

using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Fails loudly at startup when a configured secret-bearing length is below the security floor for
/// its kind, instead of silently generating a guessable client secret, authorization code or
/// identifier at runtime. Every shipped default is already at or above these floors, so a valid
/// configuration is unaffected; the validator only rejects a deliberately shortened value.
/// </summary>
public class SecretLengthOptionsValidator : IValidateOptions<OidcOptions>
{
    /// <summary>
    /// Minimum length, in characters, of a generated client secret. A client authenticating with
    /// <c>client_secret_jwt</c> (OpenID Connect Core §9) uses the secret's UTF-8 bytes as the HMAC
    /// key, and RFC 7518 §3.2 requires an HS256 key of at least 32 bytes; a shorter secret cannot
    /// serve that method at all.
    /// </summary>
    public const int MinimumClientSecretLength = 32;

    /// <summary>
    /// Minimum length, in characters, of an opaque random secret the server issues as a bearer value
    /// (authorization code, PAR request URI, session/token/grant identifier). Below this a random
    /// token becomes guessable; the value is a hard safety floor, well under every shipped default.
    /// </summary>
    public const int MinimumRandomSecretLength = 16;

    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        var failures = new List<string>();

        Check(failures, "NewClientOptions.ClientSecret.Length",
            options.NewClientOptions.ClientSecret.Length, MinimumClientSecretLength);

        Check(failures, nameof(options.AuthorizationCodeLength),
            options.AuthorizationCodeLength, MinimumRandomSecretLength);
        Check(failures, nameof(options.RequestUriLength),
            options.RequestUriLength, MinimumRandomSecretLength);
        Check(failures, nameof(options.SessionIdLength),
            options.SessionIdLength, MinimumRandomSecretLength);
        Check(failures, nameof(options.TokenIdLength),
            options.TokenIdLength, MinimumRandomSecretLength);
        Check(failures, nameof(options.GrantIdLength),
            options.GrantIdLength, MinimumRandomSecretLength);

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }

    private static void Check(List<string> failures, string optionName, int configuredLength, int minimumLength)
    {
        if (configuredLength < minimumLength)
        {
            failures.Add(
                $"{optionName} is {configuredLength}, below the minimum of {minimumLength} characters " +
                $"required for a secret of this kind.");
        }
    }
}
