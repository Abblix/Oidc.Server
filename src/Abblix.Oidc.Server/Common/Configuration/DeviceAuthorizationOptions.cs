// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Provides configuration options for the Device Authorization Grant (RFC 8628).
/// </summary>
public record DeviceAuthorizationOptions
{
    /// <summary>
    /// The lifetime of device_code and user_code. After this duration, the codes expire
    /// and the client must start a new device authorization request.
    /// </summary>
    public required TimeSpan CodeLifetime { get; set; }

    /// <summary>
    /// The minimum interval that the client should wait between polling requests to the token endpoint.
    /// </summary>
    public required TimeSpan PollingInterval { get; set; }

    /// <summary>
    /// The minimum device code length in bytes (128 bits). The device code is never displayed to
    /// the user, so it carries no usability constraint and RFC 8628 Section 5.2 asks for very high
    /// entropy; 128 bits is the conventional cryptographic floor for a non-guessable random value.
    /// </summary>
    private const int MinDeviceCodeLengthBytes = 16;

    private int _deviceCodeLength;

    /// <summary>
    /// The length in bytes of the device code. The device code is a high-entropy string
    /// used by the client to poll the token endpoint. Must be at least 128 bits (16 bytes)
    /// of entropy per RFC 8628 Section 5.2.
    /// </summary>
    public required int DeviceCodeLength
    {
        get => _deviceCodeLength;
        set
        {
            if (value < MinDeviceCodeLengthBytes)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(DeviceCodeLength),
                    value,
                    $"The device_code MUST contain very high entropy per RFC 8628 Section 5.2; " +
                    $"the length must be at least {MinDeviceCodeLengthBytes} bytes (128 bits).");
            }
            _deviceCodeLength = value;
        }
    }

    /// <summary>
    /// The length of the user code (number of characters).
    /// </summary>
    public required int UserCodeLength { get; set; }

    /// <summary>
    /// The alphabet used to generate user codes.
    /// Defaults to numeric digits "0123456789" for universal device compatibility.
    /// Can be set to letters like "BCDFGHJKLMNPQRSTVWXZ" (consonants without ambiguous characters)
    /// or alphanumeric like "BCDFGHJKLMNPQRSTVWXZ23456789".
    /// </summary>
    /// <remarks>
    /// <para>
    /// This and <see cref="UserCodeLength"/> decide how hard the code is to guess, and the rate limits
    /// decide how many guesses anyone gets. Both halves are needed, so here is the arithmetic rather than
    /// a recommendation: a code drawn from an alphabet of <c>A</c> symbols at length <c>L</c> is one of
    /// <c>A^L</c>, so the chance of landing it in <c>N</c> guesses is <c>N / A^L</c>.
    /// </para>
    /// <para>
    /// RFC 8628 section 5.1 works the same sum the other way round: it takes an 8-character code over a
    /// 20-symbol alphabet and says "the rate-limiting interval and validity period would need to only
    /// allow 5 attempts in order to get the same 2^-32 probability of success by random guessing" - five
    /// over the code's whole life, not five per interval. Put in those terms, the number of guesses a
    /// configuration can afford at that same probability is <c>A^L / 2^32</c>:
    /// </para>
    /// <para>
    /// Here <c>N</c> is <see cref="MaxUserCodeAttempts"/>, because that is the number of guesses a code
    /// gets before it stops being verifiable - the growing pause decides how long they take, not how many
    /// there are. With that number at 5:
    /// </para>
    /// <list type="bullet">
    ///   <item>8 digits: 5 in 100 million, about 1 in 20 million.</item>
    ///   <item>6 digits: 5 in a million, about 1 in 200 thousand - which is why a code this short needs a
    ///   short life as well.</item>
    ///   <item>8 symbols of "BCDFGHJKLMNPQRSTVWXZ": 5 in 25.6 billion, which is the example's own
    ///   2^-32.</item>
    ///   <item>8 symbols of "BCDFGHJKLMNPQRSTVWXZ23456789": 5 in 377 billion.</item>
    /// </list>
    /// <para>
    /// Both halves move the same sum, and they cost different people: a longer or wider code is work for
    /// everyone who types one, while a smaller number of attempts is only felt by somebody who mistypes
    /// that many times and has to start the flow again. That is the trade to make deliberately, and it is
    /// why neither number is refused at startup for being weak - only for being impossible.
    /// </para>
    /// </remarks>
    public string UserCodeAlphabet { get; set; } = "0123456789";

    private Uri? _verificationUri;

    /// <summary>
    /// The user-facing URI where users can enter their user code.
    /// This should be short and easy to remember as users will manually type it.
    /// Must use HTTPS. RFC 8628 does not say so for verification_uri; the requirement is RFC 6749
    /// Section 3.1's, which asks for TLS wherever the user authenticates.
    /// </summary>
    public required Uri VerificationUri
    {
        // `required` is a compiler obligation on an object initialiser and nothing more: the configuration
        // binder does not honour it, and for an absent reference-typed member it never calls the setter at
        // all. A host binding a partial DeviceAuthorization section therefore reaches here with nothing set,
        // and handing that null onwards produced an ArgumentNullException from a URI builder on every device
        // authorization request - pointing at the plumbing rather than at the setting that was missed.
        get => _verificationUri ?? throw new InvalidOperationException(
            $"{nameof(VerificationUri)} is not configured. The device authorization endpoint cannot state "
            + "where the user should enter their code, which RFC 8628 section 3.2 makes a required member "
            + "of the response.");
        set
        {
            if (!string.Equals(value.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException(
                    "The verification_uri must use HTTPS: the user authenticates there, and RFC 6749 "
                    + "Section 3.1 requires TLS for that",
                    nameof(VerificationUri));
            }
            _verificationUri = value;
        }
    }

    /// <summary>
    /// The maximum number of failed user code verification attempts before exponential backoff is applied.
    /// RFC 8628 Section 5.1 recommends rate-limiting user code attempts, the user code being short
    /// enough to type and therefore short enough to guess.
    /// </summary>
    public int MaxFailuresBeforeBackoff { get; set; } = 3;

    /// <summary>
    /// How many failed attempts one user code allows before it stops being verifiable at all.
    /// </summary>
    /// <remarks>
    /// This is what stops one code being worked at, from one source or from a thousand: the attempts belong
    /// to the code, not to whoever made them. Reaching the number leaves that code refused for as long as
    /// its records stand, and the person starts again with a fresh one.
    /// <para>
    /// It does NOT bound a search through the space of codes, and no per-code number can: a guesser submits
    /// a different value every time, so each value it tries is a code the server never issued and has its
    /// own untouched allowance. What bounds the search is
    /// <see cref="MaxFailedAttemptsPerWindow"/> together with the code's own strength - see
    /// <see cref="UserCodeAlphabet"/> for that arithmetic.
    /// </para>
    /// <para>
    /// The cost of a small value is a person who mistypes a live code that many times starting over. Five
    /// is the number RFC 8628 section 5.1 uses in its worked example.
    /// </para>
    /// </remarks>
    public int MaxUserCodeAttempts { get; set; } = 5;

    /// <summary>
    /// How many failed verification attempts the server entertains in one counting window, across every
    /// code and every source.
    /// </summary>
    /// <remarks>
    /// The per-code and per-address limits both bound something an attacker controls: a guesser never
    /// submits the same string twice, and one that rotates addresses is not bounded by either. This is
    /// what bounds the rate of the search itself, and the only thing that does.
    /// <para>
    /// It is an emergency brake rather than a routine limit, so it belongs well above the failures a
    /// healthy deployment produces - those are typos, a few per minute at most. While it is held, a person
    /// who mistypes is refused too: that is the cost of the brake, and it is why the number is generous
    /// rather than tight. What decides the chance of a guess landing is the code's own strength, for which
    /// see <see cref="UserCodeAlphabet"/>.
    /// </para>
    /// </remarks>
    public int MaxFailedAttemptsPerWindow { get; set; } = 100;

    /// <summary>
    /// The maximum number of failed user code verification attempts allowed from a single IP address
    /// within one counting window. Prevents distributed brute force attacks.
    /// </summary>
    public int MaxIpFailuresPerMinute { get; set; } = 10;

    /// <summary>
    /// How long one counting window for per-IP rate limiting lasts.
    /// Failed attempts outside the current window are not counted toward the rate limit.
    /// </summary>
    /// <remarks>
    /// Attempts are counted per window rather than over the last interval, so a burst spanning a boundary
    /// can spend the allowance twice: sizing the window is sizing the worst case at twice the count above.
    /// The name says window rather than sliding window for that reason - and the count it replaced behaved
    /// the same way, restarting once the interval had passed since the first failure it held.
    /// </remarks>
    public TimeSpan RateLimitWindow { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// The maximum duration for exponential backoff blocking.
    /// Prevents indefinite blocking even with many failed attempts.
    /// </summary>
    public TimeSpan MaxBackoffDuration { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// How long a recorded per-IP attempt is kept in storage.
    /// Must be longer than one window, or attempts stop being counted before their window ends.
    /// </summary>
    public TimeSpan IpRateLimitStateExpiration { get; set; } = TimeSpan.FromMinutes(2);
}
