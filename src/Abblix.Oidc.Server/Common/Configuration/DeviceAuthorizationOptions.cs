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
    /// <remarks>
    /// One minute by default, and the number is a security setting as much as a usability one: the guesses
    /// an attacker gets at a live code are the server's budget for a window multiplied by how many windows
    /// the code survives, so halving the lifetime halves them. See <see cref="UserCodeAlphabet"/> for the
    /// arithmetic and <see cref="MaxFailedAttemptsPerWindow"/> for why that budget cannot simply be made
    /// small instead.
    /// <para>
    /// What it costs is the time a person has to pick up their phone and approve, so a deployment whose
    /// users need longer raises it and accepts proportionally more guesses - or lengthens the code, which
    /// buys far more than either, since every symbol multiplies the space.
    /// </para>
    /// </remarks>
    public TimeSpan CodeLifetime { get; set; } = TimeSpan.FromMinutes(1);

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
    /// Here <c>N</c> is how many guesses the server entertains while one code is alive, which is
    /// <see cref="MaxFailedAttemptsPerWindow"/> multiplied by <see cref="CodeLifetime"/> divided by
    /// <see cref="RateLimitWindow"/> - a hundred a minute over a one-minute code is a hundred. It is NOT
    /// <see cref="MaxUserCodeAttempts"/>: that bounds repeat attempts at one dead code, and a search never
    /// repeats a value. With the shipped numbers, N is 100:
    /// </para>
    /// <list type="bullet">
    ///   <item>8 digits: 100 in 100 million, about 1 in a million per code.</item>
    ///   <item>10 digits: 100 in 10 billion, about 1 in 100 million.</item>
    ///   <item>8 symbols of "BCDFGHJKLMNPQRSTVWXZ": 100 in 25.6 billion, about 1 in 256 million.</item>
    ///   <item>12 digits, or 9 symbols of that alphabet: around the example's own 2^-32.</item>
    /// </list>
    /// <para>
    /// The document's example reaches 2^-32 by allowing five guesses over a code's whole life, and at
    /// eight digits no lifetime reaches that: it would take fewer than one guess per code, which no
    /// shared budget can express. What the short lifetime buys is the factor between 1 in 200 thousand
    /// and 1 in a million; closing the rest means a longer or wider code, since every symbol multiplies
    /// the space while every limit only divides the rate. A smaller budget is not the lever it looks
    /// like - see <see cref="MaxFailedAttemptsPerWindow"/> for why.
    /// </para>
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
    /// What this counts is attempts at a value that names an authorization which can no longer be used -
    /// one already approved or denied, or one past its lifetime. Those are the only failures a code can
    /// have: a live pending code either matches what was typed, in which case the attempt succeeded, or it
    /// does not, in which case the typed value is not that code at all. So the number bounds how long a
    /// dead code keeps answering "already used" before it answers like any unknown value, and nothing else.
    /// <para>
    /// It does NOT bound a search through the space of codes, and no per-code number can: a guesser submits
    /// a different value every time, and a person who mistypes submits a value the server never issued.
    /// Both are counted by <see cref="MaxFailedAttemptsPerWindow"/> and the per-address cap - see
    /// <see cref="UserCodeAlphabet"/> for what those allow and what it costs an attacker.
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
    /// healthy deployment produces - those are typos, a few per minute at most.
    /// <para>
    /// The brake is shared, which cuts both ways and must be said plainly: while it is held, EVERY
    /// verification is refused, including every legitimate person, and an attacker willing to spend this
    /// many requests a minute can hold it down for as long as it likes. That is the price of bounding a
    /// search that rotates addresses - there is nothing else about such a search to count. A number chosen
    /// well above honest traffic keeps the brake off in practice; a number chosen tight enough to reach the
    /// improbability RFC 8628 section 5.1 works its example to would also make refusing everybody cheap.
    /// Sizing it is therefore a choice between the two, and <see cref="UserCodeAlphabet"/> carries the
    /// arithmetic for making it.
    /// </para>
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
    /// <remarks>
    /// No length means no growing pause at all, which is a choice rather than a mistake: a deployment may
    /// lean on the per-address cap and the server's budget instead, and nothing refuses it.
    /// </remarks>
    public TimeSpan MaxBackoffDuration { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// How long a recorded per-IP attempt is kept in storage.
    /// Must be longer than one window, or attempts stop being counted before their window ends.
    /// </summary>
    public TimeSpan IpRateLimitStateExpiration { get; set; } = TimeSpan.FromMinutes(2);
}
