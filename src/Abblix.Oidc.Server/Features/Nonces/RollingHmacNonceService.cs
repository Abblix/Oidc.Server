// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Buffers.Text;
using System.Security.Cryptography;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.Storages;
using Google.Protobuf;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.Nonces;

/// <summary>
/// HMAC-SHA256 backed implementation of <see cref="INonceService"/>.
/// Issues stateless nonces of the form <c>Base64Url(timestamp_8B || HMAC-SHA256(secret, timestamp_8B)[..16])</c>
/// where <c>secret</c> is rotated on a configurable cadence and shared across
/// server instances via <see cref="IEntityStorage"/>, keyed by time bucket.
/// </summary>
/// <remarks>
/// <para>
/// The bucketed-secret design avoids any explicit lock or coordination on the
/// rotation boundary: every instance derives the same bucket index from the
/// nonce's embedded timestamp, looks up that bucket's secret in the
/// entity storage, and either finds it or claims the key with a new one - of
/// instances racing to claim it, one wins and the others read the winner's.
/// Per RFC 9449 section 11.3 a brief mismatch during the rotation race
/// surfaces to the DPoP client as a single retry with a fresh
/// <c>DPoP-Nonce</c> header, which is the protocol's intended recovery path;
/// other consumers of this service get the analogous one-retry behavior
/// through their own challenge-response loop.
/// </para>
/// <para>
/// The entity storage rather than the distributed cache directly, so a deployment serving several tenants keeps
/// a secret per tenant, and a nonce issued by one tenant does not validate at another.
/// </para>
/// </remarks>
public partial class RollingHmacNonceService(
    ILogger<RollingHmacNonceService> logger,
    IEntityStorage storage,
    IEntityStorageKeyFactory keyFactory,
    IOptionsMonitor<OidcOptions> options,
    TimeProvider timeProvider) : INonceService
{
    /// <summary>
    /// Length of the HMAC secret. 32 bytes matches SHA-256's block-aligned
    /// security level - anything longer would be hashed down by HMAC anyway.
    /// </summary>
    private const int SecretLengthBytes = 32;

    /// <summary>
    /// Truncated HMAC tag length. 16 bytes (128 bits) is the standard
    /// minimum for unforgeable MACs; trimming saves 16 bytes of base64
    /// payload per nonce without weakening security in this attack model.
    /// </summary>
    private const int TagLengthBytes = 16;

    /// <summary>
    /// Total decoded nonce length: 8 bytes timestamp + 16 bytes HMAC tag.
    /// </summary>
    private const int NonceBytes = sizeof(long) + TagLengthBytes;

    /// <inheritdoc/>
    public async Task<string> IssueAsync(CancellationToken cancellationToken = default)
    {
        var timestamp = timeProvider.GetUtcNow().ToUnixTimeSeconds();
        var tag = await ComputeTagAsync(timestamp, cancellationToken);
        return BuildNonceString(tag, timestamp);
    }

    /// <inheritdoc/>
    public async Task<NonceValidationFailure?> ValidateAsync(
        string nonce,
        CancellationToken cancellationToken = default)
    {
        // The 24-byte allocation is dwarfed by the cache round-trip; using
        // byte[] (rather than stackalloc Span<byte>) sidesteps two issues at
        // once - Span cannot cross the await on GetOrCreateSecretAsync, and
        // ref structs are not allowed inside async method bodies pre-C# 13
        // (the .NET 8 target's language version).
        var decoded = new byte[NonceBytes];
        int written;
        try
        {
            // TryDecodeFromChars returns false only on insufficient destination
            // size; invalid characters and length-mod-4-of-1 surface as
            // FormatException from the BCL implementation.
            if (!Base64Url.TryDecodeFromChars(nonce.AsSpan(), decoded, out written))
            {
                LogValidationFailed(NonceValidationFailure.Malformed);
                return NonceValidationFailure.Malformed;
            }
        }
        catch (FormatException)
        {
            LogValidationFailed(NonceValidationFailure.Malformed);
            return NonceValidationFailure.Malformed;
        }
        if (written != NonceBytes)
        {
            LogValidationFailed(NonceValidationFailure.Malformed);
            return NonceValidationFailure.Malformed;
        }

        var timestamp = BitConverter.ToInt64(decoded, 0);
        var issuedAt = DateTimeOffset.FromUnixTimeSeconds(timestamp);
        var now = timeProvider.GetUtcNow();
        var window = options.CurrentValue.DPoP.Nonce.AcceptanceWindow;
        if (window < (now - issuedAt).Duration())
        {
            LogValidationFailed(NonceValidationFailure.OutOfWindow);
            return NonceValidationFailure.OutOfWindow;
        }

        var expected = await ComputeTagAsync(timestamp, cancellationToken);
        if (!VerifyTag(expected, decoded))
        {
            LogValidationFailed(NonceValidationFailure.BadSignature);
            return NonceValidationFailure.BadSignature;
        }

        return null;
    }

    /// <summary>
    /// Computes the truncated HMAC-SHA256 tag the server attaches to a nonce
    /// whose timestamp is <paramref name="timestamp"/>. Issue and Validate
    /// share this method: Issue builds a fresh nonce by gluing the tag onto
    /// the timestamp, Validate recomputes the expected tag and compares it
    /// constant-time against the one carried by the inbound nonce.
    /// </summary>
    private async Task<byte[]> ComputeTagAsync(long timestamp, CancellationToken cancellationToken)
    {
        var bucket = BucketIndex(timestamp, options.CurrentValue.DPoP.Nonce.RotationInterval);
        var secret = await GetOrCreateSecretAsync(bucket, cancellationToken);
        return ComputeTagSync(secret, timestamp);
    }

    /// <summary>
    /// Sync HMAC computation kept separate from <see cref="ComputeTagAsync"/>
    /// because <see cref="Span{T}"/> is a ref struct and pre-C# 13 (the .NET 8
    /// target's language version) ref structs are not allowed inside async
    /// method bodies. Isolating the Span work in a sync helper keeps the
    /// async surface portable across all TFMs we ship to.
    /// </summary>
    private static byte[] ComputeTagSync(byte[] secret, long timestamp)
    {
        Span<byte> message = stackalloc byte[sizeof(long)];
        BitConverter.TryWriteBytes(message, timestamp);

        var tag = new byte[TagLengthBytes];
        ComputeTag(secret, message, tag);
        return tag;
    }

    /// <summary>
    /// Sync helper: glues <paramref name="timestamp"/> and <paramref name="tag"/>
    /// into the on-the-wire nonce byte sequence and base64url-encodes it.
    /// Same async-vs-ref-struct rationale as <see cref="ComputeTagSync"/>.
    /// </summary>
    private static string BuildNonceString(byte[] tag, long timestamp)
    {
        var output = new byte[NonceBytes];
        Span<byte> span = output;
        BitConverter.TryWriteBytes(span, timestamp);
        Buffer.BlockCopy(tag, 0, output, sizeof(long), TagLengthBytes);
        return Base64Url.EncodeToString(output);
    }

    /// <summary>
    /// Sync helper: constant-time compare between the recomputed expected tag
    /// and the tag bytes embedded in the inbound nonce. Same ref-struct-in-async
    /// rationale as the other sync helpers.
    /// </summary>
    private static bool VerifyTag(byte[] expected, byte[] decoded)
        => CryptographicOperations.FixedTimeEquals(expected, decoded.AsSpan(sizeof(long)));

    /// <summary>
    /// Maps a Unix-second timestamp onto the rotation-bucket index used to
    /// key the secret in <see cref="IEntityStorage"/>. Two timestamps fall
    /// into the same bucket iff they were minted under the same secret
    /// generation; this is the only coordination needed between instances.
    /// </summary>
    private static long BucketIndex(long unixSeconds, TimeSpan rotationInterval)
    {
        var rotationSeconds = (long)rotationInterval.TotalSeconds;
        if (rotationSeconds <= 0)
        {
            throw new InvalidOperationException(
                $"{nameof(NonceOptions.RotationInterval)} must be at least one second.");
        }
        return unixSeconds / rotationSeconds;
    }

    /// <summary>
    /// Looks up the rotating secret for the given bucket. When there is none, generates a new random secret and
    /// claims the bucket's key with it; of instances racing to claim it, one wins, and the others take the
    /// winner's, so all of them sign and verify with one secret for the rest of the bucket's lifetime. The entry
    /// lives three rotation intervals so a secret remains usable for verification across the entire
    /// <see cref="NonceOptions.AcceptanceWindow"/>.
    /// </summary>
    private async Task<byte[]> GetOrCreateSecretAsync(long bucket, CancellationToken cancellationToken)
    {
        var key = keyFactory.NonceSecretKey(bucket);
        var stored = await storage.GetAsync<Storages.Proto.NonceSecret>(key, removeOnRetrieval: false, cancellationToken);
        if (stored is { Value.Length: SecretLengthBytes })
            return stored.Value.ToByteArray();

        var fresh = new Storages.Proto.NonceSecret
        {
            Value = ByteString.CopyFrom(RandomNumberGenerator.GetBytes(SecretLengthBytes)),
        };
        var lifetime = new StorageOptions
        {
            AbsoluteExpirationRelativeToNow = options.CurrentValue.DPoP.Nonce.RotationInterval * 3,
        };

        if (await storage.TrySetIfAbsentAsync(key, fresh, lifetime, cancellationToken))
        {
            LogSecretGenerated(bucket);
            return fresh.Value.ToByteArray();
        }

        var winner = await storage.GetAsync<Storages.Proto.NonceSecret>(key, removeOnRetrieval: false, cancellationToken);
        return (winner ?? fresh).Value.ToByteArray();
    }

    /// <summary>
    /// Computes a truncated HMAC-SHA256 over <paramref name="message"/>.
    /// Uses <see cref="HMACSHA256.HashData(ReadOnlySpan{byte},ReadOnlySpan{byte},Span{byte})"/>
    /// to avoid allocating a full <see cref="HMACSHA256"/> instance per call.
    /// </summary>
    private static void ComputeTag(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> message, Span<byte> tag)
    {
        Span<byte> full = stackalloc byte[HMACSHA256.HashSizeInBytes];
        HMACSHA256.HashData(secret, message, full);
        full[..TagLengthBytes].CopyTo(tag);
    }
}
