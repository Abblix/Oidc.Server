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

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Interfaces;

namespace Abblix.Oidc.Server.Features.ExternalKeys;

/// <summary>
/// Stands in for the key provider between a custodian registration and the tier choice that completes it, and
/// fails loud if the choice never came. The failure has to exist because the alternative is silent and worse: the
/// default provider is registered with TryAdd, so a custodian left without a tier would quietly serve the static
/// keys from <c>OidcOptions</c> - a configured custodian, a clean log, and local keys. C# cannot force the
/// continuation (the builder is a discardable return value), so the guard is a registration, not a signature.
/// </summary>
/// <remarks>
/// This is the second line: the startup validation registered alongside it (see
/// <see cref="CustodianTierValidation"/>) turns the same condition into a startup failure, so a host with a host
/// lifetime never reaches a key operation to trip this one. It stays for the host that resolves keys without one.
/// </remarks>
internal sealed class TierNotChosenKeysProvider : IAuthServiceKeysProvider
{
    internal const string Message =
        "A key custodian is registered, but the tier that decides how its keys are used was never chosen. " +
        "Follow the key storage registration with HoldKeysIn...() to choose where the private key stays.";

    /// <inheritdoc />
    public IAsyncEnumerable<JsonWebKey> GetSigningKeys(bool includePrivateKeys = false)
        => throw new InvalidOperationException(Message);

    /// <inheritdoc />
    public IAsyncEnumerable<JsonWebKey> GetEncryptionKeys(bool includePrivateKeys = false)
        => throw new InvalidOperationException(Message);
}
