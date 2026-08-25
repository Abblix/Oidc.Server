// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.RichAuthorizationRequests;
using Abblix.Utils;

namespace Abblix.Oidc.Server.UnitTests.TestInfrastructure;

/// <summary>
/// A per-type validator dispatch a test can steer, written by hand rather than mocked.
/// </summary>
/// <remarks>
/// <see cref="IAuthorizationDetailsPolicy.ApplyGrantedAsync"/> is a default interface member, and a mocking
/// framework intercepts the interface rather than the default body - so a mock set up on
/// <see cref="IAuthorizationDetailsPolicy.ApplyAsync"/> answers the granted-phase call with whatever a
/// strict mock does about an unconfigured member, which is a failure that reads as a defect in the code
/// under test. A hand-written implementation runs the real forwarding.
/// </remarks>
internal sealed class StubAuthorizationDetailsPolicy : IAuthorizationDetailsPolicy
{
    /// <summary>Accepts whatever it is handed, which is what most tests need of it.</summary>
    public static StubAuthorizationDetailsPolicy Accepting => new();

    /// <summary>Refuses everything, naming <paramref name="reason"/> in the error description.</summary>
    public static StubAuthorizationDetailsPolicy Refusing(string reason) => new() { _refusal = reason };

    /// <summary>
    /// Accepts, having rewritten a member of every entry - the way a validator enforces a ceiling by
    /// capping rather than by saying no. The authorization endpoint honours that answer; a grant already
    /// approved out of band cannot be rewritten, so at redemption it has to become a refusal.
    /// </summary>
    public static StubAuthorizationDetailsPolicy Capping(string member, string value) =>
        new() { _cap = (member, value) };

    private string? _refusal;
    private (string Member, string Value)? _cap;

    /// <summary>What the last call was handed, so a test can see whether it was the live array.</summary>
    public JsonArray? LastSeen { get; private set; }

    /// <summary>How many times the granted-phase question was asked.</summary>
    public int GrantedCalls { get; private set; }

    public Task<Result<JsonArray?, OidcError>> ApplyAsync(
        JsonArray? raw,
        ClientInfo client,
        CancellationToken token)
    {
        LastSeen = raw;
        if (_refusal is null)
        {
            if (_cap is { } cap && raw is not null)
            {
                foreach (var entry in raw.OfType<JsonObject>())
                    entry[cap.Member] = cap.Value;
            }

            return Task.FromResult<Result<JsonArray?, OidcError>>(raw);
        }

        return Task.FromResult<Result<JsonArray?, OidcError>>(
            new OidcError(ErrorCodes.InvalidAuthorizationDetails, _refusal));
    }

    public Task<Result<JsonArray?, OidcError>> ApplyGrantedAsync(
        JsonArray? granted,
        ClientInfo client,
        CancellationToken token)
    {
        GrantedCalls++;
        return ApplyAsync(granted, client, token);
    }
}
