// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.RichAuthorizationRequests;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Linq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.AuthorizationDetails;

/// <summary>
/// The redemption-time question, asked through the SHIPPED validator dispatch rather than through a stub.
/// </summary>
/// <remarks>
/// The gate compares what the validators handed back against what was stored, so everything it decides
/// rests on the composite's round-trip being faithful: entries are wrapped, dispatched by type, and
/// rebuilt. A stub answers with the array it was given and exercises none of that, so a stub-only suite
/// would be green over a composite that reshaped every entry it touched - and the gate would then refuse
/// every grant on every deployment, with a log accusing the host's validators of a change they did not
/// make.
/// </remarks>
public class GrantedRevalidationTests
{
    private const string ClientId = "client-1";
    private const string PaymentType = "payment_initiation";

    /// <summary>
    /// The RFC 9396 Section 2 worked example, parsed off the wire rather than built member by member, so
    /// the fixture carries what a real entry carries: nested objects, arrays, and a number written the way
    /// the client wrote it.
    /// </summary>
    private const string WorkedExample =
        """
        [{
          "type": "payment_initiation",
          "actions": ["initiate", "status", "cancel"],
          "locations": ["https://example.com/payments"],
          "instructedAmount": { "currency": "EUR", "amount": "123.50" },
          "creditorName": "Merchant A",
          "creditorAccount": { "iban": "DE02100100109307118603" },
          "remittanceInformationUnstructured": "Ref Number Merchant"
        }]
        """;

    /// <summary>
    /// A validator that changes nothing is not read as changing something.
    /// </summary>
    /// <remarks>
    /// The positive control, and the one that could not be run without the real dispatch. It fails if the
    /// composite's round trip alters an entry in any way the comparison can see - which is the failure mode
    /// that would make every other test here green and the product unusable.
    /// </remarks>
    [Fact]
    public async Task AValidatorThatChangesNothing_IsNotARefusal()
    {
        var policy = PolicyWith<PassThroughValidator>();

        Assert.Null(await policy.RefuseAsync(
            GrantWith(WorkedExample), new ClientInfo(ClientId), TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// A validator that only reorders an entry's members is not read as changing it.
    /// </summary>
    /// <remarks>
    /// Deserialise, validate, return a fresh entry is the natural way to write a validator in C#, and the
    /// interface invites it by saying what comes back may be normalised. Comparing the two as TEXT refuses
    /// such a validator and tells its author, in a warning, that it changed a grant it did not touch.
    /// </remarks>
    [Fact]
    public async Task AValidatorThatOnlyReordersMembers_IsNotARefusal()
    {
        var policy = PolicyWith<ReorderingValidator>();

        Assert.Null(await policy.RefuseAsync(
            GrantWith(WorkedExample), new ClientInfo(ClientId), TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// A validator that rewrites the entry it returns is a refusal.
    /// </summary>
    /// <remarks>
    /// One of the two halves of the comparison on its own: the composite always answers with a fresh array
    /// built from what the validators returned, so this is the half that fires against the shipped
    /// dispatch. The other half stands over a host that replaces the dispatch itself.
    /// </remarks>
    [Fact]
    public async Task AValidatorThatRewritesWhatItReturns_IsARefusal()
    {
        var policy = PolicyWith<CappingValidator>();

        var refusal = await policy.RefuseAsync(
            GrantWith(WorkedExample), new ClientInfo(ClientId), TestContext.Current.CancellationToken);

        Assert.NotNull(refusal);
        Assert.Equal(ErrorCodes.InvalidAuthorizationDetails, refusal!.Value.Error.Error);
    }

    /// <summary>
    /// A dispatch that edits in place and answers "nothing to change" is a refusal too.
    /// </summary>
    /// <remarks>
    /// The other half, which the shipped composite cannot produce - it always returns a fresh array - so it
    /// takes a policy of its own to reach. <see cref="IAuthorizationDetailsPolicy"/> is public and
    /// registered with TryAdd, so a host may supply exactly this shape, and without the probe comparison
    /// the edit would travel into the token unseen.
    /// </remarks>
    [Fact]
    public async Task ADispatchThatEditsInPlaceAndAnswersNull_IsARefusal()
    {
        IAuthorizationDetailsPolicy policy = new InPlaceEditingPolicy();

        var refusal = await policy.RefuseAsync(
            GrantWith(WorkedExample), new ClientInfo(ClientId), TestContext.Current.CancellationToken);

        Assert.NotNull(refusal);
        Assert.Equal(ErrorCodes.InvalidAuthorizationDetails, refusal!.Value.Error.Error);
    }

    private static IAuthorizationDetailsPolicy PolicyWith<TValidator>()
        where TValidator : class, IAuthorizationDetailValidator
    {
        var services = new ServiceCollection();
        services.AddRichAuthorizationRequests();
        services.AddAuthorizationDetailValidator<TValidator>(PaymentType);
        return services.BuildServiceProvider().GetRequiredService<IAuthorizationDetailsPolicy>();
    }

    private static AuthorizedGrant GrantWith(string wire)
        => new(
            new AuthSession("user", "session", DateTimeOffset.UnixEpoch, "test"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null)
            {
                AuthorizationDetails = (JsonArray)JsonNode.Parse(wire)!,
            });

    private sealed class PassThroughValidator : IAuthorizationDetailValidator
    {
        public string Type => PaymentType;

        public Task<Result<AuthorizationDetail, OidcError>> ValidateAsync(
            AuthorizationDetail detail, ClientInfo client, CancellationToken token)
            => Task.FromResult<Result<AuthorizationDetail, OidcError>>(detail);
    }

    /// <summary>Returns an entry carrying the same members, sorted by name.</summary>
    private sealed class ReorderingValidator : IAuthorizationDetailValidator
    {
        public string Type => PaymentType;

        public Task<Result<AuthorizationDetail, OidcError>> ValidateAsync(
            AuthorizationDetail detail, ClientInfo client, CancellationToken token)
        {
            var sorted = new JsonObject();
            var names = detail.Json.Select(member => member.Key).Order(StringComparer.Ordinal).ToArray();
            foreach (var name in names)
                sorted[name] = detail.Json[name]!.DeepClone();

            return Task.FromResult<Result<AuthorizationDetail, OidcError>>(new AuthorizationDetail(sorted));
        }
    }

    /// <summary>Enforces a ceiling by capping rather than by refusing.</summary>
    private sealed class CappingValidator : IAuthorizationDetailValidator
    {
        public string Type => PaymentType;

        public Task<Result<AuthorizationDetail, OidcError>> ValidateAsync(
            AuthorizationDetail detail, ClientInfo client, CancellationToken token)
        {
            var capped = (JsonObject)detail.Json.DeepClone();
            capped["instructedAmount"]!["amount"] = "100.00";

            return Task.FromResult<Result<AuthorizationDetail, OidcError>>(new AuthorizationDetail(capped));
        }
    }

    /// <summary>A dispatch of the shape a host may register: edits what it is handed, answers null.</summary>
    private sealed class InPlaceEditingPolicy : IAuthorizationDetailsPolicy
    {
        public Task<Result<JsonArray?, OidcError>> ApplyAsync(
            JsonArray? raw, ClientInfo client, CancellationToken token)
        {
            if (raw?[0] is JsonObject entry)
                entry["instructedAmount"]!["amount"] = "100.00";

            return Task.FromResult<Result<JsonArray?, OidcError>>((JsonArray?)null);
        }
    }
}
