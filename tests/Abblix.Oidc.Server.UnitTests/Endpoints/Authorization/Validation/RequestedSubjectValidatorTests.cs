// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Storages.Proto.Mappers;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization.Validation;

/// <summary>
/// What a <c>claims</c> request naming <c>sub</c> records for the endpoint to honour.
/// </summary>
/// <remarks>
/// OpenID Connect Core 1.0 Section 3.1.2.2 puts this and <c>id_token_hint</c> under one requirement, so the
/// two validators are two doors to the same MUST. What the endpoint then does with what is recorded is
/// covered in <c>AuthorizationRequestProcessorTests</c>.
/// <para>
/// Every input here is built the way the wire builds it - by deserialising the <c>claims</c> parameter - and
/// the round-trip theory additionally puts it through the store's own mapper, because that path hands the
/// validator a different runtime type for the same property.
/// </para>
/// </remarks>
public class RequestedSubjectValidatorTests
{
    private readonly RequestedSubjectValidator _validator = new();

    /// <summary>
    /// How the parameter arrives: a JSON document in a query string.
    /// </summary>
    private static AuthorizationValidationContext Context(string? claimsJson, bool throughTheStore = false)
    {
        var claims = claimsJson is null
            ? null
            : JsonSerializer.Deserialize<RequestedClaims>(claimsJson);

        if (throughTheStore && claims is not null)
            claims = RequestedClaimsMapper.FromProto(claims.ToProto());

        return new AuthorizationValidationContext(
            new AuthorizationRequest
            {
                ClientId = TestConstants.DefaultClientId,
                ResponseType = [ResponseTypes.Code],
                RedirectUri = TestConstants.DefaultRedirectUri,
                Scope = [Scopes.OpenId],
                Claims = claims,
            })
        {
            ClientInfo = new ClientInfo(TestConstants.DefaultClientId),
            ResponseMode = ResponseModes.Query,
        };
    }

    /// <summary>
    /// A single requested value is the one subject the request will accept.
    /// </summary>
    /// <remarks>
    /// Driven twice: once as the wire delivers it, once after the round trip a pushed request makes through
    /// the store. The same property holds a <c>JsonElement</c> on the first path and a <c>string</c> on the
    /// second, so a reader written for one leaves the requirement unenforced on the other - and the pushed
    /// path is the one FAPI clients use.
    /// </remarks>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ASingleRequestedValue_IsTheOnlySubjectAccepted(bool throughTheStore)
    {
        var context = Context("""{"id_token":{"sub":{"value":"alice"}}}""", throughTheStore);

        Assert.Null(await _validator.ValidateAsync(context));
        Assert.NotNull(context.RequestedSubjects);
        Assert.Equal(["alice"], context.RequestedSubjects);
    }

    /// <summary>
    /// A set of requested values is accepted whole, in the order the client wrote it.
    /// </summary>
    /// <remarks>
    /// Section 5.5.1: <c>values</c> "is processed equivalently to a value request, except that a choice of
    /// acceptable Claim values is provided", with them "appearing in order of preference" - so the order is
    /// the client's and is kept.
    /// </remarks>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ASetOfRequestedValues_IsAcceptedInOrder(bool throughTheStore)
    {
        var context = Context("""{"id_token":{"sub":{"values":["bob","alice"]}}}""", throughTheStore);

        Assert.Null(await _validator.ValidateAsync(context));
        Assert.NotNull(context.RequestedSubjects);
        Assert.Equal(["bob", "alice"], context.RequestedSubjects);
    }

    /// <summary>
    /// Both qualifiers together state both constraints, so what survives is their intersection.
    /// </summary>
    [Fact]
    public async Task BothQualifiersAgreeing_LeaveTheOneTheyAgreeOn()
    {
        var context = Context("""{"id_token":{"sub":{"value":"alice","values":["bob","alice"]}}}""");

        Assert.Null(await _validator.ValidateAsync(context));
        Assert.NotNull(context.RequestedSubjects);
        Assert.Equal(["alice"], context.RequestedSubjects);
    }

    /// <summary>
    /// Both qualifiers disagreeing accept nobody, which is a request that cannot be answered positively.
    /// </summary>
    /// <remarks>
    /// Recorded as an empty constraint rather than discarded as nonsense, because Section 5.5.1 already
    /// prescribes the outcome: "If the Claim was sub, a mismatch MUST cause the authentication to fail".
    /// Discarding it would answer the request for whichever end user happened to be logged in - the exact
    /// failure the requirement exists to prevent.
    /// </remarks>
    [Fact]
    public async Task BothQualifiersDisagreeing_AcceptNobody()
    {
        var context = Context("""{"id_token":{"sub":{"value":"carol","values":["bob","alice"]}}}""");

        Assert.Null(await _validator.ValidateAsync(context));
        Assert.NotNull(context.RequestedSubjects);
        Assert.Empty(context.RequestedSubjects);
    }

    /// <summary>
    /// A request that constrains nothing records no constraint.
    /// </summary>
    /// <remarks>
    /// The last two cases are the ones that would turn this validator into a refusal of ordinary traffic:
    /// asking for <c>sub</c> in the default manner, or as an essential claim, says nothing about which end
    /// user - Section 5.5.1 gives <c>value</c> and <c>values</c> that job and nothing else.
    /// </remarks>
    [Theory]
    [InlineData(null)]
    [InlineData("""{"userinfo":{"email":{"essential":true}}}""")]
    [InlineData("""{"id_token":{"auth_time":{"essential":true}}}""")]
    [InlineData("""{"id_token":{"sub":null}}""")]
    [InlineData("""{"id_token":{"sub":{"essential":true}}}""")]
    public async Task ARequestConstrainingNoSubject_RecordsNothing(string? claimsJson)
    {
        var context = Context(claimsJson);

        Assert.Null(await _validator.ValidateAsync(context));
        Assert.Null(context.RequestedSubjects);
    }

    /// <summary>
    /// A qualifier that is not a string is a malformed request rather than a subject nobody matches.
    /// </summary>
    /// <remarks>
    /// Section 5.5.1 requires the qualifier to be "a valid value for the Claim being requested" and Section 2
    /// makes <c>sub</c> a string. Answering <c>login_required</c> instead would be indistinguishable, to the
    /// client, from having asked about somebody who is simply not logged in.
    /// <para>
    /// Driven on both paths, because a malformed qualifier does not survive the round trip as the same thing
    /// it arrived as: a number comes back a boxed numeric, an object a <c>JsonObject</c>, an array element an
    /// <c>object[]</c>. None is a string and all must be refused, but they reach the reader as different
    /// types than the wire delivers, so one path proves nothing about the other.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData(false, """{"id_token":{"sub":{"value":42}}}""")]
    [InlineData(false, """{"id_token":{"sub":{"value":{"nested":"object"}}}}""")]
    [InlineData(false, """{"id_token":{"sub":{"values":["alice",42]}}}""")]
    [InlineData(true, """{"id_token":{"sub":{"value":42}}}""")]
    [InlineData(true, """{"id_token":{"sub":{"value":{"nested":"object"}}}}""")]
    [InlineData(true, """{"id_token":{"sub":{"values":["alice",42]}}}""")]
    public async Task AQualifierThatIsNotAString_IsAnInvalidRequest(
        bool throughTheStore, string claimsJson)
    {
        var context = Context(claimsJson, throughTheStore);

        var error = await _validator.ValidateAsync(context);

        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Null(context.RequestedSubjects);
    }
}
