// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Features.RichAuthorizationRequests;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.AuthorizationDetails;

/// <summary>
/// The one computation four comparisons share: which <c>authorization_details</c> types an array names.
/// </summary>
public class AuthorizationDetailTypesTests
{
    /// <summary>
    /// Types are compared as text, so two spellings differing only in case are two types.
    /// </summary>
    /// <remarks>
    /// RFC 9396 section 12: "All string comparisons in an authorization_details parameter are to be done
    /// as defined by [RFC8259]. No additional transformation or normalization is to be done in evaluating
    /// equivalence of string values."
    ///
    /// Pinned here rather than left to the comparer's default, because every caller of this uses the
    /// result as a BASELINE: a case-insensitive set admits an entry of a type nobody requested whenever
    /// the two differ only in case, and it admits it silently, in the direction that grants more. The
    /// comparer is one identifier and nothing else in the flow would notice it changing.
    /// </remarks>
    [Fact]
    public void NamedBy_ComparesTypesAsText()
    {
        var named = AuthorizationDetailTypes.NamedBy(
            new JsonArray(
                new JsonObject { ["type"] = "payment_initiation" },
                new JsonObject { ["type"] = "Payment_Initiation" }));

        Assert.Equal(2, named.Count);
        Assert.Contains("payment_initiation", named);
        Assert.DoesNotContain("PAYMENT_INITIATION", named);
    }

    /// <summary>
    /// An entry the conversion cannot read, and one carrying no type, are dropped rather than refused.
    /// </summary>
    /// <remarks>
    /// Dropping narrows the baseline and therefore admits LESS wherever it is used as one, which is why
    /// this side can be silent while the grant side of every comparison has to refuse instead - there the
    /// same silence would admit more. Each caller owns that refusal.
    /// </remarks>
    [Fact]
    public void NamedBy_DropsWhatItCannotRead()
    {
        var named = AuthorizationDetailTypes.NamedBy(
            new JsonArray(
                JsonValue.Create("payment_initiation"),
                new JsonObject { ["actions"] = new JsonArray(JsonValue.Create("initiate")) },
                new JsonObject { ["type"] = "account_information" }));

        Assert.Equal("account_information", Assert.Single(named));
    }

    /// <summary>
    /// A null array names nothing, which is what lets the callers decide what null MEANS.
    /// </summary>
    /// <remarks>
    /// The two flows read it differently on purpose - CIBA treats a null member as a request that predates
    /// the field and returns before asking, the device flow treats it as a request that asked for nothing -
    /// and this answering the same for both is what makes it shareable rather than what makes it wrong.
    /// </remarks>
    [Fact]
    public void NamedBy_NamesNothingForANullArray()
    {
        Assert.Empty(AuthorizationDetailTypes.NamedBy(null));
    }
}
