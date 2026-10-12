// Abblix OIDC Client Library
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

using System.Web;

namespace Abblix.Oidc.Client.UnitTests;

/// <summary>
/// Reads back the parameters this client put on the wire, so a test can assert on what a provider would
/// have received rather than on what the code meant to send.
/// </summary>
/// <remarks>
/// A request carries its parameters in one of two places - the body of a post, or the query of an address -
/// and five suites had grown their own copy of the reading. Kept here so that a test asserting on a
/// parameter name is asserting against one reading of the wire rather than whichever copy its file
/// happened to carry.
/// </remarks>
public static class Wire
{
    /// <summary>
    /// The parameters a form-encoded request body carries.
    /// </summary>
    /// <param name="body">
    /// The body a stub handler recorded. Nullable because a handler that was never called has none, and
    /// that is a failed expectation rather than an empty form - so it is asserted here instead of at every
    /// call site.
    /// </param>
    public static Dictionary<string, string> FormOf(string? body)
    {
        Assert.NotNull(body);
        return Read(HttpUtility.ParseQueryString(body));
    }

    /// <summary>
    /// The parameters an address carries in its query.
    /// </summary>
    public static Dictionary<string, string> QueryOf(Uri address)
        => Read(HttpUtility.ParseQueryString(address.Query));

    /// <remarks>
    /// OfType filters and narrows in one step: a valueless entry arrives under a null key, and that is not
    /// a parameter this client sent.
    /// </remarks>
    private static Dictionary<string, string> Read(System.Collections.Specialized.NameValueCollection parsed)
        => parsed.AllKeys
            .OfType<string>()
            .ToDictionary(key => key, key => parsed[key] ?? string.Empty, StringComparer.Ordinal);
}
