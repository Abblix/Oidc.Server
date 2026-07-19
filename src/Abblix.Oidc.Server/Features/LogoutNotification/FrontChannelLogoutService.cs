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

using System.Security.Cryptography;
using System.Text;
using Abblix.Utils;
using static System.Web.HttpUtility;

namespace Abblix.Oidc.Server.Features.LogoutNotification;

/// <summary>
/// Implements front-channel logout HTML generation in accordance with
/// OpenID Connect Front-Channel Logout 1.0 specification.
/// </summary>
public class FrontChannelLogoutService : IFrontChannelLogoutService
{
    /// <summary>
    /// Length in bytes for cryptographically secure nonce generation.
    /// 16 bytes provides 128 bits of entropy.
    /// </summary>
    private const int NonceByteLength = 16;

    /// <summary>
    /// Placeholder in HTML template for the CSP nonce value.
    /// </summary>
    private const string NoncePlaceholder = "{{nonce}}";

    /// <summary>
    /// Placeholder in HTML template for the generated iframe elements.
    /// </summary>
    private const string IframesPlaceholder = "{{iframes}}";

    /// <summary>
    /// Placeholder in HTML template for the post-logout redirect URI.
    /// </summary>
    private const string PostLogoutUriPlaceholder = "{{postLogoutUri}}";

    /// <summary>
    /// Lazily-loaded HTML template from embedded resources.
    /// </summary>
    private static readonly Lazy<string> HtmlTemplate = new(ReadHtmlTemplate);

    /// <inheritdoc />
    public FrontChannelLogoutResponse GetFrontChannelLogoutResponse(
        Uri? postLogoutRedirectUri,
        IList<Uri> frontChannelLogoutUris)
    {
        var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(NonceByteLength));
        var iframesHtml = BuildIframes(frontChannelLogoutUris);

        var postLogoutUriJs = postLogoutRedirectUri != null
            ? JavaScriptStringEncode(postLogoutRedirectUri.OriginalString, addDoubleQuotes: true)
            : "null";

        var htmlContent = HtmlTemplate.Value
            .Replace(NoncePlaceholder, nonce)
            .Replace(IframesPlaceholder, iframesHtml)
            .Replace(PostLogoutUriPlaceholder, postLogoutUriJs);

        var frameSources = frontChannelLogoutUris
            .Select(u => u.GetLeftPart(UriPartial.Authority))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return new FrontChannelLogoutResponse(htmlContent, nonce, frameSources);
    }

    /// <summary>
    /// Builds HTML iframe elements for each logout URI with proper HTML encoding.
    /// </summary>
    private static string BuildIframes(IList<Uri> logoutUris)
    {
        var sb = new StringBuilder();
        foreach (var uri in logoutUris)
        {
            sb.Append("<iframe src=\"");
            sb.Append(HtmlAttributeEncode(uri.OriginalString));
            sb.Append("\"></iframe>");
        }
        return sb.ToString();
    }

    /// <summary>
    /// Reads the HTML template from embedded assembly resources.
    /// </summary>
    private static string ReadHtmlTemplate()
    {
        var type = typeof(FrontChannelLogoutService);
        var name = $"{type.Namespace}.Resources.frontChannelLogout.html";

        using var stream = type.Assembly.GetManifestResourceStream(name).NotNull(nameof(name));
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return reader.ReadToEnd();
    }
}
