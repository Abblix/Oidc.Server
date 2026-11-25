// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Buffers;
using System.Globalization;
using System.Text;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;

/// <summary>
/// Refuses a binding_message the authentication device cannot be trusted to show as the consumption device does:
/// one longer than <see cref="BackChannelAuthenticationOptions.MaximumBindingMessageLength"/> code points, or one
/// carrying a code point that is not plain visible text.
/// </summary>
/// <remarks>
/// CIBA Core 1.0 section 7.1: "the binding_message value SHOULD be relatively short and use a limited set of plain text
/// characters". Section 13 answers a binding message that is "invalid or unacceptable for use in the context of the
/// given request" with invalid_binding_message.
/// <para>
/// The message is the end-user's proof that both devices show the same transaction, so a code point that makes a
/// device show text other than the one sent defeats it: a bidirectional override such as U+202E reverses what
/// follows it, and a zero-width character hides a difference between two messages that look the same. Refused are
/// the Unicode general categories Cc (control, line breaks and tabs included), Cf (format, the bidirectional
/// controls and U+200B and U+200D among them), Co (private use), Cs (surrogate, an unpaired one in the string), Cn
/// (unassigned), Zl and Zp (line and paragraph separators). One rule without exceptions: the zero-width joiner is
/// refused too, so an emoji composed of several joined ones is, while a single emoji with a skin-tone modifier (Sk)
/// or a variation selector (Mn) and letters of any script are accepted.
/// </para>
/// </remarks>
/// <param name="options">Holds the longest binding message accepted.</param>
public class BindingMessageValidator(IOptions<OidcOptions> options) : IBackChannelAuthenticationContextValidator
{
    /// <inheritdoc />
    public Task<OidcError?> ValidateAsync(TenantDefinition tenant, BackChannelAuthenticationValidationContext context)
        => Task.FromResult(RefusalOf(context.Request.BindingMessage));

    /// <summary>
    /// The refusal of <paramref name="bindingMessage"/>, or null where it is absent or acceptable.
    /// </summary>
    private OidcError? RefusalOf(string? bindingMessage)
    {
        if (bindingMessage is null)
            return null;

        var maximumLength = options.Value.BackChannelAuthentication.MaximumBindingMessageLength;
        var length = 0;
        var remaining = bindingMessage.AsSpan();
        while (!remaining.IsEmpty)
        {
            // An unpaired surrogate (Cs) decodes as invalid data: a decoded code point is never of that category
            if (Rune.DecodeFromUtf16(remaining, out var codePoint, out var consumed) != OperationStatus.Done ||
                IsNotPlainText(Rune.GetUnicodeCategory(codePoint)))
            {
                return new OidcError(
                    ErrorCodes.InvalidBindingMessage,
                    "The binding message contains a character that is not plain visible text");
            }

            if (maximumLength < ++length)
            {
                return new OidcError(
                    ErrorCodes.InvalidBindingMessage,
                    $"The binding message is longer than {maximumLength} characters");
            }

            remaining = remaining[consumed..];
        }

        return null;
    }

    /// <summary>
    /// Whether a code point of <paramref name="category"/> may make a device show text other than the one sent.
    /// </summary>
    private static bool IsNotPlainText(UnicodeCategory category) => category is
        UnicodeCategory.Control or
        UnicodeCategory.Format or
        UnicodeCategory.PrivateUse or
        UnicodeCategory.OtherNotAssigned or
        UnicodeCategory.LineSeparator or
        UnicodeCategory.ParagraphSeparator;
}
