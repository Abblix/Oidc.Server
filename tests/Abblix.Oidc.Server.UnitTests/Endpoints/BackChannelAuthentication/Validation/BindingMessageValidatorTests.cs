// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Linq;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.BackChannelAuthentication.Validation;

/// <summary>
/// CIBA Core 1.0 section 7.1: "the binding_message value SHOULD be relatively short and use a limited set of plain text
/// characters"; section 13 answers one "invalid or unacceptable for use in the context of the given request" with
/// invalid_binding_message.
/// </summary>
public class BindingMessageValidatorTests
{
    /// <summary>An emoji outside the Basic Multilingual Plane: one code point, two UTF-16 code units.</summary>
    private const string Emoji = "\U0001F600";

    private static readonly int DefaultMaximum = new BackChannelAuthenticationOptions().MaximumBindingMessageLength;

    private static Task<OidcError?> ValidateAsync(string? bindingMessage, int? maximumLength = null)
    {
        var options = new OidcOptions();
        if (maximumLength is { } length)
            options.BackChannelAuthentication.MaximumBindingMessageLength = length;

        var context = new BackChannelAuthenticationValidationContext(
            new BackChannelAuthenticationRequest { Scope = [TestConstants.DefaultScope], BindingMessage = bindingMessage },
            new ClientRequest { ClientId = TestConstants.DefaultClientId })
        {
            ClientInfo = new ClientInfo(TestConstants.DefaultClientId),
        };

        return new BindingMessageValidator(Options.Create(options)).ValidateAsync(SingleIssuer.Tenant, context);
    }

    /// <summary>
    /// A short message of plain text is accepted whatever its script, and so is a request without one: an emoji with a
    /// skin-tone modifier (Sk) or a variation selector (Mn) included, as the OIDF suite's message begins.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("W4SCT")]
    [InlineData("Approve payment 1234")]
    [InlineData("1234 👍🏿 品川")]
    [InlineData("\u2764\uFE0F")]
    [InlineData("Подтвердите вход")]
    [InlineData("تأكيد الدفع")]
    [InlineData("Approve " + Emoji)]
    public async Task AShortPlainTextMessage_IsAccepted(string? bindingMessage)
    {
        Assert.Null(await ValidateAsync(bindingMessage));
    }

    /// <summary>
    /// The length is counted in code points: as many emoji as the maximum, twice as many UTF-16 code units, are
    /// accepted, and one more is refused.
    /// </summary>
    [Fact]
    public async Task TheLength_IsCountedInCodePoints()
    {
        var longest = string.Concat(Enumerable.Repeat(Emoji, DefaultMaximum));

        Assert.Null(await ValidateAsync(longest));
        Assert.Equal(ErrorCodes.InvalidBindingMessage, (await ValidateAsync(longest + Emoji))?.Error);
    }

    /// <summary>
    /// A message one code point past the maximum a host set is refused, and one at it accepted.
    /// </summary>
    [Fact]
    public async Task AMessageLongerThanTheHostsMaximum_IsRefused()
    {
        Assert.Null(await ValidateAsync("12345", maximumLength: 5));
        Assert.Equal(ErrorCodes.InvalidBindingMessage, (await ValidateAsync("123456", maximumLength: 5))?.Error);
    }

    /// <summary>
    /// A code point of a category that may make a device show text other than the one sent is refused: control (Cc),
    /// a line break and a tab included; format (Cf), a bidirectional override, a zero-width space and the zero-width
    /// joiner of a composed emoji included; private use (Co); unassigned (Cn); line and paragraph separators (Zl, Zp).
    /// </summary>
    [Theory]
    [InlineData("Approve\npayment")]
    [InlineData("Approve\tpayment")]
    [InlineData("\u0000")]
    [InlineData("Approve\u0085payment")]
    [InlineData("Pay \u202E0001")]
    [InlineData("Pay\u200B1234")]
    [InlineData("\U0001F468\u200D\U0001F469\u200D\U0001F467")]
    [InlineData("Approve \uE000")]
    [InlineData("Approve \U000F0000")]
    [InlineData("Approve \u0378")]
    [InlineData("Approve\u2028payment")]
    [InlineData("Approve\u2029payment")]
    public async Task AMessageCarryingACodePointThatIsNotPlainText_IsRefused(string bindingMessage)
    {
        Assert.Equal(ErrorCodes.InvalidBindingMessage, (await ValidateAsync(bindingMessage))?.Error);
    }

    /// <summary>
    /// An unpaired surrogate (Cs), high or low, is refused rather than read as a replacement character. Built in the
    /// test rather than given as theory data, which a string that is not valid UTF-16 does not survive serialized.
    /// </summary>
    [Fact]
    public async Task AMessageCarryingAnUnpairedSurrogate_IsRefused()
    {
        Assert.Equal(ErrorCodes.InvalidBindingMessage, (await ValidateAsync("Approve " + (char)0xD83D))?.Error);
        Assert.Equal(ErrorCodes.InvalidBindingMessage, (await ValidateAsync((char)0xDC00 + " Approve"))?.Error);
    }
}
