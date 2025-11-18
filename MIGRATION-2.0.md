# Migration Guide: v1.x → v2.0

This guide helps you migrate from Abblix OIDC Server v1.x to v2.0.

## Table of Contents
- [Breaking Changes Overview](#breaking-changes-overview)
- [Framework Requirements](#framework-requirements)
- [Result Pattern Migration](#result-pattern-migration)
- [Response Type Renaming](#response-type-renaming)
- [Step-by-Step Migration](#step-by-step-migration)
- [Common Patterns](#common-patterns)
- [Troubleshooting](#troubleshooting)

---

## Breaking Changes Overview

v2.0 introduces three major breaking changes:

1. **Result Pattern**: Migrated from exception-based error handling to `Result<TSuccess, TFailure>` pattern
2. **Framework Support**: Dropped .NET 6 and .NET 7 support (now requires .NET 8 or .NET 9)
3. **API Simplification**: Removed redundant 'Response' suffix from all response types

## Framework Requirements

### Minimum Framework Version

**Before (v1.x):**
```xml
<TargetFramework>net6.0</TargetFramework>
<!-- or net7.0, net8.0, net9.0 -->
```

**After (v2.0):**
```xml
<TargetFramework>net8.0</TargetFramework>
<!-- or net9.0 -->
```

### Action Required

1. Update your project's `TargetFramework` to `net8.0` or `net9.0`
2. Update all Microsoft.Extensions.* packages to compatible versions
3. Test your application thoroughly

---

## Result Pattern Migration

The most significant change in v2.0 is the migration to the `Result<TSuccess, TFailure>` pattern.

### Why This Change?

- **Explicit Error Handling**: No more hidden exceptions
- **Better Testability**: Results are easier to test than exception flows
- **Functional Programming**: Aligns with modern C# functional patterns
- **Performance**: Eliminates exception overhead in error scenarios

### Basic Pattern

**Before (v1.x):**
```csharp
// Methods returned success objects or threw exceptions
try
{
    var response = await authorizationHandler.HandleAsync(request, context);

    if (response is SuccessfulAuthorizationResponse success)
    {
        // Handle success
        return Redirect(success.RedirectUri);
    }
    else if (response is AuthorizationErrorResponse error)
    {
        // Handle error
        return BadRequest(error);
    }
}
catch (Exception ex)
{
    // Handle unexpected errors
    return StatusCode(500, ex.Message);
}
```

**After (v2.0):**
```csharp
// Methods return Result<TSuccess, TFailure>
var result = await authorizationHandler.HandleAsync(request, context);

if (result.TryGetSuccess(out var success))
{
    // Handle success
    return Redirect(success.RedirectUri);
}
else if (result.TryGetFailure(out var error))
{
    // Handle error
    return BadRequest(error);
}

// No need for catch block - all errors are in Result
```

### Pattern Matching

You can also use pattern matching:

```csharp
return result switch
{
    { Success: var success } => Redirect(success.RedirectUri),
    { Failure: var error } => BadRequest(error),
};
```

### Working with Results

**Checking for Success:**
```csharp
if (result.TryGetSuccess(out var success))
{
    // Use success value
    Console.WriteLine($"Redirect to: {success.RedirectUri}");
}
```

**Checking for Failure:**
```csharp
if (result.TryGetFailure(out var error))
{
    // Use error value
    Console.WriteLine($"Error: {error.Error} - {error.ErrorDescription}");
}
```

**Direct Access (when you know the state):**
```csharp
// Only use when you're certain of the result state
var success = result.Success;  // Throws if result is a failure
var failure = result.Failure;  // Throws if result is a success
```

---

## Response Type Renaming

All response types have been renamed to remove the redundant 'Response' suffix.

### Authorization Endpoint

```csharp
// Before
SuccessfulAuthorizationResponse → SuccessfulAuthorization
AuthorizationErrorResponse       → AuthorizationError

// After
Result<SuccessfulAuthorization, AuthorizationError>
```

### Token Endpoint

```csharp
// Before
SuccessfulTokenResponse → SuccessfulToken
TokenErrorResponse      → TokenError

// After
Result<SuccessfulToken, TokenError>
```

### UserInfo Endpoint

```csharp
// Before
SuccessfulUserInfoResponse → SuccessfulUserInfo
UserInfoErrorResponse      → UserInfoError

// After
Result<SuccessfulUserInfo, UserInfoError>
```

### Complete Mapping

| v1.x Type | v2.0 Type |
|-----------|-----------|
| `SuccessfulAuthorizationResponse` | `SuccessfulAuthorization` |
| `AuthorizationErrorResponse` | `AuthorizationError` |
| `SuccessfulTokenResponse` | `SuccessfulToken` |
| `TokenErrorResponse` | `TokenError` |
| `SuccessfulUserInfoResponse` | `SuccessfulUserInfo` |
| `UserInfoErrorResponse` | `UserInfoError` |
| `SuccessfulIntrospectionResponse` | `SuccessfulIntrospection` |
| `IntrospectionErrorResponse` | `IntrospectionError` |
| `SuccessfulRevocationResponse` | `SuccessfulRevocation` |
| `RevocationErrorResponse` | `RevocationError` |

**Action Required:**

Find and replace all occurrences of the old type names with new ones.

---

## Step-by-Step Migration

### Step 1: Update Framework

1. Update `TargetFramework` in all `.csproj` files to `net8.0` or `net9.0`
2. Remove any .NET 6 or .NET 7 specific configurations

### Step 2: Update NuGet Packages

```bash
dotnet add package Abblix.OIDC.Server --version 2.0.0
dotnet add package Abblix.JWT --version 2.0.0
dotnet add package Abblix.DependencyInjection --version 2.0.0
```

### Step 3: Update Response Type References

Use Find & Replace in your IDE:

```
Find: SuccessfulAuthorizationResponse
Replace: SuccessfulAuthorization

Find: AuthorizationErrorResponse
Replace: AuthorizationError

(Continue for all response types...)
```

### Step 4: Migrate to Result Pattern

For each handler invocation:

**Before:**
```csharp
var response = await handler.HandleAsync(request, context);
if (response is SuccessfulAuthorization success) { }
```

**After:**
```csharp
var result = await handler.HandleAsync(request, context);
if (result.TryGetSuccess(out var success)) { }
```

### Step 5: Remove Exception Handling (where applicable)

If you were catching exceptions from OIDC handlers, those try-catch blocks can often be removed:

```csharp
// Remove this:
try
{
    var result = await handler.HandleAsync(request, context);
    // ...
}
catch (ValidationException ex)  // These exceptions no longer thrown
{
    return BadRequest(ex.Message);
}
```

### Step 6: Test Thoroughly

1. Run all unit tests
2. Run integration tests
3. Test all OAuth 2.0/OIDC flows manually
4. Verify error handling works as expected

---

## Common Patterns

### Authorization Flow

**Before (v1.x):**
```csharp
public async Task<IActionResult> Authorize([FromQuery] AuthorizationRequest request)
{
    var result = await _authorizationHandler.HandleAsync(request, HttpContext);

    return result switch
    {
        SuccessfulAuthorizationResponse success => Redirect(success.RedirectUri),
        AuthorizationErrorResponse error => BadRequest(error),
        _ => StatusCode(500)
    };
}
```

**After (v2.0):**
```csharp
public async Task<IActionResult> Authorize([FromQuery] AuthorizationRequest request)
{
    var result = await _authorizationHandler.HandleAsync(request, HttpContext);

    return result switch
    {
        { Success: var success } => Redirect(success.RedirectUri),
        { Failure: var error } => BadRequest(error),
    };
}
```

### Token Flow

**Before (v1.x):**
```csharp
public async Task<IActionResult> Token([FromForm] TokenRequest request)
{
    var response = await _tokenHandler.HandleAsync(request, HttpContext);

    if (response is SuccessfulTokenResponse success)
    {
        Response.Headers["Cache-Control"] = "no-store";
        Response.Headers["Pragma"] = "no-cache";
        return Ok(success);
    }

    if (response is TokenErrorResponse error)
    {
        return BadRequest(error);
    }

    return StatusCode(500);
}
```

**After (v2.0):**
```csharp
public async Task<IActionResult> Token([FromForm] TokenRequest request)
{
    var result = await _tokenHandler.HandleAsync(request, HttpContext);

    if (result.TryGetSuccess(out var success))
    {
        Response.Headers["Cache-Control"] = "no-store";
        Response.Headers["Pragma"] = "no-cache";
        return Ok(success);
    }

    if (result.TryGetFailure(out var error))
    {
        return BadRequest(error);
    }

    // This line should never be reached with Result pattern
    throw new InvalidOperationException("Result must be either success or failure");
}
```

### Validation

**Before (v1.x):**
```csharp
var validationResult = await _validator.ValidateAsync(request);
if (validationResult != null)  // null = success
{
    // Validation failed
    return BadRequest(validationResult);
}
```

**After (v2.0):**
```csharp
var validationResult = await _validator.ValidateAsync(request);
if (validationResult.TryGetFailure(out var error))
{
    return BadRequest(error);
}
```

---

## Troubleshooting

### Issue: Compilation errors after upgrade

**Symptom:** Lots of compiler errors about missing types

**Solution:**
1. Ensure you've updated to v2.0.0 of all Abblix packages
2. Run `dotnet restore` to ensure packages are restored
3. Clean and rebuild: `dotnet clean && dotnet build`

### Issue: Pattern matching doesn't work

**Symptom:** `Cannot use property 'Success' in this context`

**Solution:** Use `TryGetSuccess()` and `TryGetFailure()` methods instead of direct property access:

```csharp
// Don't do this:
if (result.Success != null)  // Won't compile

// Do this instead:
if (result.TryGetSuccess(out var success))
```

### Issue: Missing using statements

**Symptom:** `Result<,>` type not found

**Solution:** Add using statement:
```csharp
using Abblix.Utils;
```

### Issue: Tests failing after migration

**Symptom:** Unit tests fail with `NullReferenceException`

**Solution:** Update test assertions to work with Result pattern:

```csharp
// Before
var response = await handler.HandleAsync(request, context);
Assert.IsType<SuccessfulAuthorization>(response);

// After
var result = await handler.HandleAsync(request, context);
Assert.True(result.TryGetSuccess(out var success));
Assert.NotNull(success);
```

---

## Need Help?

- 📖 [Documentation](https://docs.abblix.com/)
- 💬 [GitHub Discussions](https://github.com/Abblix/Oidc.Server/discussions)
- 🐛 [Report Issues](https://github.com/Abblix/Oidc.Server/issues)
- 📧 [Email Support](mailto:info@abblix.com)

---

**Note:** If you encounter issues not covered in this guide, please [open an issue](https://github.com/Abblix/Oidc.Server/issues) or [start a discussion](https://github.com/Abblix/Oidc.Server/discussions).
