<a name="top"></a>
[![Abblix OIDC Server](https://resources.abblix.com/imgs/jpg/abblix-oidc-server-github-banner.jpg)](https://www.abblix.com/abblix-oidc-server)
[![.NET](https://img.shields.io/badge/.NET-8.0%2C%209.0%2C%2010.0-512BD4)](https://docs.abblix.com/docs/technical-requirements)
[![language](https://img.shields.io/badge/language-C%23-239120)](https://learn.microsoft.com/ru-ru/dotnet/csharp/tour-of-csharp/overview)
[![OS](https://img.shields.io/badge/OS-linux%2C%20windows%2C%20macOS-0078D4)](https://docs.abblix.com/docs/technical-requirements)
[![CPU](https://img.shields.io/badge/CPU-x86%2C%20x64%2C%20ARM%2C%20ARM64-FF8C00)](https://docs.abblix.com/docs/technical-requirements)
[![security rating](https://sonarcloud.io/api/project_badges/measure?project=Abblix_Oidc.Server&metric=security_rating)](https://sonarcloud.io/summary/overall?id=Abblix_Oidc.Server)
[![reliability rating](https://sonarcloud.io/api/project_badges/measure?project=Abblix_Oidc.Server&metric=reliability_rating)](https://sonarcloud.io/summary/overall?id=Abblix_Oidc.Server)
[![maintainability rating](https://sonarcloud.io/api/project_badges/measure?project=Abblix_Oidc.Server&metric=sqale_rating)](https://sonarcloud.io/summary/overall?id=Abblix_Oidc.Server)
[![CodeQL analysis](https://github.com/Abblix/Oidc.Server/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/Abblix/Oidc.Server/security/code-scanning?query=is%3Aopen)
[![tests](https://img.shields.io/badge/tests-2000+%20passing-brightgreen)](https://github.com/Abblix/Oidc.Server/tree/master/Abblix.Oidc.Server.UnitTests)
[![GitHub release](https://img.shields.io/github/v/release/Abblix/Oidc.Server)](#)
[![GitHub release date](https://img.shields.io/github/release-date/Abblix/Oidc.Server)](#)
[![GitHub last commit](https://img.shields.io/github/last-commit/Abblix/Oidc.Server)](#)
[![getting started](https://img.shields.io/badge/getting_started-guide-1D76DB)](https://docs.abblix.com/docs/getting-started-guide)
[![Free](https://img.shields.io/badge/free_for_non_commercial_use-brightgreen)](#-license)

⭐ Star us on GitHub — your support motivates us a lot! 🙏😊

[![Share](https://img.shields.io/badge/share-000000?logo=x&logoColor=white)](https://x.com/intent/tweet?text=Check%20out%20this%20project%20on%20GitHub:%20https://github.com/Abblix/Oidc.Server%20%23OpenIDConnect%20%23Security%20%23Authentication)
[![Share](https://img.shields.io/badge/share-1877F2?logo=facebook&logoColor=white)](https://www.facebook.com/sharer/sharer.php?u=https://github.com/Abblix/Oidc.Server)
[![Share](https://img.shields.io/badge/share-0A66C2?logo=linkedin&logoColor=white)](https://www.linkedin.com/sharing/share-offsite/?url=https://github.com/Abblix/Oidc.Server)
[![Share](https://img.shields.io/badge/share-FF4500?logo=reddit&logoColor=white)](https://www.reddit.com/submit?title=Check%20out%20this%20project%20on%20GitHub:%20https://github.com/Abblix/Oidc.Server)
[![Share](https://img.shields.io/badge/share-0088CC?logo=telegram&logoColor=white)](https://t.me/share/url?url=https://github.com/Abblix/Oidc.Server&text=Check%20out%20this%20project%20on%20GitHub)

🔥 Why OIDC Server is the best choice for authentication — find out in our [presentation](https://resources.abblix.com/pdf/abblix-oidc-server-presentation-eng.pdf) 📑

## Table of Contents
- [About](#-about)
- [What's New](#-whats-new)
- [Certification](#-certification)
- [How to Build](#-how-to-build)
- [Documentation](#-documentation)
- [Feedback and Contributions](#-feedback-and-contributions)
- [License](#-license)
- [Contacts](#%EF%B8%8F-contacts)

## 🚀 About

**Abblix OIDC Server** is a .NET library designed to provide comprehensive support for OAuth2 and OpenID Connect on the server side. It adheres to high standards of flexibility, reusability, and reliability, utilizing well-known software design patterns, including modular and hexagonal architectures. These patterns ensure the following benefits:

- **Modularity**: Different parts of the library can function independently, enhancing the library's modularity and allowing for easier maintenance and updates.
- **Testability**: Improved separation of concerns makes the code more testable.
- **Maintainability**: Clear structure and separation facilitate better management of the codebase.

The library also supports Dependency Injection through the standard .NET DI container, aiding in the organization and management of code. Specifically tailored for seamless integration with ASP.NET WebApi, Abblix OIDC Server employs standard controller classes, binding, and routing mechanisms, simplifying the integration of OpenID Connect into your services.

## ✨ What's New

### Version 2.2 (Latest)

🚀 **Features**
- **Custom JWT Implementation**: Complete JWT signing/encryption infrastructure replacing `Microsoft.IdentityModel.Tokens` — uses `System.Text.Json.Nodes` and .NET crypto primitives directly
- **Enhanced JWE Algorithms**: `RSA-OAEP-256`, AES-GCM key wrapping (`A128GCMKW`/`A192GCMKW`/`A256GCMKW`), and direct key agreement (`dir`)
- **ACR/AMR Compliance (RFC 8176)**: Authentication Context Class Reference values in discovery and RFC 8176 Authentication Method References
- **CSP Nonce Support**: Template-based front-channel logout and check session iframe compatible with strict Content Security Policies

✏️ **Improvements**
- Configurable session cookie path in OIDC Session Management
- Operation capability validation for `JsonWebKey` classes
- Bidirectional interoperability tests with `Microsoft.IdentityModel.Tokens`

> See 📋[Release Notes](https://github.com/Abblix/Oidc.Server/releases/tag/v2.2) for full details.

## 🎓 Certification

[![OpenID Foundation Certification](https://resources.abblix.com/imgs/svg/abblix-oidc-server-openid-foundation-certification-mark.svg)](https://oidc.abblix.com/certified-profiles)

We are certified in all profiles. During the certification process, we skipped ZERO tests and received NO warnings. All **634** tests ![Passed](https://img.shields.io/badge/PASSED-brightgreen). We are extremely proud of this achievement. It reflects our overall approach to any endeavor. For more details, click the links ([Certified OpenID Providers & Profiles](https://oidc.abblix.com/certified-profiles), [Certified OpenID Providers for Logout Profiles](https://oidc.abblix.com/certified-logout-profiles)).

For convenience, the certification information is provided in the tables below:

### Regular Profiles
|OIDC Profile|Response Types (links to official OpenID Foundation test results)|Tests|
|:-|:-|:-|
|Basic OP|[code](https://www.certification.openid.net/plan-detail.html?public=true&plan=vaSiS5JvFcWr2)|36|
|Implicit OP|[id_token](https://www.certification.openid.net/plan-detail.html?public=true&plan=PHYWpi4iBLDmq)|58|
|Hybrid OP|[code id_token](https://www.certification.openid.net/plan-detail.html?public=true&plan=HPb7q9DYsfgcf)|102|
|Config OP|[config](https://www.certification.openid.net/plan-detail.html?public=true&plan=kcQTPdtyz1bt5)|1|
|Dynamic OP|[code](https://www.certification.openid.net/plan-detail.html?public=true&plan=Ie4igUuhKheHC) \| [code id_token](https://www.certification.openid.net/plan-detail.html?public=true&plan=wz8WwocsxeXLG) \| [code id_token token](https://www.certification.openid.net/plan-detail.html?public=true&plan=Vz0xyMMiabOuT) \| [code token](https://www.certification.openid.net/plan-detail.html?public=true&plan=di3sWIakE1NfO) \| [id_token](https://www.certification.openid.net/plan-detail.html?public=true&plan=siWnWnxc0F25Q) \| [id_token token](https://www.certification.openid.net/plan-detail.html?public=true&plan=sErNAjGZuRNMX)|127|
|Form Post OP|[basic](https://www.certification.openid.net/plan-detail.html?public=true&plan=2hkxl3otFUbdm) \| [implicit](https://www.certification.openid.net/plan-detail.html?public=true&plan=81Tzj22qYpFCy) \| [hybrid](https://www.certification.openid.net/plan-detail.html?public=true&plan=ywUWjGPWsyFuS)|196|
|3rd Party-Init OP|[code](https://www.certification.openid.net/plan-detail.html?public=true&plan=GB6nP470pDdVe) \| [code id_token](https://www.certification.openid.net/plan-detail.html?public=true&plan=M89emXc0N5GMF) \| [code id_token token](https://www.certification.openid.net/plan-detail.html?public=true&plan=pe5s8Gus3Uz3y) \| [code token](https://www.certification.openid.net/plan-detail.html?public=true&plan=JNX5OGMAKr2kr) \| [id_token](https://www.certification.openid.net/plan-detail.html?public=true&plan=gfI5xgx8UGzOL) \| [id_token token](https://www.certification.openid.net/plan-detail.html?public=true&plan=k4e0SJnvHGuu9)|12|
|**Total**||**532**|

### Logout Profiles

|OIDC Profile|Response Types (links to official OpenID Foundation test results)|Tests|
|:-|:-|:-|
|RP-Initiated OP|[code](https://www.certification.openid.net/plan-detail.html?public=true&plan=VPaBRT8VQQXhH) \| [code id_token](https://www.certification.openid.net/plan-detail.html?public=true&plan=WY5LQ9JYgTUdJ) \| [code id_token token](https://www.certification.openid.net/plan-detail.html?public=true&plan=nt4LY7vwN3ACO) \| [code token](https://www.certification.openid.net/plan-detail.html?public=true&plan=jLhRFKJXYJuEK) \| [id_token](https://www.certification.openid.net/plan-detail.html?public=true&plan=hwROnePvJvrXe) \| [id_token token](https://www.certification.openid.net/plan-detail.html?public=true&plan=3CVp7fx4TQX1H)|66|
|Session OP|[code](https://www.certification.openid.net/plan-detail.html?public=true&plan=N3Tsp7nigWMiS) \| [code id_token](https://www.certification.openid.net/plan-detail.html?public=true&plan=KqBqsHxH4vN03) \| [code id_token token](https://www.certification.openid.net/plan-detail.html?public=true&plan=KCwP7JqmXbcPf) \| [code token](https://www.certification.openid.net/plan-detail.html?public=true&plan=MJxcSnziJTOaa) \| [id_token](https://www.certification.openid.net/plan-detail.html?public=true&plan=9sZ9qkcq8VY1O) \| [id_token token](https://www.certification.openid.net/plan-detail.html?public=true&plan=OrRc3cBBm53OK)|12|
|Front-Channel OP|[code](https://www.certification.openid.net/plan-detail.html?public=true&plan=FCIMtfChd8JUR) \| [code id_token](https://www.certification.openid.net/plan-detail.html?public=true&plan=UPqVQppkBai8Q) \| [code id_token token](https://www.certification.openid.net/plan-detail.html?public=true&plan=TK2z4lTRgeU0O) \| [code token](https://www.certification.openid.net/plan-detail.html?public=true&plan=ntjIMSdbzeBJN) \| [id_token](https://www.certification.openid.net/plan-detail.html?public=true&plan=0SfPTdERrzANP) \| [id_token token](https://www.certification.openid.net/plan-detail.html?public=true&plan=RLQm9h40E4j1k)|12|
|Back-Channel OP|[code](https://www.certification.openid.net/plan-detail.html?public=true&plan=5kbQfVOWmJV76) \| [code id_token](https://www.certification.openid.net/plan-detail.html?public=true&plan=VWmk225h0coIZ) \| [code id_token token](https://www.certification.openid.net/plan-detail.html?public=true&plan=YzDOT2LFWi4X7) \| [code token](https://www.certification.openid.net/plan-detail.html?public=true&plan=RxPPCdLI7LlcR) \| [id_token](https://www.certification.openid.net/plan-detail.html?public=true&plan=x73qpcrHcFWv0) \| [id_token token](https://www.certification.openid.net/plan-detail.html?public=true&plan=uYoYs5BFAZkgr)|12|
|**Total**||**102**|

## 📝 How to Build

To build the packages, follow these steps:

```shell
# Open a terminal (Command Prompt or PowerShell for Windows, Terminal for macOS or Linux)

# Ensure Git is installed
# Visit https://git-scm.com to download and install console Git if not already installed

# Clone the repository
git clone https://github.com/Abblix/Oidc.Server.git

# Navigate to the project directory
cd Oidc.Server

# Check if .NET SDK is installed
dotnet --version  # Check the installed version of .NET SDK
# Visit the official Microsoft website to install or update it if necessary

# Restore dependencies
dotnet restore

# Compile the project
dotnet build

```
## 📚 Documentation

### Getting Started
Explore the [Getting Started Guide](https://docs.abblix.com/docs/getting-started-guide).
In this guide, you will create a working solution step by step, building an OpenID Connect Provider using ASP.NET MVC and the Abblix OIDC Server solution.

To better understand the Abblix OIDC Server product, we recommend visiting our [Documentation](https://docs.abblix.com/docs) site. There, you will find useful information about the product and the OpenID Connect standard.

## 🤝 Feedback and Contributions

We've made every effort to implement all the main aspects of the OpenID protocol in the best possible way. However, the development journey doesn't end here, and your input is crucial for our continuous improvement.

> [!IMPORTANT]
> Whether you have feedback on features, have encountered any bugs, or have suggestions for enhancements, we're eager to hear from you. Your insights help us make the Abblix OIDC Server library more robust and user-friendly.

Please feel free to contribute by [submitting an issue](https://github.com/Abblix/Oidc.Server/issues) or [joining the discussions](https://github.com/orgs/Abblix/discussions). Each contribution helps us grow and improve.

We appreciate your support and look forward to making our product even better with your help!

## 📃 License

This product is distributed under a proprietary license. See📋[License Agreement](LICENSE.md) for details.

For non-commercial use, this product is available for free.

## 🗨️ Contacts

For more details about our products, services, or any general information regarding the Abblix OIDC Server, feel free to reach out to us. We are here to provide support and answer any questions you may have. Below are the best ways to contact our team:

- **Email**: Send us your inquiries or support requests at [support@abblix.com](mailto:support@abblix.com).
- **Website**: Visit the official Abblix OIDC Server page for more information: [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server).

Subscribe to our LinkedIn and Twitter:

[![LinkedIn](https://img.shields.io/badge/subscribe-white.svg?logo=data:image/svg%2bxml;base64,PHN2ZyB2aWV3Qm94PSIwIDAgMjQgMjQiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHBhdGggZD0iTTIwLjQ0NyAyMC40NTJoLTMuNTU0di01LjU2OWMwLTEuMzI4LS4wMjctMy4wMzctMS44NTItMy4wMzctMS44NTMgMC0yLjEzNiAxLjQ0NS0yLjEzNiAyLjkzOXY1LjY2N0g5LjM1MVY5aDMuNDE0djEuNTYxaC4wNDZjLjQ3Ny0uOSAxLjYzNy0xLjg1IDMuMzctMS44NSAzLjYwMSAwIDQuMjY3IDIuMzcgNC4yNjcgNS40NTV2Ni4yODZ6TTUuMzM3IDcuNDMzYTIuMDYyIDIuMDYyIDAgMCAxLTIuMDYzLTIuMDY1IDIuMDY0IDIuMDY0IDAgMSAxIDIuMDYzIDIuMDY1em0xLjc4MiAxMy4wMTlIMy41NTVWOWgzLjU2NHYxMS40NTJ6TTIyLjIyNSAwSDEuNzcxQy43OTIgMCAwIC43NzQgMCAxLjcyOXYyMC41NDJDMCAyMy4yMjcuNzkyIDI0IDEuNzcxIDI0aDIwLjQ1MUMyMy4yIDI0IDI0IDIzLjIyNyAyNCAyMi4yNzFWMS43MjlDMjQgLjc3NCAyMy4yIDAgMjIuMjIyIDBoLjAwM3oiIGZpbGw9IiMwQTY2QzIiLz48cGF0aCBzdHlsZT0iZmlsbDojZmZmO3N0cm9rZS13aWR0aDouMDIwOTI0MSIgZD0iTTQuOTE3IDcuMzc3YTIuMDUyIDIuMDUyIDAgMCAxLS4yNC0zLjk0OWMxLjEyNS0uMzg0IDIuMzM5LjI3NCAyLjY1IDEuNDM3LjA2OC4yNS4wNjguNzY3LjAwMSAxLjAxYTIuMDg5IDIuMDg5IDAgMCAxLTEuNjIgMS41MSAyLjMzNCAyLjMzNCAwIDAgMS0uNzktLjAwOHoiLz48cGF0aCBzdHlsZT0iZmlsbDojZmZmO3N0cm9rZS13aWR0aDouMDIwOTI0MSIgZD0iTTQuOTE3IDcuMzc3YTIuMDU2IDIuMDU2IDAgMCAxLTEuNTItMi42NyAyLjA0NyAyLjA0NyAwIDAgMSAzLjQxOS0uNzU2Yy4yNC4yNTQuNDIuNTczLjUxMi45MDguMDY1LjI0LjA2NS43OCAwIDEuMDItLjA1MS4xODYtLjE5Ny41MDQtLjMuNjUyLS4wOS4xMzItLjMxLjM2Mi0uNDQzLjQ2NC0uNDYzLjM1Ny0xLjEuNTAzLTEuNjY4LjM4MlpNMy41NTcgMTQuNzJWOS4wMDhoMy41NTd2MTEuNDI0SDMuNTU3Wk05LjM1MyAxNC43MlY5LjAwOGgzLjQxMXYuNzg1YzAgLjYxNC4wMDUuNzg0LjAyNi43ODMuMDE0IDAgLjA3LS4wNzMuMTI0LS4xNjIuNTI0LS44NjUgMS41MDgtMS40NzggMi42NS0xLjY1LjI3NS0uMDQyIDEtLjA0NyAxLjMzMi0uMDA5Ljc5LjA5IDEuNDUxLjMxNiAxLjk0LjY2NC4yMi4xNTcuNTU3LjQ5My43MTQuNzEzLjQyLjU5Mi42OSAxLjQxMi44MDggMi40NjQuMDc0LjY2My4wODQgMS4yMTUuMDg1IDQuNTc4djMuMjU4aC0zLjUzNnYtMi45ODZjMC0yLjk3LS4wMS0zLjQ3NC0uMDc0LTMuOTA4LS4wOS0uNjA2LS4zMTQtMS4wODItLjYzNC0xLjM0Mi0uMzk1LS4zMjItMS4wMjktLjQzNy0xLjcwMy0uMzA5LS44NTguMTYzLTEuMzU1Ljc1LTEuNTIzIDEuNzk3LS4wNzYuNDcxLS4wODQuODQ1LS4wODQgMy44MzR2Mi45MTRIOS4zNTN6Ii8+PC9zdmc+)](https://www.linkedin.com/company/103540510/)
[![X](https://img.shields.io/badge/subscribe-white.svg?logo=data:image/svg%2bxml;base64,PHN2ZyB2aWV3Qm94PSIwIDAgMjQgMjQiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHBhdGggZD0iTTE4LjkwMSAxLjE1M2gzLjY4bC04LjA0IDkuMTlMMjQgMjIuODQ2aC03LjQwNmwtNS44LTcuNTg0LTYuNjM4IDcuNTg0SC40NzRsOC42LTkuODNMMCAxLjE1NGg3LjU5NGw1LjI0MyA2LjkzMlpNMTcuNjEgMjAuNjQ0aDIuMDM5TDYuNDg2IDMuMjRINC4yOThaIi8+PHBhdGggc3R5bGU9ImZpbGw6I2ZmZjtzdHJva2Utd2lkdGg6LjAyMDkyNDEiIGQ9Ik0xMS4wMzYgMTIuMDI4IDQuMzg3IDMuMzM0bC0uMDYtLjA4SDYuNDhsNi41MTYgOC42MTQgNi41NzUgOC42OTQuMDYuMDhoLTIuMDA2eiIvPjwvc3ZnPg==)](https://twitter.com/OIDCServer)

We look forward to assisting you and ensuring your experience with our products is successful and enjoyable!

[Back to top](#top)
