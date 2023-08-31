# Keycloak SAML Assertion Attribute Filter SPI

There are many cases where you should be able to validate your user's assertion for some attributes presence before log them in. For example all users should be members of some group. Idealy it should be able to be done by Identity Provider post-login flow or custom authentificator with extra assertions, but unforunately it couldn't be done because of some issues

For this issues my plugin is the solution. It's implemented as IDP mapper and when installed filters all users without requested value in selected attribute

## How to Install

1. get plugin JAR from releases
2. drop it into {KC_BASE_DIR}/providers and restart KC
3. in KC go to Identity Providers -> select your IDP -> Mappers -> Create and create mapper of type User Attribute Validator