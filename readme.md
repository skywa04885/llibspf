# SPF Validator Library

Reference: [RFC 7208](https://datatracker.ietf.org/doc/html/rfc7208#section-7)

# Extra Features

These features are (normally) not supported by existing, crappy, implementations.

1. MACROS

# Supported Directives

1. MX
1. A
1. PTR
1. IP4
1. IP6
1. EXISTS
1. INCLUDE
1. ALL

# Supported Modifiers

1. EXP
1. REDIRECT

# Example

```ts
import { IPv4Address } from "llibipaddress";
import { SPFValidator } from "llibspf";
import { MimeHeaders } from "llibmime";
import winston from "winston";

// Creates the example logger.
const logger = winston.createLogger({
  transports: [
    new winston.transports.Console({
      level: "debug",
      format: winston.format.combine(
        winston.format.timestamp({ format: "YYYY-MM-DD HH:mm:ss.SSS" }),
        winston.format.colorize(),
        winston.format.printf(
          ({ level, message, label, timestamp }) =>
            `${timestamp} ${label || "-"} ${level}: ${message}`
        )
      ),
    }),
  ],
});

// Runs the next code using async.
(async () => {
  try {
    // Creates the context, this will be used during the validation and macro processing.
    const context: ISPFContext = {
      message: {
        emailDomain: "rijksoverheid.nl",
        emailUsername: "test123",
      },
      client: {
        greetHostname: "test123",
        ipAddress: IPv4Address.decode("29.85.216.54"),
      },
      server: {
        hostname: "example.com",
      },
    };

    // Constructs the spf validator, and validates.
    const result: SPFResult = await new SPFValidator(
      context,
      logger
    ).validate();

    // Constructs new MimeHeaders class, and puts the result inside it.
    const headers = new MimeHeaders();
    headers.set(...result.asHeader());
    console.log(headers.encode());
  } catch (e) {
    console.log(e);
  }
})();
```
