import { IPv4Address, IPv6Address } from "llibipaddress";
import { ISPFContext } from "./SPFContext";
import { SPFRecord } from "./SPFRecord";
import dns from "dns";
import util from "util";
import { SPFNetworkingError, SPFSyntacticalError } from "./SPFErrors";

export enum SPFDirectiveMechanismKeywords {
  A = "a",
  MX = "mx",
  PTR = "ptr",
  IPv4 = "ip4",
  IPv6 = "ip6",
  Exists = "exists",
  All = "all",
  Include = "include",
}

export enum SPFDirectiveQualifier {
  Pass,
  Fail,
  SoftFail,
  Neutral,
}

/**
 * Parses an raw SPF Directive's qualifier.
 * @param raw the raw qualifier.
 * @returns the qualifier enum value.
 */
export const spf_directive_qualifier_parse = (
  raw: string
): SPFDirectiveQualifier => {
  if (raw.length !== 1) {
    throw new SPFSyntacticalError("SPF Qualifier's length must be 1.");
  }

  switch (raw) {
    case "+":
      return SPFDirectiveQualifier.Pass;
    case "-":
      return SPFDirectiveQualifier.Fail;
    case "?":
      return SPFDirectiveQualifier.SoftFail;
    case "~":
      return SPFDirectiveQualifier.Neutral;
    default:
      throw new SPFSyntacticalError(
        'Unknown qualifier, must be "+" / "-" / "?" / "~"!'
      );
  }
};

export class SPFMechanismResult {
  public constructor(
    public match: boolean,
    public reason: string | null = null
  ) {}
}

/////////////////////////////////////////////////
// Mechanism Extensible Class.
/////////////////////////////////////////////////

export class SPFMechanism {
  /**
   * Performs the validation of the current mechanism, using the supplied context.
   * @param context the context of the validation.
   * @returns the result of the validation.
   */
  public async match(context: ISPFContext): Promise<SPFMechanismResult> {
    return new SPFMechanismResult(
      false,
      "Mechanism has no validation implemented."
    );
  }

  /**
   * Gets the string version of the mechanism.
   * @returns the string version.
   */
  public toString(): string {
    throw new Error("Not implemented!");
  }
}

/////////////////////////////////////////////////
// Mechanism All Class.
/////////////////////////////////////////////////

export class SPFAllMechanism extends SPFMechanism {
  /**
   * Parses the current mechanism.
   * @param value the value of the key/value pair.
   * @returns the parsed mechanism.
   */
  public static parse(value: string | null): SPFAllMechanism {
    if (value !== null) {
      throw new SPFSyntacticalError(
        '"all" mechanism may not have ANY argument!'
      );
    }

    return new this();
  }

  /**
   * Performs the validation of the current mechanism, using the supplied context.
   * @param context the context of the validation.
   * @returns the result of the validation.
   */
  public async match(context: ISPFContext): Promise<SPFMechanismResult> {
    return new SPFMechanismResult(true);
  }

  /**
   * Gets the string version of the mechanism.
   * @returns the string version.
   */
  public toString(): string {
    return `${SPFDirectiveMechanismKeywords.All}`;
  }
}

/////////////////////////////////////////////////
// Mechanism Include Class.
/////////////////////////////////////////////////

export class SPFIncludeMechanism extends SPFMechanism {
  public constructor(
    public readonly domain: string,
    public readonly record: SPFRecord | null = null
  ) {
    super();
  }

  /**
   * Parses the current mechanism.
   * @param value the value of the key/value pair.
   * @returns the parsed mechanism.
   */
  public static parse(value: string | null): SPFAllMechanism {
    if (value === null) {
      throw new SPFSyntacticalError(
        '"include" mechanism must have one domain argument!'
      );
    }

    return new this(value);
  }

  /**
   * Performs the validation of the current mechanism, using the supplied context.
   * @param context the context of the validation.
   * @returns the result of the validation.
   */
  public async match(context: ISPFContext): Promise<SPFMechanismResult> {
    // Gets the SPF record of the given domain.
    const spfRecord: SPFRecord | null = await SPFRecord.resolve(
      this.domain,
      context
    );
    if (spfRecord === null) {
      throw new SPFNetworkingError(
        `Could not include SPF record for: ${this.domain}`
      );
    }

    // Matches the directives... We only will use PASS ones
    //  the rest like fail, are ignored.
    for (const directive of spfRecord.directives) {
      // Gets the qualifier and the mechanism.
      const qualifier: SPFDirectiveQualifier = directive.qualifier;
      const mechanism: SPFMechanism = directive.mechanism;

      // Matches the mechanism.
      const mechanismResult: SPFMechanismResult = await mechanism.match(
        context
      );

      // Checks if the mechanism result passed, if so return a true.
      if (mechanismResult.match === true && qualifier === SPFDirectiveQualifier.Pass) {
        return new SPFMechanismResult(true, `${mechanism.toString()} matched.`);
      }
    }

    // Default returning, nothing matched.
    return new SPFMechanismResult(false);
  }

  /**
   * Gets the string version of the mechanism.
   * @returns the string version.
   */
  public toString(): string {
    return `${SPFDirectiveMechanismKeywords.Include}:${this.domain}`;
  }
}

/////////////////////////////////////////////////
// Mechanism A Class.
/////////////////////////////////////////////////

export class SPFAMechanism extends SPFMechanism {
  public constructor(public readonly domain: string | null) {
    super();
  }

  /**
   * Parses the current mechanism.
   * @param value the value of the key/value pair.
   * @returns the parsed mechanism.
   */
  public static parse(value: string | null): SPFAllMechanism {
    return new this(value);
  }

  /**
   * Performs the validation of the current mechanism, using the supplied context.
   * @param context the context of the validation.
   * @returns the result of the validation.
   */
  public async match(context: ISPFContext): Promise<SPFMechanismResult> {
    if (context.client.ipAddress instanceof IPv4Address) {
      // Resolves the A records of the current domain, or of the domain in the context.
      const rawAddresses: string[] = await util.promisify(dns.resolve4)(
        this.domain ?? context.message.emailDomain
      );

      // Parses the raw addresses.
      const addresses: IPv4Address[] = rawAddresses.map(
        (address: string): IPv4Address => IPv4Address.decode(address)
      );

      // Matches the client IP address against the addresses in the array.
      for (const address of addresses) {
        if (address.cidr && context.client.ipAddress.cidr_match(address)) {
          return new SPFMechanismResult(
            true,
            `Clients IPv4 ${context.client.ipAddress.encode()} is in the CIDR range ${address.encode()}`
          );
        } else if (!address.cidr && context.client.ipAddress.equals(address)) {
          return new SPFMechanismResult(
            true,
            `Clients IPv4 ${context.client.ipAddress.encode()} is mentioned in A record.`
          );
        }
      }

      // We didn't match, return false.
      return new SPFMechanismResult(
        false,
        `Clients IPv4 ${context.client.ipAddress.encode()} is not mentioned, nor in any CIDR range.`
      );
    } else if (context.client.ipAddress instanceof IPv6Address) {
      // Resolves the A records of the current domain, or of the domain in the context.
      const rawAddresses: string[] = await util.promisify(dns.resolve6)(
        this.domain ?? context.message.emailDomain
      );

      // Parses the raw addresses.
      const addresses: IPv6Address[] = rawAddresses.map(
        (address: string): IPv6Address => IPv6Address.decode(address)
      );

      // Matches the client IP address against the addresses in the array.
      for (const address of addresses) {
        if (address.cidr && context.client.ipAddress.cidr_match(address)) {
          return new SPFMechanismResult(
            true,
            `Clients IPv6 ${context.client.ipAddress.encode()} is in the CIDR range ${address.encode()}`
          );
        } else if (!address.cidr && context.client.ipAddress.equals(address)) {
          return new SPFMechanismResult(
            true,
            `Clients IPv6 ${context.client.ipAddress.encode()} is mentioned in A record.`
          );
        }
      }

      // We didn't match, return false.
      return new SPFMechanismResult(
        false,
        `Clients IPv6 ${context.client.ipAddress.encode()} is not mentioned, nor in any CIDR range.`
      );
    } else {
      throw new SPFSyntacticalError("Client IP address not IPv4 or IPv6!");
    }
  }

  /**
   * Gets the string version of the mechanism.
   * @returns the string version.
   */
  public toString(): string {
    if (this.domain !== null) {
      return `${SPFDirectiveMechanismKeywords.A}:${this.domain}`;
    }

    return SPFDirectiveMechanismKeywords.A;
  }
}

/////////////////////////////////////////////////
// Mechanism MX Class.
/////////////////////////////////////////////////

export class SPFMXMechanism extends SPFMechanism {
  public constructor(public readonly domain: string | null) {
    super();
  }

  /**
   * Parses the current mechanism.
   * @param value the value of the key/value pair.
   * @returns the parsed mechanism.
   */
  public static parse(value: string | null): SPFAllMechanism {
    return new this(value);
  }

  /**
   * Performs the validation of the current mechanism, using the supplied context.
   * @param context the context of the validation.
   * @returns the result of the validation.
   */
  public async match(context: ISPFContext): Promise<SPFMechanismResult> {
    // Gets all the mail exchanges.
    const mailExchanges: dns.MxRecord[] = await util.promisify(dns.resolveMx)(
      this.domain ?? context.message.emailDomain
    );

    // Validates depending on the IP address type.
    if (context.client.ipAddress instanceof IPv4Address) {
      // Gets all the addresses to match against.
      const addresses: IPv4Address[] = (
        await Promise.all(
          mailExchanges.map(
            async (mx: dns.MxRecord, index: number): Promise<IPv4Address[]> => {
              const rawAddresses: string[] = await util.promisify(dns.resolve4)(
                mx.exchange
              );
              return rawAddresses.map(
                (address: string, index: number): IPv4Address =>
                  IPv4Address.decode(address)
              );
            }
          )
        )
      ).flat();

      // Matches against all the addresses.
      for (const address of addresses) {
        if (address.equals(context.client.ipAddress)) {
          return new SPFMechanismResult(
            true,
            `Client IPv4 ${context.client.ipAddress.encode()} is mentioned as mail exchange.`
          );
        }
      }

      // Returns false.
      return new SPFMechanismResult(
        false,
        `Client IPv4 ${context.client.ipAddress.encode()} not mentioned as mail exchange.`
      );
    } else if (context.client.ipAddress instanceof IPv6Address) {
      // Gets all the addresses to match against.
      const addresses: IPv6Address[] = (
        await Promise.all(
          mailExchanges.map(
            async (mx: dns.MxRecord, index: number): Promise<IPv6Address[]> => {
              const rawAddresses: string[] = await util.promisify(dns.resolve6)(
                mx.exchange
              );
              return rawAddresses.map(
                (address: string, index: number): IPv6Address =>
                  IPv6Address.decode(address)
              );
            }
          )
        )
      ).flat();

      // Matches against all the addresses.
      for (const address of addresses) {
        if (address.equals(context.client.ipAddress)) {
          return new SPFMechanismResult(
            true,
            `Client IPv6 ${context.client.ipAddress.encode()} is mentioned as mail exchange.`
          );
        }
      }

      // Returns false.
      return new SPFMechanismResult(
        false,
        `Client IPv6 ${context.client.ipAddress.encode()} not mentioned as mail exchange.`
      );
    } else {
      throw new SPFSyntacticalError("Client IP address not IPv4 or IPv6!");
    }
  }

  /**
   * Gets the string version of the mechanism.
   * @returns the string version.
   */
  public toString(): string {
    if (this.domain !== null) {
      return `${SPFDirectiveMechanismKeywords.MX}:${this.domain}`;
    }

    return SPFDirectiveMechanismKeywords.MX;
  }
}

/////////////////////////////////////////////////
// Mechanism PTR Class.
/////////////////////////////////////////////////

export class SPFPTRMechanism extends SPFMechanism {
  public constructor(public readonly domain: string) {
    super();
  }

  /**
   * Parses the current mechanism.
   * @param value the value of the key/value pair.
   * @returns the parsed mechanism.
   */
  public static parse(value: string | null): SPFAllMechanism {
    if (value === null) {
      throw new SPFSyntacticalError("PTR Records needs value.");
    }

    return new this(value);
  }

  /**
   * Performs the validation of the current mechanism, using the supplied context.
   * @param context the context of the validation.
   * @returns the result of the validation.
   */
  public async match(context: ISPFContext): Promise<SPFMechanismResult> {
    // Performs the reverse lookup of all the hostnames.
    const hostnames: string[] = await util.promisify(dns.reverse)(
      context.client.ipAddress.encode()
    );

    // Checks if any of them matches.
    for (const hostname of hostnames) {
      if (hostname.endsWith(this.domain)) {
        return new SPFMechanismResult(
          true,
          `Reverse lookup of ${context.client.ipAddress.encode()} resulted in matching hostname: ${hostname}`
        );
      }
    }

    // We did not match.
    return new SPFMechanismResult(false);
  }

  /**
   * Gets the string version of the mechanism.
   * @returns the string version.
   */
  public toString(): string {
    if (this.domain !== null) {
      return `${SPFDirectiveMechanismKeywords.MX}:${this.domain}`;
    }

    return SPFDirectiveMechanismKeywords.PTR;
  }
}

/////////////////////////////////////////////////
// Mechanism IPv4 Class.
/////////////////////////////////////////////////

export class SPFIPv4Mechanism extends SPFMechanism {
  public constructor(public readonly address: IPv4Address) {
    super();
  }

  /**
   * Parses the current mechanism.
   * @param value the value of the key/value pair.
   * @returns the parsed mechanism.
   */
  public static parse(value: string | null): SPFAllMechanism {
    if (value === null) {
      throw new SPFSyntacticalError(
        '"ip4" mechanism must have one IPv4 Address argument!'
      );
    }

    // Parses the address.
    let address: IPv4Address;
    try {
      address = IPv4Address.decode(value);
    } catch (e) {
      throw new SPFSyntacticalError(`Invalid IPv4 Address: ${e}`);
    }

    // Returns the mechanism with the parsed address.
    return new this(address);
  }

  /**
   * Performs the validation of the current mechanism, using the supplied context.
   * @param context the context of the validation.
   * @returns the result of the validation.
   */
  public async match(context: ISPFContext): Promise<SPFMechanismResult> {
    if (context.client.ipAddress instanceof IPv6Address) {
      return new SPFMechanismResult(false);
    }

    if (this.address.cidr && context.client.ipAddress.cidr_match(this.address)) {
      return new SPFMechanismResult(
        true,
        `${context.client.ipAddress.encode()} is in CIDR range of ${this.address.encode()}`
      );
    } else if (
      !this.address.cidr &&
      context.client.ipAddress.equals(this.address)
    ) {
      return new SPFMechanismResult(
        true,
        `${context.client.ipAddress.encode()} is listed as IPv4 address`
      );
    }

    return new SPFMechanismResult(false);
  }

  /**
   * Gets the string version of the mechanism.
   * @returns the string version.
   */
  public toString(): string {
    return `${SPFDirectiveMechanismKeywords.IPv4}:${this.address.encode()}`;
  }
}

/////////////////////////////////////////////////
// Mechanism IPv6 Class.
/////////////////////////////////////////////////

export class SPFIPv6Mechanism extends SPFMechanism {
  public constructor(public readonly address: IPv6Address) {
    super();
  }

  /**
   * Parses the current mechanism.
   * @param value the value of the key/value pair.
   * @returns the parsed mechanism.
   */
  public static parse(value: string | null): SPFAllMechanism {
    if (value === null) {
      throw new SPFSyntacticalError(
        '"ip6" mechanism must have one IPv6 Address argument!'
      );
    }

    // Parses the address.
    let address: IPv6Address;
    try {
      address = IPv6Address.decode(value);
    } catch (e) {
      throw new SPFSyntacticalError(`Invalid IPv6 Address: ${e}`);
    }

    // Returns the mechanism with the parsed address.
    return new this(address);
  }

  /**
   * Performs the validation of the current mechanism, using the supplied context.
   * @param context the context of the validation.
   * @returns the result of the validation.
   */
  public async match(context: ISPFContext): Promise<SPFMechanismResult> {
    if (context.client.ipAddress instanceof IPv4Address) {
      return new SPFMechanismResult(false);
    }

    if (this.address.cidr && context.client.ipAddress.cidr_match(this.address)) {
      return new SPFMechanismResult(
        true,
        `${context.client.ipAddress.encode()} is in CIDR range of ${this.address.encode()}`
      );
    } else if (
      !this.address.cidr &&
      context.client.ipAddress.equals(this.address)
    ) {
      return new SPFMechanismResult(
        true,
        `${context.client.ipAddress.encode()} is listed as IPv6 address`
      );
    }

    return new SPFMechanismResult(false);
  }

  /**
   * Gets the string version of the mechanism.
   * @returns the string version.
   */
  public toString(): string {
    return `${SPFDirectiveMechanismKeywords.IPv6}:${this.address.encode()}`;
  }
}

/////////////////////////////////////////////////
// Mechanism Exists Class.
/////////////////////////////////////////////////

export class SPFExistsMechanism extends SPFMechanism {
  /**
   * Constructs a new SPF exists mechanism.
   * @param hostname the hostname.
   */
  public constructor(public readonly hostname: string) {
    super();
  }

  /**
   * Parses the current mechanism.
   * @param value the value of the key/value pair.
   * @returns the parsed mechanism.
   */
  public static parse(value: string | null): SPFAllMechanism {
    if (value === null) {
      throw new SPFSyntacticalError(
        '"exists" mechanism must have one domain argument!'
      );
    }

    return new this(value);
  }

  /**
   * Performs the validation of the current mechanism, using the supplied context.
   * @param context the context of the validation.
   * @returns the result of the validation.
   */
  public async match(context: ISPFContext): Promise<SPFMechanismResult> {
    // Creates the promises for both types of RR's.
    const iPv4Promise: Promise<string[]> = util.promisify(dns.resolve4)(
      this.hostname
    );
    const iPv6Promise: Promise<string[]> = util.promisify(dns.resolve6)(
      this.hostname
    );

    // Awaits both of the promises.
    const [iPv4Addresses, iPv6Addresses] = await Promise.all([
      iPv4Promise,
      iPv6Promise,
    ]);

    // Checks if any of the two have records.
    if (iPv4Addresses.length > 0 && iPv6Addresses.length > 0) {
      return new SPFMechanismResult(
        true,
        `IPv4 and IPv6 RR's found for hostname: ${this.hostname}`
      );
    } else if (iPv4Addresses.length > 0) {
      return new SPFMechanismResult(
        true,
        `IPv4 RR's found for hostname: ${this.hostname}`
      );
    } else if (iPv6Addresses.length > 0) {
      return new SPFMechanismResult(
        true,
        `IPv6 RR's found for hostname: ${this.hostname}`
      );
    } else {
      return new SPFMechanismResult(
        false,
        `No RR's found for hostname: ${this.hostname}`
      );
    }
  }

  /**
   * Gets the string version of the mechanism.
   * @returns the string version.
   */
  public toString(): string {
    return `${SPFDirectiveMechanismKeywords.Exists}:${this.hostname}`;
  }
}

/////////////////////////////////////////////////
// SPF Mechanism Parsing.
/////////////////////////////////////////////////

/**
 * Parses an SPF mechanism.
 * @param key the key.
 * @param value the value.
 * @returns The parsed mechanism.
 */
export const spf_parse_mechanism = (
  key: string,
  value: string | null
): SPFMechanism => {
  switch (key) {
    case SPFDirectiveMechanismKeywords.All:
      return SPFAllMechanism.parse(value);
    case SPFDirectiveMechanismKeywords.Include:
      return SPFIncludeMechanism.parse(value);
    case SPFDirectiveMechanismKeywords.A:
      return SPFAMechanism.parse(value);
    case SPFDirectiveMechanismKeywords.MX:
      return SPFMXMechanism.parse(value);
    case SPFDirectiveMechanismKeywords.PTR:
      return SPFPTRMechanism.parse(value);
    case SPFDirectiveMechanismKeywords.IPv4:
      return SPFIPv4Mechanism.parse(value);
    case SPFDirectiveMechanismKeywords.IPv6:
      return SPFIPv6Mechanism.parse(value);
    case SPFDirectiveMechanismKeywords.Exists:
      return SPFExistsMechanism.parse(value);
    default:
      break;
  }

  throw new SPFSyntacticalError(`Invalid SPF Mechanism: ${key}`);
};

/////////////////////////////////////////////////
// Directive Class.
/////////////////////////////////////////////////

export class SPFDirective {
  /**
   * Constructs a new SPF directive.
   * @param qualifier the qualifier for the directive.
   * @param mechanism the mechanism for the directive.
   */
  public constructor(
    public readonly qualifier: SPFDirectiveQualifier,
    public readonly mechanism: SPFMechanism
  ) {}

  /**
   * Parses an directive from the given key/ value pair.
   * @param key the key of the directive.
   * @param value the value of the directive.
   * @returns The parsed directive.
   */
  public static parse(key: string, value: string | null): SPFDirective {
    // Gets the mechanism and the qualifier (Defaults to Pass).
    let qualifier: SPFDirectiveQualifier = SPFDirectiveQualifier.Pass;
    if (/^[\+\-\~\?].*/.test(key)) {
      qualifier = spf_directive_qualifier_parse(key.slice(0, 1));
      key = key.slice(1);
    }

    // Parses the mechanism.
    const mechanism: SPFMechanism = spf_parse_mechanism(key, value);

    // Returns the directive.
    return new SPFDirective(qualifier, mechanism);
  }
}
