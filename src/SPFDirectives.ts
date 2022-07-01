import { IPv4Address, IPv6Address } from "llibipaddress";
import { SPFContext } from "./SPFContext";
import { SPFRecord } from "./SPFRecord";
import dns from "dns";
import util from "util";
import { SPFSyntacticalError } from "./SPFErrors";

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

export class SPFMechanism {
  /**
   * Performs the validation of the current mechanism, using the supplied context.
   * @param context the context of the validation.
   * @returns the result of the validation.
   */
  public async validate(context: SPFContext): Promise<SPFMechanismResult> {
    return new SPFMechanismResult(
      false,
      "Mechanism has no validation implemented."
    );
  }

  /**
   * Returns the string version of the message (used in the encoding of the header).
   */
  public toString(): string {
    throw new Error("Not implemented!");
  }
}

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
  public async validate(context: SPFContext): Promise<SPFMechanismResult> {
    return new SPFMechanismResult(true, "everything matches");
  }

  /**
   * Returns the string version of the message (used in the encoding of the header).
   */
  public toString(): string {
    return `${SPFDirectiveMechanismKeywords.All}`;
  }
}

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
  public async validate(context: SPFContext): Promise<SPFMechanismResult> {
    return new SPFMechanismResult(false);
  }

  /**
   * Returns the string version of the message (used in the encoding of the header).
   */
  public toString(): string {
    return `${SPFDirectiveMechanismKeywords.Include}:${this.domain}`;
  }
}

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
  public async validate(context: SPFContext): Promise<SPFMechanismResult> {
    if (context.clientIPAddress instanceof IPv4Address) {
      // Resolves the A records of the current domain, or of the domain in the context.
      const rawAddresses: string[] = await util.promisify(dns.resolve4)(
        this.domain ?? context.senderDomain
      );

      // Parses the raw addresses.
      const addresses: IPv4Address[] = rawAddresses.map(
        (address: string): IPv4Address => IPv4Address.decode(address)
      );

      // Matches the client IP address against the addresses in the array.
      for (const address of addresses) {
        if (address.cidr && context.clientIPAddress.cidr_match(address)) {
          return new SPFMechanismResult(
            true,
            `Clients IPv4 ${context.clientIPAddress.encode()} is in the CIDR range ${address.encode()}`
          );
        } else if (!address.cidr && context.clientIPAddress.equals(address)) {
          return new SPFMechanismResult(
            true,
            `Clients IPv4 ${context.clientIPAddress.encode()} is mentioned in A record.`
          );
        }
      }

      // We didn't match, return false.
      return new SPFMechanismResult(
        false,
        `Clients IPv4 ${context.clientIPAddress.encode()} is not mentioned, nor in any CIDR range.`
      );
    } else if (context.clientIPAddress instanceof IPv6Address) {
      // Resolves the A records of the current domain, or of the domain in the context.
      const rawAddresses: string[] = await util.promisify(dns.resolve6)(
        this.domain ?? context.senderDomain
      );

      // Parses the raw addresses.
      const addresses: IPv6Address[] = rawAddresses.map(
        (address: string): IPv6Address => IPv6Address.decode(address)
      );

      // Matches the client IP address against the addresses in the array.
      for (const address of addresses) {
        if (address.cidr && context.clientIPAddress.cidr_match(address)) {
          return new SPFMechanismResult(
            true,
            `Clients IPv6 ${context.clientIPAddress.encode()} is in the CIDR range ${address.encode()}`
          );
        } else if (!address.cidr && context.clientIPAddress.equals(address)) {
          return new SPFMechanismResult(
            true,
            `Clients IPv6 ${context.clientIPAddress.encode()} is mentioned in A record.`
          );
        }
      }

      // We didn't match, return false.
      return new SPFMechanismResult(
        false,
        `Clients IPv6 ${context.clientIPAddress.encode()} is not mentioned, nor in any CIDR range.`
      );
    } else {
      throw new SPFSyntacticalError("Client IP address not IPv4 or IPv6!");
    }
  }

  /**
   * Returns the string version of the message (used in the encoding of the header).
   */
  public toString(): string {
    if (this.domain !== null) {
      return `${SPFDirectiveMechanismKeywords.A}:${this.domain}`;
    }

    return SPFDirectiveMechanismKeywords.A;
  }
}

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
  public async validate(context: SPFContext): Promise<SPFMechanismResult> {
    // Gets all the mail exchanges.
    const mailExchanges: dns.MxRecord[] = await util.promisify(dns.resolveMx)(
      this.domain ?? context.senderDomain
    );

    // Validates depending on the IP address type.
    if (context.clientIPAddress instanceof IPv4Address) {
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
        if (address.equals(context.clientIPAddress)) {
          return new SPFMechanismResult(
            true,
            `Client IPv4 ${context.clientIPAddress.encode()} is mentioned as mail exchange.`
          );
        }
      }

      // Returns false.
      return new SPFMechanismResult(
        false,
        `Client IPv4 ${context.clientIPAddress.encode()} not mentioned as mail exchange.`
      );
    } else if (context.clientIPAddress instanceof IPv6Address) {
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
        if (address.equals(context.clientIPAddress)) {
          return new SPFMechanismResult(
            true,
            `Client IPv6 ${context.clientIPAddress.encode()} is mentioned as mail exchange.`
          );
        }
      }

      // Returns false.
      return new SPFMechanismResult(
        false,
        `Client IPv6 ${context.clientIPAddress.encode()} not mentioned as mail exchange.`
      );
    } else {
      throw new SPFSyntacticalError("Client IP address not IPv4 or IPv6!");
    }
  }

  /**
   * Returns the string version of the message (used in the encoding of the header).
   */
  public toString(): string {
    if (this.domain !== null) {
      return `${SPFDirectiveMechanismKeywords.MX}:${this.domain}`;
    }

    return SPFDirectiveMechanismKeywords.MX;
  }
}

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
  public async validate(context: SPFContext): Promise<SPFMechanismResult> {
    // Performs the reverse lookup of all the hostnames.
    const hostnames: string[] = await util.promisify(dns.reverse)(
      context.clientIPAddress.encode()
    );

    // Checks if any of them matches.
    for (const hostname of hostnames) {
      if (hostname.endsWith(this.domain)) {
        return new SPFMechanismResult(
          true,
          `Reverse lookup of ${context.clientIPAddress.encode()} resulted in matching hostname: ${hostname}`
        );
      }
    }

    // We did not match.
    return new SPFMechanismResult(false);
  }

  /**
   * Returns the string version of the message (used in the encoding of the header).
   */
  public toString(): string {
    if (this.domain !== null) {
      return `${SPFDirectiveMechanismKeywords.MX}:${this.domain}`;
    }

    return SPFDirectiveMechanismKeywords.PTR;
  }
}

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
  public async validate(context: SPFContext): Promise<SPFMechanismResult> {
    if (context.clientIPAddress instanceof IPv6Address) {
      return new SPFMechanismResult(false);
    }

    if (this.address.cidr && context.clientIPAddress.cidr_match(this.address)) {
      return new SPFMechanismResult(
        true,
        `${context.clientIPAddress.encode()} is in CIDR range of ${this.address.encode()}`
      );
    } else if (
      !this.address.cidr &&
      context.clientIPAddress.equals(this.address)
    ) {
      return new SPFMechanismResult(
        true,
        `${context.clientIPAddress.encode()} is listed as IPv4 address`
      );
    }

    return new SPFMechanismResult(false);
  }

  /**
   * Returns the string version of the message (used in the encoding of the header).
   */
  public toString(): string {
    return `${SPFDirectiveMechanismKeywords.IPv4}:${this.address.encode()}`;
  }
}

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
  public async validate(context: SPFContext): Promise<SPFMechanismResult> {
    if (context.clientIPAddress instanceof IPv4Address) {
      return new SPFMechanismResult(false);
    }

    if (this.address.cidr && context.clientIPAddress.cidr_match(this.address)) {
      return new SPFMechanismResult(
        true,
        `${context.clientIPAddress.encode()} is in CIDR range of ${this.address.encode()}`
      );
    } else if (
      !this.address.cidr &&
      context.clientIPAddress.equals(this.address)
    ) {
      return new SPFMechanismResult(
        true,
        `${context.clientIPAddress.encode()} is listed as IPv6 address`
      );
    }

    return new SPFMechanismResult(false);
  }

  /**
   * Returns the string version of the message (used in the encoding of the header).
   */
  public toString(): string {
    return `${SPFDirectiveMechanismKeywords.IPv6}:${this.address.encode()}`;
  }
}

export class SPFExistsMechanism extends SPFMechanism {
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
      throw new SPFSyntacticalError(
        '"exists" mechanism must have one domain argument!'
      );
    }

    return new this(value);
  }

  /**
   * Returns the string version of the message (used in the encoding of the header).
   */
  public toString(): string {
    return `${SPFDirectiveMechanismKeywords.Exists}:${this.domain}`;
  }
}

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

export class SPFDirective {
  public constructor(
    public readonly qualifier: SPFDirectiveQualifier,
    public readonly mechanism: SPFMechanism
  ) {}

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
