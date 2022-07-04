import { SPFSyntacticalError } from "./SPFErrors";

/////////////////////////////////////////////////
// Modifier Class.
/////////////////////////////////////////////////

export class SPFModifier {
  /**
   * Parses the SPF modifier by key and value.
   * @param key the key.
   * @param value the value.
   */
  public static parse(key: string, value: string | null): SPFModifier {
    switch (key) {
      case "redirect":
        return SPFRedirectModifier.parse(key, value);
      case "exp":
        return SPFExplainModifier.parse(key, value);
      default:
        throw new SPFSyntacticalError(`Unknown SPF modifier: "${key}"`);
    }
  }
}

/////////////////////////////////////////////////
// Redirect Modifier Class.
/////////////////////////////////////////////////

export class SPFRedirectModifier extends SPFModifier {
  /**
   * Constructs a new SPF redirect modifier.
   * @param hostname the hostname to redirect to.
   */
  public constructor(public readonly hostname: string) {
    super();
  }

  /**
   * Parses the SPF modifier by key and value.
   * @param key the key.
   * @param value the value.
   */
  public static parse(key: string, value: string | null): SPFModifier {
    if (value === null) {
      throw new SPFSyntacticalError("SPF Redirect modifier must have an domain as argument.");
    }

    return new this(value);
  }
}

/////////////////////////////////////////////////
// Explain Modifier Class.
/////////////////////////////////////////////////

export class SPFExplainModifier extends SPFModifier {
  /**
   * Constructs a new SPF explain modifier.
   * @param hostname the hostname.
   */
  public constructor(public readonly hostname: string) {
    super();
  }

  /**
   * Parses the SPF modifier by key and value.
   * @param key the key.
   * @param value the value.
   */
  public static parse(key: string, value: string | null): SPFModifier {
    if (value === null) {
      throw new SPFSyntacticalError("SPF Explain modifier must have an domain as argument.");
    }

    return new this(value);
  }
}
