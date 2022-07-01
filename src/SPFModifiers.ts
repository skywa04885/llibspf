import { SPFSyntacticalError } from "./SPFErrors";

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

export class SPFRedirectModifier extends SPFModifier {
  public constructor(public readonly domain: string) {
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

export class SPFExplainModifier extends SPFModifier {
  public constructor(public readonly domain: string) {
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
