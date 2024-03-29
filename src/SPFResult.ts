import { MimeMappedHeaderValue } from "llibmime";
import { SPFCheckedIdentity } from "./SPFCheckedIdentity";
import { ISPFContext } from "./SPFContext";
import { SPFMechanism } from "./SPFDirectives";

export const RECEIVED_SPF_HEADER_KEY = 'Received-SPF';

export enum SPFResultType {
  None = 'none',
  Neutral = 'neutral',
  Pass = 'pass',
  Fail = 'fail',
  SoftFail = 'softfail',
  TempError = 'temperror',
  PermError = 'permerror',
}

export class SPFResult {
  /**
   * Constructs a new SPF result.
   * @param type the type of the result.
   * @param context the context.
   * @param mechanism the matching mechanism.
   * @param comment the comment.
   * @param explaination the possible explaination supplied by provider.
   */
  public constructor(public readonly type: SPFResultType, public readonly context: ISPFContext, public readonly mechanism: SPFMechanism | null = null, public readonly comment: string | null = null, public readonly explaination: string | null = null) {}

  /**
   * Constructs the header version of the result.
   * @returns the header version of the result.
   */
  public asHeader(): [string, string] {
    // Constructs the key/ value pairs.
    const pairs: {[key: string]: string} = {
      "client-ip": this.context.client.ipAddress.encode(),
      "envelope-from": `${this.context.message.emailUsername}@${this.context.message.emailDomain}`,
      "helo": this.context.client.greetHostname,
      "receiver": this.context.server.hostname,
      "mechanism": this.mechanism ? this.mechanism.toString() : 'default',
      "identity": SPFCheckedIdentity.MailFrom,
    };

    // Encodes the pairs.
    const encodedPairs: string = Object.entries(pairs).map((elem: [string, string], index: number): string => {
      // Gets the key and value for ease.
      const key: string = elem[0];
      const value: string = elem[1];

      // Tests for whitespace, if so enclose it in double quotes.
      if (/\s+/g.test(value)) {
        return `${key}="${value}";`;
      }

      // No whitespace, just keep it _raw_.
      return `${key}=${value};`;
    }).join(' ');
    
    // Returns the built header.
    return [
      RECEIVED_SPF_HEADER_KEY,
      `${this.type} (${this.comment ?? 'None'}) ${encodedPairs}`
    ];
  }
}
