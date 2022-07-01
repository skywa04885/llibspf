import dns from "dns";
import util from "util";
import { SPFMacroProcessor } from "./SPFMacroProcessor";
import { SPFDirective, SPFMechanism } from "./SPFDirectives";
import { SPFModifier } from "./SPFModifiers";
import { SPFContext } from "./SPFContext";
import { SPFNetworkingError } from "./SPFErrors";

export enum SPFBasicMechanism {
  All = "all",
  Include = "include",
}

export enum SPFDesignatedSenderMechanisms {
  A = "a",
  MX = "mx",
  PTR = "ptr",
  IP4 = "ip4",
  IP6 = "ip6",
  Exists = "exists",
}

export class SPFRecord {
  public constructor(
    public directives: SPFDirective[],
    public modifiers: SPFModifier[]
  ) {}

  /**
   * Gets an modifier of the given type.
   * @param type the desired type of the modifier.
   * @returns the possibly found modifier.
   */
  public getModifierOfType<Type extends SPFModifier>(type: any): Type | null {
    const index: number = this.modifiers.findIndex(
      (elem: any) => elem instanceof type
    );
    if (index === -1) {
      return null;
    }

    return this.modifiers.at(index) as Type;
  }

  public static async resolve(
    hostname: string,
    context: SPFContext,
    explain: boolean = false
  ): Promise<SPFRecord | null> {
    // Gets all the TXT records from the domain.
    let records: string[];
    try {
      records = (await util.promisify(dns.resolveTxt)(hostname)).map(
        (record: string[]): string => record.join().trim()
      );
    } catch (e) {
      throw new SPFNetworkingError();
    }

    // Filters the txt records which start with 'v=spf1', so that we're left
    //  with only spf records.
    const spf_records: string[] = records.filter((record: string) =>
      record.startsWith("v=spf1")
    );
    if (spf_records.length === 0) {
      return null;
    }
    const spf_record: string = spf_records[0].slice(6); // Ignore others.

    // Returns the decoded header.
    return SPFRecord.decode(spf_record, context, explain);
  }

  public static decode(
    raw: string,
    context: SPFContext,
    explain: boolean
  ): SPFRecord {
    /////////////////////////////////////////////////
    // Processes macro's in the header.
    /////////////////////////////////////////////////

    // Processes the header.
    const processed: string = new SPFMacroProcessor(context).process(
      raw,
      explain
    );

    /////////////////////////////////////////////////
    // Parses the raw header into pairs and keys.
    /////////////////////////////////////////////////

    // Initializes the pairs object.
    let directive_pairs: [string, string | null][] = [];
    let modifier_pairs: [string, string | null][] = [];

    // Parses the processed string, and gets a pairs of key/ value pairs, and the keys.
    processed
      .replace(/\s+/g, " ")
      .trim()
      .split(/\s/g)
      .forEach((pair: string): void => {
        const colon_sep_index: number = pair.indexOf(":");
        const equals_sep_index: number = pair.indexOf("=");

        // Gets either of the indices.
        const sep_index: number =
          colon_sep_index !== -1 ? colon_sep_index : equals_sep_index;

        // Checks if there is a separation index, if not
        //  we're dealing with a single key.
        if (sep_index === -1) {
          directive_pairs.push([pair.trim().toLowerCase(), null]);
          return;
        }

        // Splits the key/ value pair.
        const key: string = pair.substring(0, sep_index).trim().toLowerCase();
        const value: string = pair
          .substring(sep_index + 1)
          .trim()
          .toLowerCase();

        // Checks if it's a modifier or directive.
        if (colon_sep_index !== -1) {
          directive_pairs.push([key, value]);
        } else if (equals_sep_index !== -1) {
          modifier_pairs.push([key, value]);
        }
      });

    /////////////////////////////////////////////////
    // Constructs the array of directives and modifiers.
    /////////////////////////////////////////////////

    // Parses all the directives.
    const directives: SPFDirective[] = directive_pairs.map(
      (pair: [string, string | null], index: number): SPFDirective => {
        // Gets the key and the value.
        const key: string = pair[0];
        const value: string | null = pair[1];

        // Parses the mechanism
        return SPFDirective.parse(key, value);
      }
    );

    // Parses all the modifiers.
    const modifiers: SPFModifier[] = modifier_pairs.map(
      (pair: [string, string | null], index: number): SPFModifier => {
        // Gets the key and the value.
        const key: string = pair[0];
        const value: string | null = pair[1];

        // Parses the mechanism
        return SPFModifier.parse(key, value);
      }
    );

    /////////////////////////////////////////////////
    // Finishes and returns the result.
    /////////////////////////////////////////////////

    return new SPFRecord(directives, modifiers);
  }
}
