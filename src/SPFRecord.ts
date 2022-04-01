import dns from "dns";
import util from "util";
import {SPFMechanism} from "./SPFMechanisms";

export enum SPFQualifier {
  Pass = '+',
  Fail = '-',
  SoftFail = '~',
  Neutral = '?',
}

export enum SPFBasicMechanism {
  All = 'all',
  Include = 'include',
}

export enum SPFDesignatedSenderMechanisms {
  A = 'a',
  MX = 'mx',
  PTR = 'ptr',
  IP4 = 'ip4',
  IP6 = 'ip6',
  Exists = 'exists',
}


export class SPFRecord {
  public constructor(public mechanisms: SPFMechanism[]) {}

  public static async resolve(hostname: string) {
    // Gets all the TXT records from the domain.
    const records: string[] = (
      await util.promisify(dns.resolveTxt)(hostname)
    ).map((record: string[]): string => record.join().trim());

    // Filters the txt records which start with 'v=spf1', so that we're left
    //  with only spf records.
    const spf_records: string[] = records.filter((record: string) =>
      record.startsWith("v=spf1")
    );
    if (spf_records.length === 0) {
      throw new Error(`No SPF records found for hostname: '${hostname}'`);
    }
    const spf_record: string = spf_records[0]; // Ignore others.

    return SPFRecord.decode(spf_record);
  }

  public static decode(raw: string) {
    /////////////////////////////////////////////////
    // Parses the raw header into pairs and keys.
    /////////////////////////////////////////////////

    let pairs: { [key: string]: string } = {};
    let keys: string[] = [];

    // Parses the raw string, and gets a pairs of key/ value pairs, and the keys.
    raw.split(/\s+/g).forEach((pair: string): void => {
      // Finds the separation index.
      let sep_index: number = pair.indexOf("=");
      if (sep_index === -1) {
        sep_index = pair.indexOf(":");
      }

      // Checks if there is a separation index, if not
      //  we're dealing with a single key.
      if (sep_index === -1) {
        keys.push(pair.trim().toLowerCase());
        return;
      }

      // Splits the key/ value pair.
      const key: string = pair.substring(0, sep_index).trim().toLowerCase();
      const value: string = pair
        .substring(sep_index + 1)
        .trim()
        .toLowerCase();

      // Puts the key/ value pair in the pairs.
      pairs[key] = value;
    });

    /////////////////////////////////////////////////
    // Processes macro's in the header.
    /////////////////////////////////////////////////
  }
}
