import dns from "dns";
import util from "util";
import { SPFContext } from ".";
import { SPFNetworkingError } from "./SPFErrors";
import { SPFMacroProcessor } from "./SPFMacroProcessor";

export class SPFExplainRecord {
  /**
   * Constructs a new SPF explain record.
   * @param contents the contents.
   */
  public constructor(public readonly contents: string) {}

  /**
   * Resolves an SPF explain record.
   * @param hostname the hostname.
   * @param context the context.
   * @returns the explain record,
   */
  public static async resolve(
    hostname: string,
    context: SPFContext
  ): Promise<SPFExplainRecord> {
    // Gets all the found txt records.
    const txtRecords: string[][] = await util.promisify(dns.resolveTxt)(
      hostname
    );

    // Checks if there are any records, at all.. If not, throw error.
    if (txtRecords.length === 0) {
      throw new SPFNetworkingError(
        `Could not find any TXT records for hostname: ${hostname}`
      );
    }

    // Gets the first TXT record, and concatenates the strings into a single string.
    const txtRecord: string[] = txtRecords.at(0) as string[];
    const txtRecordContents: string = txtRecord.join(""); // [RFC7208] The fetched TXT record's strings are concatenated with no spaces.

    // Processes the macros inside the record.
    const processedTxtRecordContents: string = new SPFMacroProcessor(
      context
    ).process(txtRecordContents, true);

    // Returns the record.
    return new SPFExplainRecord(processedTxtRecordContents);
  }
}
