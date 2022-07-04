import { IPv4Address } from "llibipaddress";
import * as net from "net";
import { ISPFContext } from "./SPFContext";
import { SPFSyntacticalError } from "./SPFErrors";

export class SPFMacroProcessor {
  /**
   * Constructs a new macro processor.
   * @param context the context.
   */
  public constructor(public readonly context: ISPFContext) {}

  /**
   * Executes the given macro.
   * @param macro the macro to execute.
   * @param exp if we're allowed to use exp letters.
   * @protected
   */
  protected _execute(macro: string, exp: boolean): string {
    // Matches the base pattern of the macro.
    let match: RegExpMatchArray | null = macro.match(
      /^%{(?<letter>[a-z])(?<transformation_digits>[0-9]+)?(?<transformation_letters>[a-z])?(?<delimiter>[.\-+,/_=])?}$/
    );
    if (!match) {
      throw new SPFSyntacticalError(`'${macro}' is not a valid macro!`);
    }

    // Gets the matched segments.
    const letter: string = match.groups!.letter;
    const transformation_digits: number | undefined = match.groups!
      .transformation_digits
      ? parseInt(match.groups!.transformation_digits)
      : undefined;
    const transformation_letters: string | undefined =
      match.groups!.transformation_letters;
    const delimiter: string = match.groups!.delimiter ?? ".";

    // Checks the letter and what to do, the constructs the base.
    let base: string;
    switch (letter) {
      // Sender.
      case "s": {
        base = `${this.context.message.emailUsername}@${this.context.message.emailDomain}`;
        break;
      }
      // Local part of sender.
      case "l": {
        base = this.context.message.emailUsername;
        break;
      }
      // Domain of sender.
      case "o":
      case "d": {
        base = this.context.message.emailDomain;
        break;
      }
      // IP Address.
      case "i": {
        base = this.context.client.ipAddress.encode();
        break;
      }
      // The validated domain (deprecated).
      case "p": {
        throw new SPFSyntacticalError("The validate domain is deprecated!");
      }
      // Address type.
      case "v": {
        base =
          this.context.client.ipAddress instanceof IPv4Address
            ? "in-addr"
            : "ip6";
        break;
      }
      // 'HELO' / 'EHLO' domain.
      case "h": {
        base = this.context.client.greetHostname;
        break;
      }
      // EXP Only commands.
      case "c":
      case "r":
      case "t": {
        // Makes sure we're in EXP.
        if (!exp) {
          throw new SPFSyntacticalError(
            "May only be used inside the exp command."
          );
        }

        // Checks the letter (again, I know not efficient).
        if (letter === "c") {
          base = this.context.client.ipAddress.encode();
        } else if (letter === "r") {
          base = this.context.server.hostname;
        } else {
          // 't'
          base = Math.floor(new Date().getTime() / 1000).toString();
        }

        // Breaks.
        break;
      }
      default:
        throw new SPFSyntacticalError("Invalid letter.");
    }

    // Splits the base on dots, so we can perform possible
    //  transformations on it.
    let arr: string[] = base.split(".");

    // Checks if we need to reverse.
    if (transformation_letters === "r") {
      arr = arr.reverse();
    }

    // Checks if we're dealing with a digit transformation, which tells us how many right-hand parts to use.
    if (transformation_digits) {
      arr = arr.splice(arr.length - transformation_digits);
    }

    return arr.join(delimiter);
  }

  /**
   * Processes the macro's in the given token, and returns the result.
   * @param token the token to process.
   * @param exp if the command is executed from the inside the exp, if so allow more letters.
   */
  public process(token: string, exp: boolean = false): string {
    // Replaces the complex macro's.
    token = token.replace(
      /%{[a-z0-9.\-+,/_=]+}/g,
      (substring: string): string => this._execute(substring, exp)
    );

    // Replaces the simple macro's.
    token = token.replace(/%.?/g, (substring: string): string => {
      switch (substring.charAt(1)) {
        case "%":
          return "%";
        case "_":
          return " ";
        case "-":
          return encodeURIComponent(" ");
        default:
          throw new SPFSyntacticalError(
            `Invalid char after macro: ${substring.charAt(1)}`
          );
      }
    });

    return token;
  }
}
