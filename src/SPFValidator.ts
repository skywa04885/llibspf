import winston from "winston";
import { ISPFContext } from "./SPFContext";
import {
  SPFDirectiveQualifier,
  SPFMechanism,
  SPFMechanismResult,
} from "./SPFDirectives";
import { SPFNetworkingError, SPFSyntacticalError } from "./SPFErrors";
import { SPFExplainRecord } from "./SPFExplainRecord";
import { SPFExplainModifier, SPFRedirectModifier } from "./SPFModifiers";
import { SPFRecord } from "./SPFRecord";
import { SPFResult, SPFResultType } from "./SPFResult";

export class SPFValidator {
  public constructor(
    public readonly context: ISPFContext,
    public readonly logger: winston.Logger | undefined = undefined
  ) {}

  /**
   * Validates the SPF Record.
   * @param hostname the domain to check the SPF for.
   */
  public async validate(
    hostname: string = this.context.message.emailDomain
  ): Promise<SPFResult> {
    try {
      /////////////////////////////////////////////////
      // Record resolving.
      /////////////////////////////////////////////////

      this.logger?.debug(`Resolving record for: ${hostname}`);

      // Gets the SPF Record.
      const record: SPFRecord | null = await SPFRecord.resolve(
        hostname,
        this.context,
        this.logger
      );

      // Makes sure that the record is found.
      if (record === null) {
        return new SPFResult(
          SPFResultType.None,
          this.context,
          null,
          `could not resolve ${hostname}`
        );
      }

      // Logs the record basic information.
      this.logger?.debug(
        `Record has ${record.modifiers.length} modifiers, and ${record.directives.length} directives.`
      );

      /////////////////////////////////////////////////
      // Handle modifiers.
      /////////////////////////////////////////////////

      // Checks some of the modifiers, will be important later in the process.
      if (record.modifiers.length !== 0) {
        // Checks if there is a redirect modifier, if so we want to recurse, and use that resuilt.
        const redirectModifier: SPFRedirectModifier | null =
          record.getModifierOfType<SPFRedirectModifier>(SPFRedirectModifier);
        if (redirectModifier !== null) {
          this.logger?.debug(
            `Found redirect modifier, redirecting to: "${
              redirectModifier.hostname
            }", ignoring ${record.modifiers.length - 1} modifiers and ${
              record.directives.length
            } directives.`
          );

          return this.validate(redirectModifier.hostname);
        }
      }

      /////////////////////////////////////////////////
      // Matches the mechanisms inside the directives.
      /////////////////////////////////////////////////

      // Starts looping over all the directives.
      for (const directive of record.directives) {
        // Gets the qualifier and the mechanism.
        const qualifier: SPFDirectiveQualifier = directive.qualifier;
        const mechanism: SPFMechanism = directive.mechanism;

        // Calls the validate method inside the mechanism, and stores the result.
        const mechanismResult: SPFMechanismResult = await mechanism.match(
          this.context
        );

        // Performs a debug log if verbosity specified.
        this.logger?.debug(
          `Tried directive with mechanism: ${directive.mechanism.constructor.name}, and qualifier: ${directive.qualifier}, resulting in: [${mechanismResult.match}] ${mechanismResult.reason}`
        );

        // Checks the qualifier of the message, and then checks what to do with the
        //  possible match.
        switch (qualifier) {
          case SPFDirectiveQualifier.Fail: {
            // If it matches, we will fail the SPF validation.
            if (mechanismResult.match) {
              this.logger?.debug(
                `${mechanism.toString()} matched, and resulted in fail.`
              );

              // Gets the explain modifier, if there.
              const explainModifier: SPFExplainModifier | null =
                record.getModifierOfType<SPFExplainModifier>(
                  SPFExplainModifier
                );

              // Checks if we have an explain modifier.
              let explaination: string | null = null;
              if (explainModifier !== null) {
                // Logs that we've found an explain modifier.
                this.logger?.debug(
                  `Failed, also found explain modifier with hostname: ${explainModifier.hostname}, resolving...`
                );

                // Resolves the explain record.
                const spfExplainRecord: SPFExplainRecord = await SPFExplainRecord.resolve(explainModifier.hostname, this.context);
                this.logger?.debug(`Resolved explaination: '${spfExplainRecord.contents}'`);

                // Sets the explaination.
                explaination = spfExplainRecord.contents;
              }

              // Returns the result.
              return new SPFResult(
                SPFResultType.Fail,
                this.context,
                mechanism,
                mechanismResult.reason,
                explaination
              );
            }

            // Continue to the next directive.
            break;
          }
          case SPFDirectiveQualifier.Pass: {
            // If it matches, we have finished the SPF check return pass.
            if (mechanismResult.match) {
              this.logger?.debug(
                `${mechanism.toString()} matched, and resulted in pass.`
              );
              return new SPFResult(
                SPFResultType.Pass,
                this.context,
                mechanism,
                mechanismResult.reason
              );
            }

            // Continue to next directive.
            break;
          }
          case SPFDirectiveQualifier.Neutral: {
            // If it matches, we have finished the check, and we're neutral about the result.
            if (mechanismResult.match) {
              this.logger?.debug(
                `${mechanism.toString()} matched, and resulted in neutral.`
              );
              return new SPFResult(
                SPFResultType.Neutral,
                this.context,
                mechanism,
                mechanismResult.reason
              );
            }

            // Continue to the next directive.
            break;
          }
          case SPFDirectiveQualifier.SoftFail: {
            // If ti matches, we have finished the check, and we will (sort-off) fail.
            if (mechanismResult.match) {
              this.logger?.debug(
                `${mechanism.toString()} matched, and resulted in soft fail.`
              );
              return new SPFResult(
                SPFResultType.SoftFail,
                this.context,
                mechanism,
                mechanismResult.reason
              );
            }

            // Continue to the next directive.
            break;
          }
          default: {
            throw new Error("Mechanism has invalid qualifier!");
          }
        }
      }

      // Nothing matched, nothing declided.. We don't know what to do.
      return new SPFResult(
        SPFResultType.None,
        this.context,
        null,
        "No matching directives"
      );
    } catch (_e) {
      // If it is an SPF error, handle it appropiately.
      if (_e instanceof SPFSyntacticalError) {
        const e: SPFSyntacticalError = _e as SPFSyntacticalError;
        return new SPFResult(
          SPFResultType.PermError,
          this.context,
          null,
          e.message
        );
      } else if (_e instanceof SPFNetworkingError) {
        const e: SPFSyntacticalError = _e as SPFSyntacticalError;
        return new SPFResult(
          SPFResultType.TempError,
          this.context,
          null,
          e.message
        );
      }

      throw _e;
    }
  }
}
